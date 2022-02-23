// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package boot

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/socket/netfilter"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/link/qdisc/fifo"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/config"
)

var (
	// DefaultLoopbackLink contains IP addresses and routes of "127.0.0.1/8" and
	// "::1/8" on "lo" interface.
	DefaultLoopbackLink = LoopbackLink{
		Name: "lo",
		Addresses: []IPWithPrefix{
			{Address: net.IP("\x7f\x00\x00\x01"), PrefixLen: 8},
			{Address: net.IPv6loopback, PrefixLen: 128},
		},
		Routes: []Route{
			{
				Destination: net.IPNet{
					IP:   net.IPv4(0x7f, 0, 0, 0),
					Mask: net.IPv4Mask(0xff, 0, 0, 0),
				},
			},
			{
				Destination: net.IPNet{
					IP:   net.IPv6loopback,
					Mask: net.IPMask(strings.Repeat("\xff", net.IPv6len)),
				},
			},
		},
	}
)

// Network exposes methods that can be used to configure a network stack.
type Network struct {
	Stack *stack.Stack
}

// Route represents a route in the network stack.
type Route struct {
	Destination net.IPNet
	Gateway     net.IP
}

// DefaultRoute represents a catch all route to the default gateway.
type DefaultRoute struct {
	Route Route
	Name  string
}

type Neighbor struct {
	IP           net.IP
	HardwareAddr net.HardwareAddr
}

// FDBasedLink configures an fd-based link.
type FDBasedLink struct {
	Name               string
	MTU                int
	Addresses          []IPWithPrefix
	Routes             []Route
	GSOMaxSize         uint32
	SoftwareGSOEnabled bool
	TXChecksumOffload  bool
	RXChecksumOffload  bool
	LinkAddress        net.HardwareAddr
	QDisc              config.QueueingDiscipline
	Neighbors          []Neighbor

	// NumChannels controls how many underlying FD's are to be used to
	// create this endpoint.
	NumChannels int
}

// LoopbackLink configures a loopback li nk.
type LoopbackLink struct {
	Name      string
	Addresses []IPWithPrefix
	Routes    []Route
}

// CreateLinksAndRoutesArgs are arguments to CreateLinkAndRoutes.
type CreateLinksAndRoutesArgs struct {
	// FilePayload contains the fds associated with the FDBasedLinks. The
	// number of fd's should match the sum of the NumChannels field of the
	// FDBasedLink entries below.
	urpc.FilePayload

	LoopbackLinks []LoopbackLink
	FDBasedLinks  []FDBasedLink

	Defaultv4Gateway DefaultRoute
	Defaultv6Gateway DefaultRoute
}

// IPWithPrefix is an address with its subnet prefix length.
type IPWithPrefix struct {
	// Address is a network address.
	Address net.IP

	// PrefixLen is the subnet prefix length.
	PrefixLen int
}

func (ip IPWithPrefix) String() string {
	return fmt.Sprintf("%s/%d", ip.Address, ip.PrefixLen)
}

// Empty returns true if route hasn't been set.
func (r *Route) Empty() bool {
	return r.Destination.IP == nil && r.Destination.Mask == nil && r.Gateway == nil
}

func (r *Route) toTcpipRoute(id tcpip.NICID) (tcpip.Route, error) {
	subnet, err := tcpip.NewSubnet(ipToAddress(r.Destination.IP), ipMaskToAddressMask(r.Destination.Mask))
	if err != nil {
		return tcpip.Route{}, err
	}
	return tcpip.Route{
		Destination: subnet,
		Gateway:     ipToAddress(r.Gateway),
		NIC:         id,
	}, nil
}

type Action string

const (
	Drop   Action = "drop"
	Accept        = "accept"
	Reject        = "reject"
)

// ReplaceIPTableArg
type ReplaceIPTableArg struct {
	// only support filter table for now
	Table string `json:"table"`

	InputRules  Rules `json:"input_rules"`
	OutputRules Rules `json:"output_rules"`
}

type Rules struct {
	DefaultDrop bool   `json:"default_drop"`
	Rules       []Rule `json:"rules"`
}

type Rule struct {
	// only support tcp/udp for now
	Protocol     string `json:"protocol"`
	Action       Action `json:"action"`
	Dst          string `json:"dst"`
	DstMask      string `json:"dst_mask"`
	Src          string `json:"src"`
	SrcMask      string `json:"src_mask"`
	SrcPortStart uint16 `json:"src_port_start"`
	SrcPortEnd   uint16 `json:"src_port_end"`
	DstPortStart uint16 `json:"dst_port_start"`
	DstPortEnd   uint16 `json:"dst_port_end"`
}

// ReplaceIPTables replace iptables in a network stack. It expose to runsc cmd
// Only support ipv4 and filter tables for test demo for now.
// Example Table:
// FilterID: {
// 	Rules: []Rule{
// 		{
// 			Filter: IPHeaderFilter{
// 				Protocol:             header.TCPProtocolNumber,
// 				CheckProtocol:        true,
// 				DstInvert: 			  true,
// 				Dst:                  "172.17.0.2",
// 				DstMask:              "255.255.255.0",

// 			},
// 			Target: &DropTarget{NetworkProtocol: header.IPv4ProtocolNumber},
// 			Matchers: []Matcher{&defaultTcpMatcher{
// 				sourcePortStart:      1,
// 				sourcePortEnd:        60000,
// 				destinationPortStart: 79,
// 				destinationPortEnd:   60000,
// 			}},
// 		},
// 		{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
// 		{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
// 		{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
// 		{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
// 		{Target: &ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
// 	},
// 	BuiltinChains: [NumHooks]int{
// 		Prerouting:  HookUnset,
// 		Input:       0,
// 		Forward:     1,
// 		Output:      2,
// 		Postrouting: HookUnset,
// 	},
// 	Underflows: [NumHooks]int{
// 		Prerouting:  HookUnset,
// 		Input:       0,
// 		Forward:     1,
// 		Output:      2,
// 		Postrouting: HookUnset,
// 	},
// }
func (n *Network) ReplaceIPTables(args *ReplaceIPTableArg, _ *struct{}) error {
	log.Infof("start to replace filter iptables")
	if args.Table != "filter" {
		return fmt.Errorf("only support filter table , not support %s table", args.Table)
	}
	log.Infof("replace tables %v", args.InputRules)

	rules := []stack.Rule{}
	defaultInputRule := stack.Rule{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}}
	defaultOutputRule := stack.Rule{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}}
	if args.InputRules.DefaultDrop {
		defaultInputRule = stack.Rule{Target: &stack.DropTarget{NetworkProtocol: header.IPv4ProtocolNumber}}
	}
	if args.OutputRules.DefaultDrop {
		defaultOutputRule = stack.Rule{Target: &stack.DropTarget{NetworkProtocol: header.IPv4ProtocolNumber}}
	}
	inputStartIndex := 0
	for _, rule := range args.InputRules.Rules {
		// srcInvert, dstInvert := true, true
		// if rule.Src == "" {
		// 	srcInvert = false
		// }
		// if rule.Dst == "" {
		// 	dstInvert = false
		// }
		var target stack.Target
		switch rule.Action {
		case Drop:
			target = &stack.DropTarget{NetworkProtocol: header.IPv4ProtocolNumber}
		case Accept:
			target = &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}
		case Reject:
			target = &stack.RejectICMPTarget{NetworkProtocol: header.IPv4ProtocolNumber}
		default:
			return fmt.Errorf("not supported target %s", target)
		}

		protol := header.TCPProtocolNumber
		var matcher stack.Matcher = netfilter.NewTCPMatcher(rule.SrcPortStart, rule.SrcPortEnd, rule.DstPortStart, rule.DstPortEnd)
		if rule.Protocol == "udp" {
			protol = header.UDPProtocolNumber
			matcher = netfilter.NewUDPMatcher(rule.SrcPortStart, rule.SrcPortEnd, rule.DstPortStart, rule.DstPortEnd)
		} else if rule.Protocol != "tcp" {
			log.Warningf("not supported protocol")
			continue
		}

		var src, srcMask, dst, dstMask tcpip.Address
		src = tcpip.Address(parseIPv4(rule.Src))
		srcMask = tcpip.Address(parseIPv4(rule.SrcMask))
		dst = tcpip.Address(parseIPv4(rule.Dst))
		dstMask = tcpip.Address(parseIPv4(rule.DstMask))

		r := stack.Rule{
			Filter: stack.IPHeaderFilter{
				Protocol:      protol,
				CheckProtocol: true,
				// SrcInvert:     srcInvert,
				Src:     src,
				SrcMask: srcMask,
				// DstInvert: dstInvert,
				Dst:     dst,
				DstMask: dstMask,
			},
			Target:   target,
			Matchers: []stack.Matcher{matcher},
		}
		rules = append(rules, r)
	}
	// add default rule
	rules = append(rules, defaultInputRule)
	// add forward default rule
	rules = append(rules, stack.Rule{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}})
	forwardStartIndex := len(rules) - 1
	outputStartIndex := forwardStartIndex + 1
	for _, rule := range args.OutputRules.Rules {
		// srcInvert, dstInvert := true, true
		// if rule.Src == "" {
		// 	srcInvert = false
		// }
		// if rule.Dst == "" {
		// 	dstInvert = false
		// }
		var target stack.Target
		switch rule.Action {
		case Drop:
			target = &stack.DropTarget{NetworkProtocol: header.IPv4ProtocolNumber}
		case Accept:
			target = &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}
		case Reject:
			target = &stack.ReturnTarget{NetworkProtocol: header.IPv4ProtocolNumber}
		default:
			return fmt.Errorf("not supported target %s", target)
		}

		protol := header.TCPProtocolNumber
		var matcher stack.Matcher = netfilter.NewTCPMatcher(rule.SrcPortStart, rule.SrcPortEnd, rule.DstPortStart, rule.DstPortEnd)
		if rule.Protocol == "udp" {
			protol = header.UDPProtocolNumber
			matcher = netfilter.NewUDPMatcher(rule.SrcPortStart, rule.SrcPortEnd, rule.DstPortStart, rule.DstPortEnd)
		} else if rule.Protocol != "tcp" {
			log.Warningf("not supported protocol")
			continue
		}

		var src, srcMask, dst, dstMask tcpip.Address
		src = tcpip.Address(parseIPv4(rule.Src))
		srcMask = tcpip.Address(parseIPv4(rule.SrcMask))
		dst = tcpip.Address(parseIPv4(rule.Dst))
		dstMask = tcpip.Address(parseIPv4(rule.DstMask))

		r := stack.Rule{
			Filter: stack.IPHeaderFilter{
				Protocol:      protol,
				CheckProtocol: true,
				// SrcInvert:     srcInvert,
				Src:     src,
				SrcMask: srcMask,
				// DstInvert: dstInvert,
				Dst:     dst,
				DstMask: dstMask,
			},
			Target:   target,
			Matchers: []stack.Matcher{matcher},
		}
		rules = append(rules, r)
	}

	// add default rule
	rules = append(rules, defaultOutputRule)
	rules = append(rules, stack.Rule{Target: &stack.ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}})

	table := stack.Table{
		Rules: rules,
		BuiltinChains: [stack.NumHooks]int{
			stack.Prerouting:  stack.HookUnset,
			stack.Input:       inputStartIndex,
			stack.Forward:     forwardStartIndex,
			stack.Output:      outputStartIndex,
			stack.Postrouting: stack.HookUnset,
		},
		Underflows: [stack.NumHooks]int{
			stack.Prerouting:  stack.HookUnset,
			stack.Input:       inputStartIndex,
			stack.Forward:     forwardStartIndex,
			stack.Output:      outputStartIndex,
			stack.Postrouting: stack.HookUnset,
		},
	}

	// log.Infof("new tables is %v", table)
	// for _, r := range rules {
	// 	log.Infof("rule %v", r)
	// }
	n.Stack.IPTables().ReplaceTable(stack.FilterID, table, false)
	log.Infof("replace stack iptables success!")
	return nil
}

func parseIPv4(s string) []byte {
	var p [4]byte
	for i := 0; i < 4; i++ {
		if len(s) == 0 {
			// Missing octets
			return nil
		}
		if i > 0 {
			if s[0] != '.' {
				return nil
			}
			s = s[1:]
		}
		n, c, ok := dtoi(s)
		if !ok || n > 0xFF {
			return nil
		}
		s = s[c:]
		p[i] = byte(n)
	}
	if len(s) != 0 {
		return nil
	}
	return p[:]
}

// Decimal to integer.
// Returns number, characters consumed, success.
const big = 0xFFFFFF

func dtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= big {
			return big, i, false
		}
	}
	if i == 0 {
		return 0, 0, false
	}
	return n, i, true
}

// CreateLinksAndRoutes creates links and routes in a network stack.  It should
// only be called once.
func (n *Network) CreateLinksAndRoutes(args *CreateLinksAndRoutesArgs, _ *struct{}) error {
	wantFDs := 0
	for _, l := range args.FDBasedLinks {
		wantFDs += l.NumChannels
	}
	if got := len(args.FilePayload.Files); got != wantFDs {
		return fmt.Errorf("args.FilePayload.Files has %d FD's but we need %d entries based on FDBasedLinks", got, wantFDs)
	}

	var nicID tcpip.NICID
	nicids := make(map[string]tcpip.NICID)

	// Collect routes from all links.
	var routes []tcpip.Route

	// Loopback normally appear before other interfaces.
	for _, link := range args.LoopbackLinks {
		nicID++
		nicids[link.Name] = nicID

		linkEP := ethernet.New(loopback.New())

		log.Infof("Enabling loopback interface %q with id %d on addresses %+v", link.Name, nicID, link.Addresses)
		if err := n.createNICWithAddrs(nicID, link.Name, linkEP, link.Addresses); err != nil {
			return err
		}

		// Collect the routes from this link.
		for _, r := range link.Routes {
			route, err := r.toTcpipRoute(nicID)
			if err != nil {
				return err
			}
			routes = append(routes, route)
		}
	}

	fdOffset := 0
	for _, link := range args.FDBasedLinks {
		nicID++
		nicids[link.Name] = nicID

		FDs := []int{}
		for j := 0; j < link.NumChannels; j++ {
			// Copy the underlying FD.
			oldFD := args.FilePayload.Files[fdOffset].Fd()
			newFD, err := unix.Dup(int(oldFD))
			if err != nil {
				return fmt.Errorf("failed to dup FD %v: %v", oldFD, err)
			}
			FDs = append(FDs, newFD)
			fdOffset++
		}

		mac := tcpip.LinkAddress(link.LinkAddress)
		log.Infof("gso max size is: %d", link.GSOMaxSize)

		linkEP, err := fdbased.New(&fdbased.Options{
			FDs:                FDs,
			MTU:                uint32(link.MTU),
			EthernetHeader:     mac != "",
			Address:            mac,
			PacketDispatchMode: fdbased.RecvMMsg,
			GSOMaxSize:         link.GSOMaxSize,
			SoftwareGSOEnabled: link.SoftwareGSOEnabled,
			TXChecksumOffload:  link.TXChecksumOffload,
			RXChecksumOffload:  link.RXChecksumOffload,
		})
		if err != nil {
			return err
		}

		switch link.QDisc {
		case config.QDiscNone:
		case config.QDiscFIFO:
			log.Infof("Enabling FIFO QDisc on %q", link.Name)
			linkEP = fifo.New(linkEP, runtime.GOMAXPROCS(0), 1000)
		}

		log.Infof("Enabling interface %q with id %d on addresses %+v (%v) w/ %d channels", link.Name, nicID, link.Addresses, mac, link.NumChannels)
		if err := n.createNICWithAddrs(nicID, link.Name, linkEP, link.Addresses); err != nil {
			return err
		}

		// Collect the routes from this link.
		for _, r := range link.Routes {
			route, err := r.toTcpipRoute(nicID)
			if err != nil {
				return err
			}
			routes = append(routes, route)
		}

		for _, neigh := range link.Neighbors {
			proto, tcpipAddr := ipToAddressAndProto(neigh.IP)
			n.Stack.AddStaticNeighbor(nicID, proto, tcpipAddr, tcpip.LinkAddress(neigh.HardwareAddr))
		}
	}

	if !args.Defaultv4Gateway.Route.Empty() {
		nicID, ok := nicids[args.Defaultv4Gateway.Name]
		if !ok {
			return fmt.Errorf("invalid interface name %q for default route", args.Defaultv4Gateway.Name)
		}
		route, err := args.Defaultv4Gateway.Route.toTcpipRoute(nicID)
		if err != nil {
			return err
		}
		routes = append(routes, route)
	}

	if !args.Defaultv6Gateway.Route.Empty() {
		nicID, ok := nicids[args.Defaultv6Gateway.Name]
		if !ok {
			return fmt.Errorf("invalid interface name %q for default route", args.Defaultv6Gateway.Name)
		}
		route, err := args.Defaultv6Gateway.Route.toTcpipRoute(nicID)
		if err != nil {
			return err
		}
		routes = append(routes, route)
	}

	log.Infof("Setting routes %+v", routes)
	n.Stack.SetRouteTable(routes)
	return nil
}

// createNICWithAddrs creates a NIC in the network stack and adds the given
// addresses.
func (n *Network) createNICWithAddrs(id tcpip.NICID, name string, ep stack.LinkEndpoint, addrs []IPWithPrefix) error {
	opts := stack.NICOptions{Name: name}
	if err := n.Stack.CreateNICWithOptions(id, sniffer.New(ep), opts); err != nil {
		return fmt.Errorf("CreateNICWithOptions(%d, _, %+v) failed: %v", id, opts, err)
	}

	for _, addr := range addrs {
		proto, tcpipAddr := ipToAddressAndProto(addr.Address)
		protocolAddr := tcpip.ProtocolAddress{
			Protocol: proto,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpipAddr,
				PrefixLen: addr.PrefixLen,
			},
		}
		if err := n.Stack.AddProtocolAddress(id, protocolAddr, stack.AddressProperties{}); err != nil {
			return fmt.Errorf("AddProtocolAddress(%d, %+v, {}) failed: %s", id, protocolAddr, err)
		}
	}
	return nil
}

// ipToAddressAndProto converts IP to tcpip.Address and a protocol number.
//
// Note: don't use 'len(ip)' to determine IP version because length is always 16.
func ipToAddressAndProto(ip net.IP) (tcpip.NetworkProtocolNumber, tcpip.Address) {
	if i4 := ip.To4(); i4 != nil {
		return ipv4.ProtocolNumber, tcpip.Address(i4)
	}
	return ipv6.ProtocolNumber, tcpip.Address(ip)
}

// ipToAddress converts IP to tcpip.Address, ignoring the protocol.
func ipToAddress(ip net.IP) tcpip.Address {
	_, addr := ipToAddressAndProto(ip)
	return addr
}

// ipMaskToAddressMask converts IPMask to tcpip.AddressMask, ignoring the
// protocol.
func ipMaskToAddressMask(ipMask net.IPMask) tcpip.AddressMask {
	return tcpip.AddressMask(ipToAddress(net.IP(ipMask)))
}
