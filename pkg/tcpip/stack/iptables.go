// Copyright 2019 The gVisor Authors.
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

package stack

import (
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TableID identifies a specific table.
type TableID int

// Each value identifies a specific table.
const (
	NATID TableID = iota
	MangleID
	FilterID
	NumTables
)

// HookUnset indicates that there is no hook set for an entrypoint or
// underflow.
const HookUnset = -1

// reaperDelay is how long to wait before starting to reap connections.
const reaperDelay = 5 * time.Second

// DefaultTables returns a default set of tables. Each chain is set to accept
// all packets.
func DefaultTables(seed uint32, clock tcpip.Clock) *IPTables {
	return &IPTables{
		v4Tables: [NumTables]Table{
			NATID: {
				Rules: []Rule{
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  0,
					Input:       1,
					Forward:     HookUnset,
					Output:      2,
					Postrouting: 3,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       1,
					Forward:     HookUnset,
					Output:      2,
					Postrouting: 3,
				},
			},
			MangleID: {
				Rules: []Rule{
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting: 0,
					Output:     1,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       HookUnset,
					Forward:     HookUnset,
					Output:      1,
					Postrouting: HookUnset,
				},
			},
			FilterID: {
				Rules: []Rule{
					// {
					// 	Filter: IPHeaderFilter{
					// 		Protocol:             header.TCPProtocolNumber,
					// 		CheckProtocol:        true,
					// 		DstInvert: 			  true,
					// 		Dst:                  "172.17.0.2",
					// 		DstMask:              "255.255.255.0",

					// 	},
					// 	Target: &DropTarget{NetworkProtocol: header.IPv4ProtocolNumber},
					// 	Matchers: []Matcher{&defaultTcpMatcher{
					// 		sourcePortStart:      1,
					// 		sourcePortEnd:        60000,
					// 		destinationPortStart: 79,
					// 		destinationPortEnd:   60000,
					// 	}},
					// },
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  HookUnset,
					Input:       0,
					Forward:     1,
					Output:      2,
					Postrouting: HookUnset,
				},
				Underflows: [NumHooks]int{
					Prerouting:  HookUnset,
					Input:       0,
					Forward:     1,
					Output:      2,
					Postrouting: HookUnset,
				},
			},
		},
		v6Tables: [NumTables]Table{
			NATID: {
				Rules: []Rule{
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &ErrorTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  0,
					Input:       1,
					Forward:     HookUnset,
					Output:      2,
					Postrouting: 3,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       1,
					Forward:     HookUnset,
					Output:      2,
					Postrouting: 3,
				},
			},
			MangleID: {
				Rules: []Rule{
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &ErrorTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting: 0,
					Output:     1,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       HookUnset,
					Forward:     HookUnset,
					Output:      1,
					Postrouting: HookUnset,
				},
			},
			FilterID: {
				Rules: []Rule{
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &ErrorTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  HookUnset,
					Input:       0,
					Forward:     1,
					Output:      2,
					Postrouting: HookUnset,
				},
				Underflows: [NumHooks]int{
					Prerouting:  HookUnset,
					Input:       0,
					Forward:     1,
					Output:      2,
					Postrouting: HookUnset,
				},
			},
		},
		priorities: [NumHooks][]TableID{
			Prerouting:  {MangleID, NATID},
			Input:       {NATID, FilterID},
			Forward:     {FilterID},
			Output:      {MangleID, NATID, FilterID},
			Postrouting: {MangleID, NATID},
		},
		connections: ConnTrack{
			seed:  seed,
			clock: clock,
		},
		reaperDone: make(chan struct{}, 1),
	}
}

// EmptyFilterTable returns a Table with no rules and the filter table chains
// mapped to HookUnset.
func EmptyFilterTable() Table {
	return Table{
		Rules: []Rule{},
		BuiltinChains: [NumHooks]int{
			Prerouting:  HookUnset,
			Postrouting: HookUnset,
		},
		Underflows: [NumHooks]int{
			Prerouting:  HookUnset,
			Postrouting: HookUnset,
		},
	}
}

// EmptyNATTable returns a Table with no rules and the filter table chains
// mapped to HookUnset.
func EmptyNATTable() Table {
	return Table{
		Rules: []Rule{},
		BuiltinChains: [NumHooks]int{
			Forward: HookUnset,
		},
		Underflows: [NumHooks]int{
			Forward: HookUnset,
		},
	}
}

// GetTable returns a table with the given id and IP version. It panics when an
// invalid id is provided.
func (it *IPTables) GetTable(id TableID, ipv6 bool) Table {
	it.mu.RLock()
	defer it.mu.RUnlock()
	if ipv6 {
		return it.v6Tables[id]
	}
	return it.v4Tables[id]
}

// ReplaceTable replaces or inserts table by name. It panics when an invalid id
// is provided.
func (it *IPTables) ReplaceTable(id TableID, table Table, ipv6 bool) tcpip.Error {
	it.mu.Lock()
	defer it.mu.Unlock()
	// If iptables is being enabled, initialize the conntrack table and
	// reaper.
	if !it.modified {
		it.connections.init()
		it.startReaper(reaperDelay)
	}
	it.modified = true
	if ipv6 {
		it.v6Tables[id] = table
	} else {
		it.v4Tables[id] = table
	}
	return nil
}

// A chainVerdict is what a table decides should be done with a packet.
type chainVerdict int

const (
	// chainAccept indicates the packet should continue through netstack.
	chainAccept chainVerdict = iota

	// chainAccept indicates the packet should be dropped.
	chainDrop

	// chainReturn indicates the packet should return to the calling chain
	// or the underflow rule of a builtin chain.
	chainReturn
)

// CheckPrerouting performs the prerouting hook on the packet.
//
// Returns true iff the packet may continue traversing the stack; the packet
// must be dropped if false is returned.
//
// Precondition: The packet's network and transport header must be set.
func (it *IPTables) CheckPrerouting(pkt *PacketBuffer, addressEP AddressableEndpoint, inNicName string) bool {
	const hook = Prerouting

	if it.shouldSkip(pkt.NetworkProtocolNumber) {
		return true
	}

	pkt.tuple = it.connections.getConnOrMaybeInsertNoop(pkt)

	return it.check(hook, pkt, nil /* route */, addressEP, inNicName, "" /* outNicName */)
}

// CheckInput performs the input hook on the packet.
//
// Returns true iff the packet may continue traversing the stack; the packet
// must be dropped if false is returned.
//
// Precondition: The packet's network and transport header must be set.
func (it *IPTables) CheckInput(pkt *PacketBuffer, r *Route, inNicName string) bool {
	const hook = Input
	if it.shouldSkip(pkt.NetworkProtocolNumber) {
		return true
	}

	ret := it.check(hook, pkt, r /* route */, nil /* addressEP */, inNicName, "" /* outNicName */)
	if t := pkt.tuple; t != nil {
		t.conn.finalize()
	}
	pkt.tuple = nil
	return ret
}

// CheckForward performs the forward hook on the packet.
//
// Returns true iff the packet may continue traversing the stack; the packet
// must be dropped if false is returned.
//
// Precondition: The packet's network and transport header must be set.
func (it *IPTables) CheckForward(pkt *PacketBuffer, inNicName, outNicName string) bool {
	if it.shouldSkip(pkt.NetworkProtocolNumber) {
		return true
	}
	return it.check(Forward, pkt, nil /* route */, nil /* addressEP */, inNicName, outNicName)
}

// CheckOutput performs the output hook on the packet.
//
// Returns true iff the packet may continue traversing the stack; the packet
// must be dropped if false is returned.
//
// Precondition: The packet's network and transport header must be set.
func (it *IPTables) CheckOutput(pkt *PacketBuffer, r *Route, outNicName string) bool {
	const hook = Output

	if it.shouldSkip(pkt.NetworkProtocolNumber) {
		return true
	}

	pkt.tuple = it.connections.getConnOrMaybeInsertNoop(pkt)

	return it.check(hook, pkt, r, nil /* addressEP */, "" /* inNicName */, outNicName)
}

// CheckPostrouting performs the postrouting hook on the packet.
//
// Returns true iff the packet may continue traversing the stack; the packet
// must be dropped if false is returned.
//
// Precondition: The packet's network and transport header must be set.
func (it *IPTables) CheckPostrouting(pkt *PacketBuffer, r *Route, addressEP AddressableEndpoint, outNicName string) bool {
	const hook = Postrouting

	if it.shouldSkip(pkt.NetworkProtocolNumber) {
		return true
	}

	ret := it.check(hook, pkt, r, addressEP, "" /* inNicName */, outNicName)
	if t := pkt.tuple; t != nil {
		t.conn.finalize()
	}
	pkt.tuple = nil
	return ret
}

func (it *IPTables) shouldSkip(netProto tcpip.NetworkProtocolNumber) bool {
	switch netProto {
	case header.IPv4ProtocolNumber, header.IPv6ProtocolNumber:
	default:
		// IPTables only supports IPv4/IPv6.
		return true
	}

	it.mu.RLock()
	defer it.mu.RUnlock()
	// Many users never configure iptables. Spare them the cost of rule
	// traversal if rules have never been set.
	return !it.modified
}

// check runs pkt through the rules for hook. It returns true when the packet
// should continue traversing the network stack and false when it should be
// dropped.
//
// Precondition: The packet's network and transport header must be set.
func (it *IPTables) check(hook Hook, pkt *PacketBuffer, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) bool {
	it.mu.RLock()
	defer it.mu.RUnlock()

	// Go through each table containing the hook.
	priorities := it.priorities[hook]
	for _, tableID := range priorities {
		if t := pkt.tuple; t != nil && tableID == NATID && t.conn.handlePacket(pkt, hook, r) {
			continue
		}
		var table Table
		if pkt.NetworkProtocolNumber == header.IPv6ProtocolNumber {
			table = it.v6Tables[tableID]
		} else {
			table = it.v4Tables[tableID]
		}

		ruleIdx := table.BuiltinChains[hook]
		switch verdict := it.checkChain(hook, pkt, table, ruleIdx, r, addressEP, inNicName, outNicName); verdict {
		// If the table returns Accept, move on to the next table.
		case chainAccept:
			continue
		// The Drop verdict is final.
		case chainDrop:
			return false
		case chainReturn:
			// Any Return from a built-in chain means we have to
			// call the underflow.
			underflow := table.Rules[table.Underflows[hook]]
			switch v, _ := underflow.Target.Action(pkt, hook, r, addressEP); v {
			case RuleAccept:
				continue
			case RuleDrop:
				return false
			case RuleJump, RuleReturn:
				panic("Underflows should only return RuleAccept or RuleDrop.")
			default:
				panic(fmt.Sprintf("Unknown verdict: %d", v))
			}

		default:
			panic(fmt.Sprintf("Unknown verdict %v.", verdict))
		}
	}

	return true
}

// beforeSave is invoked by stateify.
func (it *IPTables) beforeSave() {
	// Ensure the reaper exits cleanly.
	it.reaperDone <- struct{}{}
	// Prevent others from modifying the connection table.
	it.connections.mu.Lock()
}

// afterLoad is invoked by stateify.
func (it *IPTables) afterLoad() {
	it.startReaper(reaperDelay)
}

// startReaper starts a goroutine that wakes up periodically to reap timed out
// connections.
func (it *IPTables) startReaper(interval time.Duration) {
	go func() { // S/R-SAFE: reaperDone is signalled when iptables is saved.
		bucket := 0
		for {
			select {
			case <-it.reaperDone:
				return
				// TODO(gvisor.dev/issue/5939): do not use the ambient clock.
			case <-time.After(interval):
				bucket, interval = it.connections.reapUnused(bucket, interval)
			}
		}
	}()
}

// CheckOutputPackets performs the output hook on the packets.
//
// Returns a map of packets that must be dropped.
//
// Precondition:  The packets' network and transport header must be set.
func (it *IPTables) CheckOutputPackets(pkts PacketBufferList, r *Route, outNicName string) (drop map[*PacketBuffer]struct{}, natPkts map[*PacketBuffer]struct{}) {
	return checkPackets(pkts, func(pkt *PacketBuffer) bool {
		return it.CheckOutput(pkt, r, outNicName)
	}, true /* dnat */)
}

// CheckPostroutingPackets performs the postrouting hook on the packets.
//
// Returns a map of packets that must be dropped.
//
// Precondition:  The packets' network and transport header must be set.
func (it *IPTables) CheckPostroutingPackets(pkts PacketBufferList, r *Route, addressEP AddressableEndpoint, outNicName string) (drop map[*PacketBuffer]struct{}, natPkts map[*PacketBuffer]struct{}) {
	return checkPackets(pkts, func(pkt *PacketBuffer) bool {
		return it.CheckPostrouting(pkt, r, addressEP, outNicName)
	}, false /* dnat */)
}

func checkPackets(pkts PacketBufferList, f func(*PacketBuffer) bool, dnat bool) (drop map[*PacketBuffer]struct{}, natPkts map[*PacketBuffer]struct{}) {
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		natDone := &pkt.SNATDone
		if dnat {
			natDone = &pkt.DNATDone
		}

		if ok := f(pkt); !ok {
			if drop == nil {
				drop = make(map[*PacketBuffer]struct{})
			}
			drop[pkt] = struct{}{}
		}
		if *natDone {
			if natPkts == nil {
				natPkts = make(map[*PacketBuffer]struct{})
			}
			natPkts[pkt] = struct{}{}
		}
	}
	return drop, natPkts
}

// Preconditions:
// * pkt is a IPv4 packet of at least length header.IPv4MinimumSize.
// * pkt.NetworkHeader is not nil.
func (it *IPTables) checkChain(hook Hook, pkt *PacketBuffer, table Table, ruleIdx int, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) chainVerdict {
	// Start from ruleIdx and walk the list of rules until a rule gives us
	// a verdict.
	for ruleIdx < len(table.Rules) {
		switch verdict, jumpTo := it.checkRule(hook, pkt, table, ruleIdx, r, addressEP, inNicName, outNicName); verdict {
		case RuleAccept:
			return chainAccept

		case RuleDrop:
			return chainDrop

		case RuleReturn:
			return chainReturn

		case RuleJump:
			// "Jumping" to the next rule just means we're
			// continuing on down the list.
			if jumpTo == ruleIdx+1 {
				ruleIdx++
				continue
			}
			switch verdict := it.checkChain(hook, pkt, table, jumpTo, r, addressEP, inNicName, outNicName); verdict {
			case chainAccept:
				return chainAccept
			case chainDrop:
				return chainDrop
			case chainReturn:
				ruleIdx++
				continue
			default:
				panic(fmt.Sprintf("Unknown verdict: %d", verdict))
			}

		default:
			panic(fmt.Sprintf("Unknown verdict: %d", verdict))
		}

	}

	// We got through the entire table without a decision. Default to DROP
	// for safety.
	return chainDrop
}

// Preconditions:
// * pkt is a IPv4 packet of at least length header.IPv4MinimumSize.
// * pkt.NetworkHeader is not nil.
func (it *IPTables) checkRule(hook Hook, pkt *PacketBuffer, table Table, ruleIdx int, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) (RuleVerdict, int) {
	rule := table.Rules[ruleIdx]

	// Check whether the packet matches the IP header filter.
	if !rule.Filter.match(pkt, hook, inNicName, outNicName) {
		// Continue on to the next rule.
		return RuleJump, ruleIdx + 1
	}

	// Go through each rule matcher. If they all match, run
	// the rule target.
	for _, matcher := range rule.Matchers {
		matches, hotdrop := matcher.Match(hook, pkt, inNicName, outNicName)
		if hotdrop {
			return RuleDrop, 0
		}
		if !matches {
			// Continue on to the next rule.
			return RuleJump, ruleIdx + 1
		}
	}

	// All the matchers matched, so run the target.
	return rule.Target.Action(pkt, hook, r, addressEP)
}

// OriginalDst returns the original destination of redirected connections. It
// returns an error if the connection doesn't exist or isn't redirected.
func (it *IPTables) OriginalDst(epID TransportEndpointID, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber) (tcpip.Address, uint16, tcpip.Error) {
	it.mu.RLock()
	defer it.mu.RUnlock()
	if !it.modified {
		return "", 0, &tcpip.ErrNotConnected{}
	}
	return it.connections.originalDst(epID, netProto, transProto)
}

type defaultTcpMatcher struct {
	sourcePortStart      uint16
	sourcePortEnd        uint16
	destinationPortStart uint16
	destinationPortEnd   uint16
}

func (*defaultTcpMatcher) name() string {
	return "tcp"
}

func (tm *defaultTcpMatcher) Match(hook Hook, pkt *PacketBuffer, _, _ string) (matches bool, hotdrop bool) {
	// log.Infof("begin to test match: %v, pkt: %v", hook, pkt)
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		netHeader := header.IPv4(pkt.NetworkHeader().View())
		if netHeader.TransportProtocol() != header.TCPProtocolNumber {
			return false, false
		}

		// We don't match fragments.
		if frag := netHeader.FragmentOffset(); frag != 0 {
			if frag == 1 {
				return false, true
			}
			return false, false
		}

	case header.IPv6ProtocolNumber:
		// As in Linux, we do not perform an IPv6 fragment check. See
		// xt_action_param.fragoff in
		// include/linux/netfilter/x_tables.h.
		if header.IPv6(pkt.NetworkHeader().View()).TransportProtocol() != header.TCPProtocolNumber {
			return false, false
		}

	default:
		// We don't know the network protocol.
		return false, false
	}

	tcpHeader := header.TCP(pkt.TransportHeader().View())
	if len(tcpHeader) < header.TCPMinimumSize {
		// There's no valid TCP header here, so we drop the packet immediately.
		return false, true
	}

	// Check whether the source and destination ports are within the
	// matching range.
	if sourcePort := tcpHeader.SourcePort(); sourcePort < tm.sourcePortStart || tm.sourcePortEnd < sourcePort {
		return false, false
	}
	if destinationPort := tcpHeader.DestinationPort(); destinationPort < tm.destinationPortStart || tm.destinationPortEnd < destinationPort {
		return false, false
	}
	return true, false
}
