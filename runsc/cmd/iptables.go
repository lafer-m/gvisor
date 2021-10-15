package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/control/client"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/flag"
)

type Iptables struct {
	content string
}

// Name implements subcommands.Command.Name.
func (*Iptables) Name() string {
	return "iptables"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Iptables) Synopsis() string {
	return "replace iptables resources held by a container"
}

// Usage implements subcommands.Command.Usage.
func (*Iptables) Usage() string {
	return `iptables [flags] <container ids>`
}

// SetFlags implements subcommands.Command.SetFlags.
func (i *Iptables) SetFlags(f *flag.FlagSet) {
	// f.BoolVar(&d.force, "force", false, "terminate container if running")
	f.StringVar(&i.content, "data", "{}", "iptables replace data")
}

// Execute implements subcommands.Command.Execute.
func (i *Iptables) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() == 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	// should want the container sandbox id
	id := f.Args()[0]
	log.Infof("start to connect to sandbox %q", id)
	conn, err := sandboxConnect(id)
	if err != nil {
		log.Infof("connect err: %v", err)
		return subcommands.ExitFailure
	}
	defer conn.Close()
	callArg := &boot.ReplaceIPTableArg{}
	if err := json.Unmarshal([]byte(i.content), callArg); err != nil {
		log.Infof("parse data err: %v", err)
		return subcommands.ExitFailure
	}

	log.Infof("call Args content: %s json: %v, table: %s", i.content, callArg.InputRules, callArg.Table)

	log.Infof("start to call NetworkReplaceIptables")
	if err := conn.Call(boot.NetworkReplaceIptables, callArg, nil); err != nil {
		log.Debugf("Replace container iptables %q: %v", id, err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func sandboxConnect(sandboxID string) (*urpc.Client, error) {
	log.Debugf("Connecting to sandbox %q", sandboxID)
	conn, err := client.ConnectTo(boot.ControlSocketAddr(sandboxID))
	if err != nil {
		return nil, fmt.Errorf("connect to sandbox %q err: %v", sandboxID, err)
	}
	return conn, nil
}
