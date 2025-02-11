package cmd

import (
	"context"
	"flag"
	"fmt"
	"github.com/google/subcommands"
)

type CheckCmd struct {
	domain string
	ipAddr string
}

func (c *CheckCmd) Name() string {
	return "check"
}

func (c *CheckCmd) Synopsis() string {
	return "check if an ip address is in the spf record."
}

func (c *CheckCmd) Usage() string {
	return `check -domain <domain> -ipaddr <ip address>
	Check if an ip address is in the spf record.
`
}

func (c *CheckCmd) SetFlags(set *flag.FlagSet) {
	set.StringVar(&c.domain, "domain", "", "Domain to check")
	set.StringVar(&c.ipAddr, "ipaddr", "", "IP address to check")
}

func (c *CheckCmd) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {

	fmt.Println("test")

	return subcommands.ExitSuccess
}
