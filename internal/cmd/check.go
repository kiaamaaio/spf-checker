package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/google/subcommands"
	"spf-checker/internal/dns"
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

	d := dns.NewDomain(c.domain)
	txtRecord, err := d.GetSpfRecord()
	if errors.Is(err, dns.ErrorNoTxtRecord) {
		fmt.Println(err)
		return subcommands.ExitSuccess
	}
	if err != nil {
		fmt.Printf("unexpected error: %v)\n", err)
		return subcommands.ExitFailure
	}

	var isIPListedInSpf bool
	sr := dns.NewSpfRecord(txtRecord)
	isIPListedInSpf, err = sr.ContainsIP(c.ipAddr)

	if err != nil {
		fmt.Printf("Failed to check record. (err:%v, txtRecord:%s)\n", err, txtRecord)
		return subcommands.ExitFailure
	}
	if isIPListedInSpf {
		fmt.Printf("%s\n", txtRecord)
		return subcommands.ExitSuccess
	}

	return subcommands.ExitSuccess
}
