package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/google/subcommands"
	"spf-checker/internal/dns"
	"spf-checker/internal/validation"
)

type CheckCmd struct {
	domain    string
	ipAddr    string
	recursive bool
}

func (c *CheckCmd) Name() string {
	return "check"
}

func (c *CheckCmd) Synopsis() string {
	return "check if an ip address is in the spf record"
}

func (c *CheckCmd) Usage() string {
	return `check -recursive -domain <domain> -ipaddr <ip address>
	Check if an ip address is in the spf record.
`
}

func (c *CheckCmd) SetFlags(set *flag.FlagSet) {
	set.StringVar(&c.domain, "domain", "", "domain to check")
	set.StringVar(&c.ipAddr, "ipaddr", "", "ip address to check")
	set.BoolVar(&c.recursive, "recursive", false, "recursively check include mechanisms")
}

func (c *CheckCmd) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	_, err := validation.IsValidDnsRecordName(c.domain)
	if errors.Is(err, validation.ErrorInvalidDnsRecordName) {
		fmt.Println(err)
		return subcommands.ExitSuccess
	}
	if err != nil {
		fmt.Printf("unexpected error: %v)\n", err)
		return subcommands.ExitFailure
	}

	d := dns.NewDomain(c.domain)
	txtRecord, err := d.GetSpfRecord()
	if errors.Is(err, dns.ErrorNoTxtRecord) || errors.Is(err, dns.ErrorNoSpfRecord) {
		fmt.Println(err)
		return subcommands.ExitSuccess
	}
	if err != nil {
		fmt.Printf("unexpected error: %v)\n", err)
		return subcommands.ExitFailure
	}

	var isIPListedInSpf bool
	sr := dns.NewSpfRecord(txtRecord)
	if c.recursive {
		isIPListedInSpf, err = sr.ContainsIPRecursive(c.ipAddr, map[string]struct{}{c.domain: {}})
	} else {
		isIPListedInSpf, err = sr.ContainsIP(c.ipAddr)
	}

	if errors.Is(err, validation.ErrorInvalidIpAddress) {
		fmt.Println(err)
		return subcommands.ExitSuccess
	}
	if err != nil {
		fmt.Printf("failed to check record (err:%v, txtRecord:%s)\n", err, txtRecord)
		return subcommands.ExitFailure
	}
	if isIPListedInSpf {
		fmt.Printf("%s\n", txtRecord)
		return subcommands.ExitSuccess
	}

	return subcommands.ExitSuccess
}
