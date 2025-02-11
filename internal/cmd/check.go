package cmd

import (
	"context"
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
	records, err := d.GetSpfRecords()
	if err != nil {
		fmt.Printf("Failed to get spf records. (err: %v)\n", err)
		return subcommands.ExitFailure
	}

	var checkedResult bool
	for _, record := range records {
		sr := dns.NewSpfRecord(record)
		checkedResult, err = sr.Check(c.ipAddr)

		if err != nil {
			fmt.Printf("Failed to check record. (err:%v, txtRecord:%s)\n", err, record)
			return subcommands.ExitFailure
		}
		if checkedResult {
			fmt.Printf("%t\n", checkedResult)
			return subcommands.ExitSuccess
		}
	}

	fmt.Printf("%t\n", checkedResult)
	return subcommands.ExitFailure
}
