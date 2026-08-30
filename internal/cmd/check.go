package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/subcommands"

	"spf-checker/internal/dns"
	"spf-checker/internal/validation"
)

type CheckCmd struct {
	domain    string
	ipAddr    string
	recursive bool
	timeout   time.Duration
}

func (c *CheckCmd) Name() string {
	return "check"
}

func (c *CheckCmd) Synopsis() string {
	return "check if an ip address is in the spf record"
}

func (c *CheckCmd) Usage() string {
	return `check [-recursive] -domain <domain> -ipaddr <ip address>:
	Check if an ip address is authorized by the spf record.

	Exit status:
	  0  pass         the ip is authorized
	  1  not pass     fail, softfail, neutral or none
	  2  usage error  invalid domain or ip address
	  3  lookup error the record could not be retrieved or evaluated
`
}

func (c *CheckCmd) SetFlags(set *flag.FlagSet) {
	set.StringVar(&c.domain, "domain", "", "domain to check")
	set.StringVar(&c.ipAddr, "ipaddr", "", "ip address to check")
	set.BoolVar(&c.recursive, "recursive", false, "follow include, redirect, a and mx terms")
	set.DurationVar(&c.timeout, "timeout", defaultTimeout, "dns lookup timeout (0 for no limit)")
}

func (c *CheckCmd) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected arguments: %v\n", f.Args())
		return exitUsageError
	}

	// Validate the ip address before spending a dns lookup on the domain.
	parsedIP, err := validation.ParseIP(c.ipAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v: %q\n", err, c.ipAddr)
		return exitUsageError
	}

	ctx, cancel := contextWithTimeout(ctx, c.timeout)
	defer cancel()

	txtRecord, status, ok := fetchSpfRecord(ctx, os.Stderr, c.domain)
	if !ok {
		return status
	}

	evaluation := dns.NewEvaluator(dns.DefaultResolver, c.recursive).Check(ctx, c.domain, txtRecord, parsedIP)
	printEvaluation(txtRecord, c.domain, c.ipAddr, evaluation)

	switch evaluation.Result {
	case dns.ResultPass:
		return subcommands.ExitSuccess
	case dns.ResultPermError, dns.ResultTempError:
		return exitLookupError
	default:
		return exitNotAuthorized
	}
}

func printEvaluation(txtRecord, domain, ipAddr string, evaluation *dns.Evaluation) {
	fmt.Printf("%-15s : %s\n", "Domain", domain)
	fmt.Printf("%-15s : %s\n", "IP", ipAddr)
	fmt.Printf("%-15s : %s\n", "Record", txtRecord)
	fmt.Printf("%-15s : %s\n", "Result", evaluation.Result)
	if evaluation.MatchedBy != "" {
		fmt.Printf("%-15s : %s (in the record of %s)\n", "Matched", evaluation.MatchedBy, evaluation.MatchedAt)
	}
	fmt.Printf("%-15s : %d\n", "DNS Lookups", evaluation.Lookups)

	for _, warning := range evaluation.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}
}
