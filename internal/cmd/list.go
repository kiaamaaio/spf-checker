package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/subcommands"

	"spf-checker/internal/dns"
	"spf-checker/internal/output"
)

type ListCmd struct {
	domain  string
	timeout time.Duration
}

func (l *ListCmd) Name() string {
	return "list"
}

func (l *ListCmd) Synopsis() string {
	return "list spf records for the domain"
}

func (l *ListCmd) Usage() string {
	return `list -domain <domain>:
	List spf records for the domain.
`
}

func (l *ListCmd) SetFlags(set *flag.FlagSet) {
	set.StringVar(&l.domain, "domain", "", "domain to check")
	set.DurationVar(&l.timeout, "timeout", defaultTimeout, "dns lookup timeout (0 for no limit)")
}

func (l *ListCmd) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected arguments: %v\n", f.Args())
		return exitUsageError
	}

	ctx, cancel := contextWithTimeout(ctx, l.timeout)
	defer cancel()

	txtRecord, status, ok := fetchSpfRecord(ctx, os.Stderr, l.domain)
	if !ok {
		return status
	}

	fmt.Println(output.FormatSpfRecordAligned(dns.ParseSpfRecord(txtRecord)))

	return subcommands.ExitSuccess
}
