package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/google/subcommands"
	"spf-checker/internal/dns"
	"spf-checker/internal/formatter"
)

type ListCmd struct {
	domain string
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
}

func (l *ListCmd) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {

	d := dns.NewDomain(l.domain)
	txtRecord, err := d.GetSpfRecord()
	if errors.Is(err, dns.ErrorNoTxtRecord) || errors.Is(err, dns.ErrorNoSpfRecord) {
		fmt.Println(err)
		return subcommands.ExitSuccess
	}
	if err != nil {
		fmt.Printf("unexpected error: %v)\n", err)
		return subcommands.ExitFailure
	}

	fmt.Println(formatter.FormatSpfRecordAligned(txtRecord))

	return subcommands.ExitSuccess
}
