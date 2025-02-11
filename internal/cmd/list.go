package cmd

import (
	"context"
	"flag"
	"fmt"
	"github.com/google/subcommands"
	"spf-checker/internal/delimiter"
	"spf-checker/internal/dns"
)

type ListCmd struct {
	domain string
}

func (l *ListCmd) Name() string {
	return "list"
}

func (l *ListCmd) Synopsis() string {
	return "List spf records for the domain."
}

func (l *ListCmd) Usage() string {
	return `list -domain <domain>:
	List spf records for the domain.
`
}

func (l *ListCmd) SetFlags(set *flag.FlagSet) {
	set.StringVar(&l.domain, "domain", "", "Domain to check")
}

func (l *ListCmd) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {

	d := dns.NewDomain(l.domain)
	records, err := d.GetSpfRecords()
	if err != nil {
		fmt.Printf("Failed to get spf records. (err: %v)\n", err)
		return subcommands.ExitFailure
	}

	var displayRecords []string
	for _, record := range records {
		displayRecords = append(displayRecords, delimiter.Whitespace(record))
	}
	fmt.Println(delimiter.Element(displayRecords))

	return subcommands.ExitSuccess
}
