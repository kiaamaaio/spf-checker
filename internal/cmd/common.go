package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/subcommands"

	"spf-checker/internal/dns"
	"spf-checker/internal/validation"
)

const defaultTimeout = 10 * time.Second

// Exit statuses. subcommands only defines success/failure/usage-error, so the
// remaining ones are declared here to keep the cli scriptable.
const (
	exitNotAuthorized subcommands.ExitStatus = 1
	exitUsageError    subcommands.ExitStatus = 2
	exitLookupError   subcommands.ExitStatus = 3
)

// fetchSpfRecord validates the domain and returns its spf record. The returned
// exit status is meaningful only when ok is false.
func fetchSpfRecord(ctx context.Context, errOut io.Writer, domain string) (string, subcommands.ExitStatus, bool) {
	if err := validation.ValidateDnsRecordName(domain); err != nil {
		fmt.Fprintf(errOut, "%v: %q\n", err, domain)
		return "", exitUsageError, false
	}

	record, err := dns.NewDomain(domain).GetSpfRecord(ctx)
	switch {
	case errors.Is(err, dns.ErrNoTxtRecord), errors.Is(err, dns.ErrNoSpfRecord), errors.Is(err, dns.ErrMultipleSpfRecords):
		fmt.Fprintf(errOut, "%v (domain: %s)\n", err, domain)
		return "", exitLookupError, false
	case err != nil:
		fmt.Fprintf(errOut, "unexpected error: %v (domain: %s)\n", err, domain)
		return "", exitLookupError, false
	}

	return record, subcommands.ExitSuccess, true
}

// contextWithTimeout applies the command timeout, treating zero as "no limit".
func contextWithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}
