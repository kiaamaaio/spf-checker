package cmd

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/google/subcommands"

	"spf-checker/internal/dns"
)

type stubResolver struct {
	txt map[string][]string
}

func (s stubResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	records, ok := s.txt[name]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", name)
	}
	return records, nil
}

func (s stubResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	return nil, fmt.Errorf("no such host: %s", host)
}

func (s stubResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return nil, fmt.Errorf("no such host: %s", name)
}

// withStubResolver points the commands at a fake resolver and silences stdout
// for the duration of the test.
func withStubResolver(t *testing.T, txt map[string][]string) {
	t.Helper()

	previousResolver := dns.DefaultResolver
	dns.DefaultResolver = stubResolver{txt: txt}

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("cannot open %s: %v", os.DevNull, err)
	}
	previousStdout, previousStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = devNull, devNull

	t.Cleanup(func() {
		dns.DefaultResolver = previousResolver
		os.Stdout, os.Stderr = previousStdout, previousStderr
		devNull.Close()
	})
}

func runCheck(t *testing.T, args ...string) subcommands.ExitStatus {
	t.Helper()

	command := &CheckCmd{}
	set := flag.NewFlagSet("check", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	command.SetFlags(set)
	if err := set.Parse(args); err != nil {
		t.Fatalf("cannot parse %v: %v", args, err)
	}
	return command.Execute(context.Background(), set)
}

func TestCheckExitStatus(t *testing.T) {
	withStubResolver(t, map[string][]string{
		"example.test": {"v=spf1 ip4:192.0.2.0/24 -all"},
		"notxt.test":   nil,
		"nospf.test":   {"example-domain-verification=abc"},
	})

	tests := []struct {
		name string
		args []string
		want subcommands.ExitStatus
	}{
		{
			name: "authorized ip",
			args: []string{"-domain", "example.test", "-ipaddr", "192.0.2.1"},
			want: subcommands.ExitSuccess,
		},
		{
			name: "unauthorized ip",
			args: []string{"-domain", "example.test", "-ipaddr", "203.0.113.1"},
			want: exitNotAuthorized,
		},
		{
			name: "invalid ip address",
			args: []string{"-domain", "example.test", "-ipaddr", "999.999.999.999"},
			want: exitUsageError,
		},
		{
			name: "missing ip address",
			args: []string{"-domain", "example.test"},
			want: exitUsageError,
		},
		{
			name: "invalid domain",
			args: []string{"-domain", "exam$ple.test", "-ipaddr", "192.0.2.1"},
			want: exitUsageError,
		},
		{
			name: "unexpected positional argument",
			args: []string{"-domain", "example.test", "-ipaddr", "192.0.2.1", "extra"},
			want: exitUsageError,
		},
		{
			name: "domain without a txt record",
			args: []string{"-domain", "missing.test", "-ipaddr", "192.0.2.1"},
			want: exitLookupError,
		},
		{
			name: "domain without an spf record",
			args: []string{"-domain", "nospf.test", "-ipaddr", "192.0.2.1"},
			want: exitLookupError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runCheck(t, tt.args...); got != tt.want {
				t.Errorf("exit status = %d; want %d", got, tt.want)
			}
		})
	}
}

func TestListExitStatus(t *testing.T) {
	withStubResolver(t, map[string][]string{
		"example.test": {"v=spf1 ip4:192.0.2.0/24 -all"},
	})

	tests := []struct {
		name string
		args []string
		want subcommands.ExitStatus
	}{
		{"existing record", []string{"-domain", "example.test"}, subcommands.ExitSuccess},
		{"empty domain", []string{"-domain", ""}, exitUsageError},
		{"missing record", []string{"-domain", "missing.test"}, exitLookupError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command := &ListCmd{}
			set := flag.NewFlagSet("list", flag.ContinueOnError)
			set.SetOutput(os.Stderr)
			command.SetFlags(set)
			if err := set.Parse(tt.args); err != nil {
				t.Fatalf("cannot parse %v: %v", tt.args, err)
			}
			if got := command.Execute(context.Background(), set); got != tt.want {
				t.Errorf("exit status = %d; want %d", got, tt.want)
			}
		})
	}
}
