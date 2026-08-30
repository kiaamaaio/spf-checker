package output

import (
	"strings"
	"testing"

	"spf-checker/internal/dns"
)

func TestFormatSpfRecordAligned(t *testing.T) {
	record := dns.ParseSpfRecord("v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.example.com a mx bogus redirect=example.org ~all")

	got := FormatSpfRecordAligned(record)
	lines := strings.Split(got, "\n")

	want := []string{
		"Version         : v=spf1",
		"IPv4            : ip4:192.0.2.0/24",
		"IPv6            : ip6:2001:db8::/32",
		"Include         : include:_spf.example.com",
		"A               : a",
		"MX              : mx",
		"All Mechanism   : ~all",
		"Redirect        : redirect=example.org",
		"Unknown         : bogus",
	}

	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%s", len(lines), len(want), got)
	}
	for i, wantLine := range want {
		if lines[i] != wantLine {
			t.Errorf("line %d = %q; want %q", i, lines[i], wantLine)
		}
	}
}

func TestFormatSpfRecordAlignedEmpty(t *testing.T) {
	if got := FormatSpfRecordAligned(dns.ParseSpfRecord("")); got != "" {
		t.Errorf("want empty output, got %q", got)
	}
}
