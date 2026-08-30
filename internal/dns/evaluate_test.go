package dns

import (
	"context"
	"net"
	"strings"
	"testing"
)

func evaluate(t *testing.T, resolver *fakeResolver, domain, ipaddr string, recursive bool) *Evaluation {
	t.Helper()
	record, ok := resolver.txt[domain]
	if !ok || len(record) == 0 {
		t.Fatalf("no txt record configured for %s", domain)
	}
	return NewEvaluator(resolver, recursive).
		Check(context.Background(), domain, record[0], net.ParseIP(ipaddr))
}

func TestCheckIPMechanisms(t *testing.T) {
	tests := []struct {
		name   string
		record string
		ipaddr string
		want   Result
	}{
		{"ipv4 inside the range", "v=spf1 ip4:192.0.2.0/24 -all", "192.0.2.1", ResultPass},
		{"ipv4 outside the range", "v=spf1 ip4:192.0.2.0/24 -all", "203.0.113.5", ResultFail},
		{"ipv6 inside the range", "v=spf1 ip6:2001:db8::/32 -all", "2001:db8::1", ResultPass},

		// Regression: a prefix length is optional (RFC 7208 5.6). A bare
		// address used to make the whole check fail.
		{"bare ipv4 address matches", "v=spf1 ip4:192.0.2.1 -all", "192.0.2.1", ResultPass},
		{"bare ipv4 address does not match", "v=spf1 ip4:192.0.2.1 -all", "192.0.2.2", ResultFail},
		{"bare ipv6 address matches", "v=spf1 ip6:2001:db8::1 -all", "2001:db8::1", ResultPass},
		{
			"a bare address does not hide later terms",
			"v=spf1 ip4:192.0.2.1 ip4:198.51.100.0/24 -all",
			"198.51.100.5",
			ResultPass,
		},

		// Regression: qualifiers used to be part of the mechanism name and so
		// never matched.
		{"explicit pass qualifier", "v=spf1 +ip4:192.0.2.0/24 -all", "192.0.2.5", ResultPass},
		{"fail qualifier", "v=spf1 -ip4:192.0.2.0/24 +all", "192.0.2.5", ResultFail},
		{"softfail qualifier", "v=spf1 ~ip4:192.0.2.0/24 +all", "192.0.2.5", ResultSoftFail},
		{"neutral qualifier", "v=spf1 ?ip4:192.0.2.0/24 +all", "192.0.2.5", ResultNeutral},

		// Regression: mechanism names are case insensitive.
		{"uppercase mechanism name", "v=spf1 IP4:192.0.2.0/24 -all", "192.0.2.5", ResultPass},

		// An ip4 term must never match an ipv6 query and vice versa.
		{"ipv4 query against an ip6 term", "v=spf1 ip6:2001:db8::/32 -all", "192.0.2.5", ResultFail},
		{"ipv6 query against an ip4 term", "v=spf1 ip4:0.0.0.0/0 -all", "2001:db8::1", ResultFail},

		{"first match wins", "v=spf1 -ip4:192.0.2.5 ip4:192.0.2.0/24 -all", "192.0.2.5", ResultFail},
		{"no all term defaults to neutral", "v=spf1 ip4:192.0.2.0/24", "203.0.113.5", ResultNeutral},
		{"malformed term is skipped", "v=spf1 ip4:not-an-ip ip4:192.0.2.0/24 -all", "192.0.2.5", ResultPass},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := newFakeResolver()
			resolver.txt["example.test"] = []string{tt.record}

			got := evaluate(t, resolver, "example.test", tt.ipaddr, true)

			if got.Result != tt.want {
				t.Errorf("result = %s; want %s (warnings: %v)", got.Result, tt.want, got.Warnings)
			}
		})
	}
}

func TestCheckInclude(t *testing.T) {
	resolver := newFakeResolver()
	resolver.txt["example.test"] = []string{"v=spf1 include:_spf.example.test -all"}
	resolver.txt["_spf.example.test"] = []string{"v=spf1 include:deep.example.test ip4:192.0.2.0/24 -all"}
	resolver.txt["deep.example.test"] = []string{"v=spf1 ip4:198.51.100.0/24 -all"}

	t.Run("matches through a nested include", func(t *testing.T) {
		got := evaluate(t, resolver, "example.test", "198.51.100.7", true)
		if got.Result != ResultPass {
			t.Fatalf("result = %s; want pass (warnings: %v)", got.Result, got.Warnings)
		}
		if got.MatchedAt != "deep.example.test" {
			t.Errorf("matched at %q; want deep.example.test", got.MatchedAt)
		}
		if got.Lookups != 2 {
			t.Errorf("lookups = %d; want 2", got.Lookups)
		}
	})

	t.Run("a failing include does not decide the result", func(t *testing.T) {
		// -all inside the include must not turn into a fail for the parent.
		got := evaluate(t, resolver, "example.test", "203.0.113.9", true)
		if got.Result != ResultFail {
			t.Fatalf("result = %s; want fail", got.Result)
		}
		if got.MatchedAt != "example.test" || got.MatchedBy != "-all" {
			t.Errorf("matched %q at %q; want -all at example.test", got.MatchedBy, got.MatchedAt)
		}
	})

	t.Run("includes are not followed without the recursive flag", func(t *testing.T) {
		got := evaluate(t, resolver, "example.test", "198.51.100.7", false)
		if got.Result == ResultPass {
			t.Fatalf("result = pass; want a non-pass result when includes are skipped")
		}
		if got.Lookups != 0 {
			t.Errorf("lookups = %d; want 0", got.Lookups)
		}
		if !hasWarning(got.Warnings, "-recursive") {
			t.Errorf("want a warning mentioning -recursive, got %v", got.Warnings)
		}
	})
}

func TestCheckIncludeLoop(t *testing.T) {
	resolver := newFakeResolver()
	resolver.txt["a.test"] = []string{"v=spf1 include:b.test -all"}
	resolver.txt["b.test"] = []string{"v=spf1 include:a.test -all"}

	got := evaluate(t, resolver, "a.test", "192.0.2.1", true)

	if got.Result != ResultFail {
		t.Errorf("result = %s; want fail", got.Result)
	}
	if !hasWarning(got.Warnings, "loop") {
		t.Errorf("want a loop warning, got %v", got.Warnings)
	}
}

func TestCheckDnsLookupLimit(t *testing.T) {
	resolver := newFakeResolver()
	// A chain of 12 includes, one lookup each, exceeds the limit of 10.
	for i := 0; i < 12; i++ {
		resolver.txt[chainDomain(i)] = []string{"v=spf1 include:" + chainDomain(i+1) + " -all"}
	}
	resolver.txt[chainDomain(12)] = []string{"v=spf1 ip4:192.0.2.0/24 -all"}

	got := evaluate(t, resolver, chainDomain(0), "192.0.2.1", true)

	if got.Result != ResultPermError {
		t.Errorf("result = %s; want permerror", got.Result)
	}
	if got.Lookups != maxDnsLookups+1 {
		t.Errorf("lookups = %d; want %d", got.Lookups, maxDnsLookups+1)
	}
}

func TestCheckRedirect(t *testing.T) {
	resolver := newFakeResolver()
	resolver.txt["example.test"] = []string{"v=spf1 ip4:192.0.2.0/24 redirect=_spf.example.test"}
	resolver.txt["_spf.example.test"] = []string{"v=spf1 ip4:198.51.100.0/24 -all"}

	t.Run("redirect is followed when no mechanism matches", func(t *testing.T) {
		got := evaluate(t, resolver, "example.test", "198.51.100.7", true)
		if got.Result != ResultPass {
			t.Errorf("result = %s; want pass (warnings: %v)", got.Result, got.Warnings)
		}
	})

	t.Run("redirect is skipped when a mechanism matches", func(t *testing.T) {
		got := evaluate(t, resolver, "example.test", "192.0.2.7", true)
		if got.Result != ResultPass || got.MatchedAt != "example.test" {
			t.Errorf("matched %q at %q; want a match in the root record", got.MatchedBy, got.MatchedAt)
		}
	})
}

func TestCheckAAndMXMechanisms(t *testing.T) {
	resolver := newFakeResolver()
	resolver.txt["example.test"] = []string{"v=spf1 a mx a:web.example.test/24 -all"}
	resolver.ips["example.test"] = ips("192.0.2.10")
	resolver.ips["web.example.test"] = ips("203.0.113.1")
	resolver.mx["example.test"] = []*net.MX{{Host: "mail.example.test", Pref: 10}}
	resolver.ips["mail.example.test"] = ips("198.51.100.20", "2001:db8::20")

	tests := []struct {
		name   string
		ipaddr string
		want   Result
	}{
		{"a mechanism matches the domain address", "192.0.2.10", ResultPass},
		{"mx mechanism matches an mx host address", "198.51.100.20", ResultPass},
		{"mx mechanism matches an ipv6 mx host address", "2001:db8::20", ResultPass},
		{"a mechanism honours the prefix length", "203.0.113.99", ResultPass},
		{"unrelated address does not match", "192.0.2.11", ResultFail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluate(t, resolver, "example.test", tt.ipaddr, true)
			if got.Result != tt.want {
				t.Errorf("result = %s; want %s (warnings: %v)", got.Result, tt.want, got.Warnings)
			}
		})
	}
}

func TestCheckUnsupportedTermsAreReported(t *testing.T) {
	resolver := newFakeResolver()
	resolver.txt["example.test"] = []string{"v=spf1 ptr include:%{d}.example.test -all"}

	got := evaluate(t, resolver, "example.test", "192.0.2.1", true)

	if got.Result != ResultFail {
		t.Errorf("result = %s; want fail", got.Result)
	}
	if !hasWarning(got.Warnings, "ptr") {
		t.Errorf("want a ptr warning, got %v", got.Warnings)
	}
	if !hasWarning(got.Warnings, "macro") {
		t.Errorf("want a macro warning, got %v", got.Warnings)
	}
}

func chainDomain(i int) string {
	return "n" + string(rune('a'+i)) + ".test"
}

func hasWarning(warnings []string, substring string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, substring) {
			return true
		}
	}
	return false
}

func TestCheckInconclusiveWithoutRecursion(t *testing.T) {
	resolver := newFakeResolver()
	resolver.txt["example.test"] = []string{"v=spf1 include:_spf.example.test -all"}
	resolver.txt["_spf.example.test"] = []string{"v=spf1 ip4:192.0.2.0/24 -all"}

	t.Run("skipped terms make an all verdict inconclusive", func(t *testing.T) {
		got := evaluate(t, resolver, "example.test", "192.0.2.1", false)
		if !hasWarning(got.Warnings, "inconclusive") {
			t.Errorf("want an inconclusive warning, got %v", got.Warnings)
		}
	})

	t.Run("a direct match is never inconclusive", func(t *testing.T) {
		resolver.txt["direct.test"] = []string{"v=spf1 include:_spf.example.test ip4:192.0.2.0/24 -all"}
		got := evaluate(t, resolver, "direct.test", "192.0.2.1", false)
		if got.Result != ResultPass {
			t.Fatalf("result = %s; want pass", got.Result)
		}
		if hasWarning(got.Warnings, "inconclusive") {
			t.Errorf("unexpected inconclusive warning: %v", got.Warnings)
		}
	})

	t.Run("nothing is skipped when the record needs no lookups", func(t *testing.T) {
		resolver.txt["flat.test"] = []string{"v=spf1 ip4:192.0.2.0/24 -all"}
		got := evaluate(t, resolver, "flat.test", "203.0.113.1", false)
		if got.Result != ResultFail {
			t.Fatalf("result = %s; want fail", got.Result)
		}
		if len(got.Warnings) != 0 {
			t.Errorf("unexpected warnings: %v", got.Warnings)
		}
	})
}
