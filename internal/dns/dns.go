package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
)

const spfVersion = "v=spf1"

// Resolver is the subset of *net.Resolver that spf evaluation needs.
// It is an interface so that tests can supply a fake resolver.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// DefaultResolver is the resolver used when none is supplied.
var DefaultResolver Resolver = net.DefaultResolver

type Domain struct {
	name     string
	resolver Resolver
}

func NewDomain(name string) *Domain {
	return NewDomainWithResolver(name, DefaultResolver)
}

func NewDomainWithResolver(name string, resolver Resolver) *Domain {
	return &Domain{name: name, resolver: resolver}
}

func (d *Domain) Name() string {
	return d.name
}

func (d *Domain) Resolver() Resolver {
	return d.resolver
}

// GetSpfRecord returns the single spf TXT record published for the domain.
func (d *Domain) GetSpfRecord(ctx context.Context) (string, error) {
	return lookupSpfRecord(ctx, d.resolver, d.name)
}

func lookupSpfRecord(ctx context.Context, resolver Resolver, name string) (string, error) {
	txtRecords, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		return "", fmt.Errorf("%w (detail: %v)", ErrNoTxtRecord, err)
	}

	var found string
	for _, txtRecord := range txtRecords {
		if !isSpfRecord(txtRecord) {
			continue
		}
		// RFC 7208 4.5: more than one spf record is a permanent error.
		if found != "" {
			return "", ErrMultipleSpfRecords
		}
		found = strings.TrimSpace(txtRecord)
	}

	if found == "" {
		return "", ErrNoSpfRecord
	}
	return found, nil
}

// isSpfRecord reports whether a TXT record starts with the spf version token.
// The comparison is case insensitive (RFC 7208 4.5) and the token must not be
// a prefix of a longer word, so that "v=spf10" is not treated as spf1.
func isSpfRecord(txtRecord string) bool {
	record := strings.TrimSpace(txtRecord)
	if len(record) < len(spfVersion) {
		return false
	}
	if !strings.EqualFold(record[:len(spfVersion)], spfVersion) {
		return false
	}
	return len(record) == len(spfVersion) || record[len(spfVersion)] == ' '
}
