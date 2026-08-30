package validation

import (
	"regexp"
	"strings"
)

const (
	domainMaxLength      = 253
	domainLabelMaxLength = 63
)

var dnsLabelRegex = regexp.MustCompile(`^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?$`)

// ValidateDnsRecordName reports whether name is a syntactically valid DNS
// record name. A single trailing dot (a fully qualified name) is accepted.
func ValidateDnsRecordName(name string) error {
	name = strings.TrimSuffix(name, ".")

	if name == "" || len(name) > domainMaxLength {
		return ErrInvalidDnsRecordName
	}

	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > domainLabelMaxLength {
			return ErrInvalidDnsRecordName
		}
		if !dnsLabelRegex.MatchString(label) {
			return ErrInvalidDnsRecordName
		}
	}
	return nil
}
