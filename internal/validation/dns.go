package validation

import (
	"regexp"
	"strings"
)

var dnsLabelRegex = regexp.MustCompile(`^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?$`)

func IsValidDnsRecordName(name string) (bool, error) {
	var domainMaxLength = 253
	var domainLabelMaxLength = 63

	if name == "" || len(name) > domainMaxLength {
		return false, ErrorInvalidDnsRecordName
	}

	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > domainLabelMaxLength {
			return false, ErrorInvalidDnsRecordName
		}
		if !dnsLabelRegex.MatchString(label) {
			return false, ErrorInvalidDnsRecordName
		}
	}
	return true, nil
}
