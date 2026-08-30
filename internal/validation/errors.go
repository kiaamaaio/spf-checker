package validation

import "errors"

var (
	ErrInvalidIpAddress     = errors.New("invalid ip address")
	ErrInvalidDnsRecordName = errors.New("invalid dns record name")
)
