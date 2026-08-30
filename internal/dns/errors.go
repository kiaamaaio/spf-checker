package dns

import "errors"

var (
	ErrNoTxtRecord        = errors.New("txt record not found")
	ErrNoSpfRecord        = errors.New("spf record not found")
	ErrMultipleSpfRecords = errors.New("multiple spf records found")
	ErrInvalidMechanism   = errors.New("invalid spf mechanism")
	ErrTooManyDnsLookups  = errors.New("exceeded the maximum number of dns lookups")
)
