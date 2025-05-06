package dns

import "errors"

var ErrorNoTxtRecord = errors.New("txt record not found")
var ErrorNoSpfRecord = errors.New("spf record not found")
