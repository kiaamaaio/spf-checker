package validation

import (
	"regexp"
	"strings"
)

const (
	// domainMaxLength は名前全体の最大長 (RFC 1035 2.3.4)。
	domainMaxLength = 253
	// domainLabelMaxLength はラベル1つあたりの最大長 (RFC 1035 2.3.4)。
	domainLabelMaxLength = 63
)

// dnsLabelRegex は1ラベル分の文字種を表す。ハイフンで開始・終了できない
// 一方、SPF で使う _spf のようなアンダースコア始まりのラベルは許可する。
var dnsLabelRegex = regexp.MustCompile(`^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?$`)

// ValidateDnsRecordName は name が DNS レコード名として妥当かを検査し、
// 不正な場合は ErrInvalidDnsRecordName を返す。
//
// 名前全体の長さ、ラベルごとの長さ、使用できる文字種を検査する。
// 末尾のドット (FQDN 表記) は1つだけ許容する。
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
