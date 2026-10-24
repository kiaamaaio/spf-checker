// Package validation は、コマンドライン引数として受け取ったドメイン名や
// IP アドレスの形式検査を提供する。
package validation

import "errors"

// 入力値の検査で返すエラー。呼び出し側が errors.Is で判別できるよう、
// センチネルエラーとして公開している。
var (
	// ErrInvalidIpAddress は IP アドレスとして解釈できない文字列を
	// 受け取ったことを表す。
	ErrInvalidIpAddress = errors.New("invalid ip address")
	// ErrInvalidDnsRecordName は DNS レコード名として不正な文字列を
	// 受け取ったことを表す。
	ErrInvalidDnsRecordName = errors.New("invalid dns record name")
)
