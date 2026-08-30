// Package dns は、ドメインからの SPF レコードの取得と、RFC 7208 に沿った
// レコードの解析・評価を提供する。
package dns

import "errors"

// レコードの取得と評価で返すエラー。呼び出し側が errors.Is で判別できるよう、
// センチネルエラーとして公開している。
var (
	// ErrNoTxtRecord はドメインの TXT レコードを引けなかったことを表す。
	// 名前解決自体の失敗もここに含まれるため、詳細は %w でラップした
	// エラーを参照する。
	ErrNoTxtRecord = errors.New("txt record not found")
	// ErrNoSpfRecord は TXT レコードは引けたが、その中に SPF レコードが
	// 含まれていなかったことを表す。
	ErrNoSpfRecord = errors.New("spf record not found")
	// ErrMultipleSpfRecords は SPF レコードが複数公開されていることを表す。
	// RFC 7208 4.5 では permerror として扱う。
	ErrMultipleSpfRecords = errors.New("multiple spf records found")
	// ErrInvalidMechanism は mechanism として解釈できない項目を表す。
	ErrInvalidMechanism = errors.New("invalid spf mechanism")
	// ErrTooManyDnsLookups は DNS ルックアップ数が上限を超えたことを表す。
	// RFC 7208 4.6.4 では permerror として扱う。
	ErrTooManyDnsLookups = errors.New("exceeded the maximum number of dns lookups")
)
