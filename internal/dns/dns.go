package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// spfVersion は SPF レコードの先頭に置かれるバージョン文字列 (RFC 7208 4.5)。
const spfVersion = "v=spf1"

// Resolver は SPF の評価に必要な名前解決だけを切り出したインターフェースである。
// *net.Resolver がそのまま満たす。テストから偽の応答を差し込めるように、
// 具象型ではなくインターフェースを介して利用する。
type Resolver interface {
	// LookupTXT は name の TXT レコードを返す。
	LookupTXT(ctx context.Context, name string) ([]string, error)
	// LookupIP は host のアドレスを返す。network には "ip", "ip4", "ip6" を指定する。
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	// LookupMX は name の MX レコードを優先度順に返す。
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// DefaultResolver は Resolver を明示しない場合に使われる名前解決器である。
// テストから差し替えられるように変数にしている。
var DefaultResolver Resolver = net.DefaultResolver

// Domain は SPF レコードの取得対象となるドメインを表す。
type Domain struct {
	name     string
	resolver Resolver
}

// NewDomain は DefaultResolver を使う Domain を生成する。
func NewDomain(name string) *Domain {
	return NewDomainWithResolver(name, DefaultResolver)
}

// NewDomainWithResolver は名前解決器を指定して Domain を生成する。
func NewDomainWithResolver(name string, resolver Resolver) *Domain {
	return &Domain{name: name, resolver: resolver}
}

// Name はドメイン名を返す。
func (d *Domain) Name() string {
	return d.name
}

// Resolver はこの Domain が使う名前解決器を返す。
func (d *Domain) Resolver() Resolver {
	return d.resolver
}

// GetSpfRecord はドメインに公開されている SPF レコードを返す。
//
// TXT レコードを引けなかった場合は ErrNoTxtRecord、TXT レコードはあるが
// SPF レコードが含まれない場合は ErrNoSpfRecord、SPF レコードが複数ある
// 場合は ErrMultipleSpfRecords を返す。
func (d *Domain) GetSpfRecord(ctx context.Context) (string, error) {
	return lookupSpfRecord(ctx, d.resolver, d.name)
}

// lookupSpfRecord は name の TXT レコードから SPF レコードを1つ取り出す。
// 評価中の再帰的な取得からも使うため、Domain を介さない関数にしている。
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
		// RFC 7208 4.5 では SPF レコードが複数ある場合を permerror とする。
		// どれか1つを選ぶと結果が不定になるため、エラーとして返す。
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

// isSpfRecord は TXT レコードが SPF レコードかどうかを判定する。
//
// RFC 7208 4.5 に従いバージョン文字列は大文字小文字を区別せずに比較する。
// また "v=spf10" のような別の語の一部に一致しないよう、バージョン文字列の
// 直後が行末か空白であることを確認する。
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
