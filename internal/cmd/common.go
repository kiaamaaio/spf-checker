// Package cmd は spf-checker のサブコマンドを提供する。
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/subcommands"

	"spf-checker/internal/dns"
	"spf-checker/internal/validation"
)

// defaultTimeout は DNS 問い合わせの既定のタイムアウトである。
// 再帰的な評価では最大10回問い合わせるため、1回分ではなく評価全体に
// 効かせている。
const defaultTimeout = 10 * time.Second

// 終了ステータス。subcommands は成功・失敗・引数エラーしか定義していないため、
// スクリプトから結果を判別できるよう残りをここで定義している。
const (
	// exitNotAuthorized は pass 以外の判定を表す。
	exitNotAuthorized subcommands.ExitStatus = 1
	// exitUsageError はドメイン名や IP アドレスが不正であることを表す。
	exitUsageError subcommands.ExitStatus = 2
	// exitLookupError はレコードを取得・評価できなかったことを表す。
	exitLookupError subcommands.ExitStatus = 3
)

// fetchSpfRecord はドメイン名を検査し、その SPF レコードを取得する。
// list と check で共通の前処理をまとめたものである。
//
// 取得できなかった場合はその内容を errOut に書き、ok に false を返す。
// 返す終了ステータスは ok が false のときだけ意味を持つ。
func fetchSpfRecord(ctx context.Context, errOut io.Writer, domain string) (string, subcommands.ExitStatus, bool) {
	if err := validation.ValidateDnsRecordName(domain); err != nil {
		fmt.Fprintf(errOut, "%v: %q\n", err, domain)
		return "", exitUsageError, false
	}

	record, err := dns.NewDomain(domain).GetSpfRecord(ctx)
	switch {
	case errors.Is(err, dns.ErrNoTxtRecord), errors.Is(err, dns.ErrNoSpfRecord), errors.Is(err, dns.ErrMultipleSpfRecords):
		fmt.Fprintf(errOut, "%v (domain: %s)\n", err, domain)
		return "", exitLookupError, false
	case err != nil:
		fmt.Fprintf(errOut, "unexpected error: %v (domain: %s)\n", err, domain)
		return "", exitLookupError, false
	}

	return record, subcommands.ExitSuccess, true
}

// contextWithTimeout は timeout を適用した context を返す。
// timeout が 0 以下の場合はタイムアウトを設けない。
func contextWithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}
