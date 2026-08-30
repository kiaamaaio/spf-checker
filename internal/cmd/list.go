package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/subcommands"

	"spf-checker/internal/dns"
	"spf-checker/internal/output"
)

// ListCmd はドメインの SPF レコードを整形して表示する list サブコマンドである。
type ListCmd struct {
	domain  string
	timeout time.Duration
}

// Name はサブコマンド名を返す。
func (l *ListCmd) Name() string {
	return "list"
}

// Synopsis はヘルプ一覧に表示する1行の説明を返す。
func (l *ListCmd) Synopsis() string {
	return "list spf records for the domain"
}

// Usage は "help list" で表示する使い方を返す。
func (l *ListCmd) Usage() string {
	return `list -domain <domain>:
	List spf records for the domain.
`
}

// SetFlags はこのサブコマンドのオプションを登録する。
func (l *ListCmd) SetFlags(set *flag.FlagSet) {
	set.StringVar(&l.domain, "domain", "", "domain to check")
	set.DurationVar(&l.timeout, "timeout", defaultTimeout, "dns lookup timeout (0 for no limit)")
}

// Execute はドメインの SPF レコードを取得し、1項目1行に整形して表示する。
// 終了ステータスの意味は CheckCmd.Usage を参照。
func (l *ListCmd) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	// 余分な位置引数は、オプションの綴り違いなど指定の誤りであることが多い。
	// 黙って無視すると誤ったドメインを調べたまま気づけないため、エラーとする。
	if f.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected arguments: %v\n", f.Args())
		return exitUsageError
	}

	ctx, cancel := contextWithTimeout(ctx, l.timeout)
	defer cancel()

	txtRecord, status, ok := fetchSpfRecord(ctx, os.Stderr, l.domain)
	if !ok {
		return status
	}

	fmt.Println(output.FormatSpfRecordAligned(dns.ParseSpfRecord(txtRecord)))

	return subcommands.ExitSuccess
}
