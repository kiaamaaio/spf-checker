package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/subcommands"

	"spf-checker/internal/dns"
	"spf-checker/internal/validation"
)

// CheckCmd は IP アドレスが SPF レコードで認可されているかを判定する
// check サブコマンドである。
type CheckCmd struct {
	domain string
	ipAddr string
	// direct が true の場合、対象ドメインのレコード内だけで評価する。
	direct  bool
	timeout time.Duration
}

// Name はサブコマンド名を返す。
func (c *CheckCmd) Name() string {
	return "check"
}

// Synopsis はヘルプ一覧に表示する1行の説明を返す。
func (c *CheckCmd) Synopsis() string {
	return "check if an ip address is in the spf record"
}

// Usage は "help check" で表示する使い方を返す。
func (c *CheckCmd) Usage() string {
	return `check [-direct] -domain <domain> -ipaddr <ip address>:
	Check if an ip address is authorized by the spf record.

	include, redirect, a and mx terms are followed by default. Use -direct to
	evaluate only the record of the domain itself, which answers "is this ip
	listed here" rather than "is this ip authorized".

	Exit status:
	  0  pass         the ip is authorized
	  1  not pass     fail, softfail, neutral or none
	  2  usage error  invalid domain or ip address
	  3  lookup error the record could not be retrieved or evaluated
`
}

// SetFlags はこのサブコマンドのオプションを登録する。
func (c *CheckCmd) SetFlags(set *flag.FlagSet) {
	set.StringVar(&c.domain, "domain", "", "domain to check")
	set.StringVar(&c.ipAddr, "ipaddr", "", "ip address to check")
	set.BoolVar(&c.direct, "direct", false, "evaluate only this domain's own record, without following include, redirect, a or mx")
	set.DurationVar(&c.timeout, "timeout", defaultTimeout, "dns lookup timeout (0 for no limit)")
}

// Execute は SPF レコードを取得して評価し、判定結果を表示する。
// 判定結果に応じた終了ステータスを返す。意味は Usage を参照。
func (c *CheckCmd) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	// 余分な位置引数は、オプションの綴り違いなど指定の誤りであることが多い。
	// 黙って無視すると誤った条件で判定したまま気づけないため、エラーとする。
	if f.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected arguments: %v\n", f.Args())
		return exitUsageError
	}

	// IP アドレスの検査を先に行う。指定が誤っているだけで DNS へ
	// 問い合わせても無駄になるためである。
	parsedIP, err := validation.ParseIP(c.ipAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v: %q\n", err, c.ipAddr)
		return exitUsageError
	}

	ctx, cancel := contextWithTimeout(ctx, c.timeout)
	defer cancel()

	txtRecord, status, ok := fetchSpfRecord(ctx, os.Stderr, c.domain)
	if !ok {
		return status
	}

	evaluation := dns.NewEvaluator(dns.DefaultResolver, !c.direct).Check(ctx, c.domain, txtRecord, parsedIP)
	printEvaluation(txtRecord, c.domain, c.ipAddr, evaluation)

	switch evaluation.Result {
	case dns.ResultPass:
		return subcommands.ExitSuccess
	case dns.ResultPermError, dns.ResultTempError:
		return exitLookupError
	default:
		return exitNotAuthorized
	}
}

// printEvaluation は判定結果を標準出力へ、警告を標準エラー出力へ書く。
//
// 判定の根拠となった mechanism とその出典ドメインも表示する。include を
// 辿った結果の pass なのか、自ドメインのレコードによる pass なのかは
// 利用者にとって意味が違うためである。
func printEvaluation(txtRecord, domain, ipAddr string, evaluation *dns.Evaluation) {
	fmt.Printf("%-15s : %s\n", "Domain", domain)
	fmt.Printf("%-15s : %s\n", "IP", ipAddr)
	fmt.Printf("%-15s : %s\n", "Record", txtRecord)
	fmt.Printf("%-15s : %s\n", "Result", evaluation.Result)
	if evaluation.MatchedBy != "" {
		fmt.Printf("%-15s : %s (in the record of %s)\n", "Matched", evaluation.MatchedBy, evaluation.MatchedAt)
	}
	fmt.Printf("%-15s : %d\n", "DNS Lookups", evaluation.Lookups)

	for _, warning := range evaluation.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}
}
