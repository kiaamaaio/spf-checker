package cmd

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/google/subcommands"

	"spf-checker/internal/dns"
)

// stubResolver は TXT レコードだけを固定で返す Resolver である。
// サブコマンドの終了ステータスの検証が目的なので、アドレスと MX は
// 常に失敗させ、ネットワークに依存しないようにしている。
type stubResolver struct {
	txt map[string][]string
}

// LookupTXT は登録済みの TXT レコードを返す。
func (s stubResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	records, ok := s.txt[name]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", name)
	}
	return records, nil
}

// LookupIP は常に失敗する。このテストではアドレス解決を伴う
// mechanism を対象にしていない。
func (s stubResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	return nil, fmt.Errorf("no such host: %s", host)
}

// LookupMX は常に失敗する。このテストでは MX を対象にしていない。
func (s stubResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return nil, fmt.Errorf("no such host: %s", name)
}

// withStubResolver はサブコマンドの参照する Resolver を差し替え、
// テストの間だけ標準出力と標準エラー出力を捨てる。
// いずれも t.Cleanup で元に戻す。
func withStubResolver(t *testing.T, txt map[string][]string) {
	t.Helper()

	previousResolver := dns.DefaultResolver
	dns.DefaultResolver = stubResolver{txt: txt}

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("cannot open %s: %v", os.DevNull, err)
	}
	previousStdout, previousStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = devNull, devNull

	t.Cleanup(func() {
		dns.DefaultResolver = previousResolver
		os.Stdout, os.Stderr = previousStdout, previousStderr
		devNull.Close()
	})
}

// runCheck は check サブコマンドを args で実行し、終了ステータスを返す。
func runCheck(t *testing.T, args ...string) subcommands.ExitStatus {
	t.Helper()

	command := &CheckCmd{}
	set := flag.NewFlagSet("check", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	command.SetFlags(set)
	if err := set.Parse(args); err != nil {
		t.Fatalf("cannot parse %v: %v", args, err)
	}
	return command.Execute(context.Background(), set)
}

// TestCheckExitStatus は、判定結果と入力の誤りが終了ステータスに
// 正しく対応することを検証する。修正前はどの経路でも 0 を返しており、
// スクリプトから結果を判別できなかった。
func TestCheckExitStatus(t *testing.T) {
	withStubResolver(t, map[string][]string{
		"example.test": {"v=spf1 ip4:192.0.2.0/24 -all"},
		"notxt.test":   nil,
		"nospf.test":   {"example-domain-verification=abc"},
	})

	tests := []struct {
		name string
		args []string
		want subcommands.ExitStatus
	}{
		{
			name: "authorized ip",
			args: []string{"-domain", "example.test", "-ipaddr", "192.0.2.1"},
			want: subcommands.ExitSuccess,
		},
		{
			name: "unauthorized ip",
			args: []string{"-domain", "example.test", "-ipaddr", "203.0.113.1"},
			want: exitNotAuthorized,
		},
		{
			name: "invalid ip address",
			args: []string{"-domain", "example.test", "-ipaddr", "999.999.999.999"},
			want: exitUsageError,
		},
		{
			name: "missing ip address",
			args: []string{"-domain", "example.test"},
			want: exitUsageError,
		},
		{
			name: "invalid domain",
			args: []string{"-domain", "exam$ple.test", "-ipaddr", "192.0.2.1"},
			want: exitUsageError,
		},
		{
			name: "unexpected positional argument",
			args: []string{"-domain", "example.test", "-ipaddr", "192.0.2.1", "extra"},
			want: exitUsageError,
		},
		{
			name: "domain without a txt record",
			args: []string{"-domain", "missing.test", "-ipaddr", "192.0.2.1"},
			want: exitLookupError,
		},
		{
			name: "domain without an spf record",
			args: []string{"-domain", "nospf.test", "-ipaddr", "192.0.2.1"},
			want: exitLookupError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runCheck(t, tt.args...); got != tt.want {
				t.Errorf("exit status = %d; want %d", got, tt.want)
			}
		})
	}
}

// TestCheckFollowsIncludesByDefault は、オプションを指定しない場合に
// include を辿ること、および -direct を指定すると辿らないことを検証する。
func TestCheckFollowsIncludesByDefault(t *testing.T) {
	withStubResolver(t, map[string][]string{
		"example.test":      {"v=spf1 include:_spf.example.test -all"},
		"_spf.example.test": {"v=spf1 ip4:192.0.2.0/24 -all"},
	})

	args := []string{"-domain", "example.test", "-ipaddr", "192.0.2.1"}

	if got := runCheck(t, args...); got != subcommands.ExitSuccess {
		t.Errorf("exit status = %d; want %d (includes must be followed by default)", got, subcommands.ExitSuccess)
	}

	// -direct stays inside the record of the domain itself, so the same ip is
	// no longer authorized.
	if got := runCheck(t, append(args, "-direct")...); got != exitNotAuthorized {
		t.Errorf("exit status with -direct = %d; want %d", got, exitNotAuthorized)
	}
}

// TestListExitStatus は list サブコマンドの終了ステータスを検証する。
func TestListExitStatus(t *testing.T) {
	withStubResolver(t, map[string][]string{
		"example.test": {"v=spf1 ip4:192.0.2.0/24 -all"},
	})

	tests := []struct {
		name string
		args []string
		want subcommands.ExitStatus
	}{
		{"existing record", []string{"-domain", "example.test"}, subcommands.ExitSuccess},
		{"empty domain", []string{"-domain", ""}, exitUsageError},
		{"missing record", []string{"-domain", "missing.test"}, exitLookupError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command := &ListCmd{}
			set := flag.NewFlagSet("list", flag.ContinueOnError)
			set.SetOutput(os.Stderr)
			command.SetFlags(set)
			if err := set.Parse(tt.args); err != nil {
				t.Fatalf("cannot parse %v: %v", tt.args, err)
			}
			if got := command.Execute(context.Background(), set); got != tt.want {
				t.Errorf("exit status = %d; want %d", got, tt.want)
			}
		})
	}
}
