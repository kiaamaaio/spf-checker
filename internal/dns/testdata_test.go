package dns

import (
	"context"
	"fmt"
	"net"
)

// fakeResolver は固定の応答を返す Resolver である。ネットワークに
// 依存せず、また実在するドメインのレコード変更に影響されずに
// 評価をテストするために使う。
type fakeResolver struct {
	txt  map[string][]string
	ips  map[string][]net.IP
	mx   map[string][]*net.MX
	logs []string
}

// newFakeResolver は応答を1件も持たない fakeResolver を生成する。
// 応答は txt, ips, mx へ直接登録する。
func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		txt: map[string][]string{},
		ips: map[string][]net.IP{},
		mx:  map[string][]*net.MX{},
	}
}

// LookupTXT は登録済みの TXT レコードを返す。未登録の名前は
// 名前解決の失敗として扱う。
func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.logs = append(f.logs, "txt:"+name)
	records, ok := f.txt[name]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", name)
	}
	return records, nil
}

// LookupIP は登録済みのアドレスを返す。未登録のホストは名前解決の
// 失敗として扱う。network は区別しない。
func (f *fakeResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	f.logs = append(f.logs, "ip:"+host)
	addrs, ok := f.ips[host]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", host)
	}
	return addrs, nil
}

// LookupMX は登録済みの MX レコードを返す。未登録の名前は名前解決の
// 失敗として扱う。
func (f *fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	f.logs = append(f.logs, "mx:"+name)
	records, ok := f.mx[name]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", name)
	}
	return records, nil
}

// ips は文字列表記のアドレスを net.IP へまとめて変換する。
// fakeResolver への登録を簡潔に書くための補助関数である。
func ips(addrs ...string) []net.IP {
	parsed := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		parsed = append(parsed, net.ParseIP(addr))
	}
	return parsed
}
