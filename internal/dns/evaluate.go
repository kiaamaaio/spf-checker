package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Result は SPF レコードを IP アドレスに対して評価した結果である
// (RFC 7208 2.6)。
type Result string

// 評価結果の一覧。
const (
	// ResultPass は認可されていることを表す。
	ResultPass Result = "pass"
	// ResultFail は明示的に拒否されていることを表す ("-all" など)。
	ResultFail Result = "fail"
	// ResultSoftFail は認可されていないが拒否までは求めないことを表す ("~all")。
	ResultSoftFail Result = "softfail"
	// ResultNeutral は送信元について判断しないことを表す ("?all"、
	// または一致する mechanism も all もない場合)。
	ResultNeutral Result = "neutral"
	// ResultNone は SPF レコードが公開されていないことを表す。
	ResultNone Result = "none"
	// ResultPermError はレコードの誤りやルックアップ上限の超過など、
	// 再試行しても解消しないエラーを表す。
	ResultPermError Result = "permerror"
	// ResultTempError は名前解決の一時的な失敗を表す。
	ResultTempError Result = "temperror"
)

// Authorized は、その結果が「送信を認可されている」を意味するかを返す。
func (r Result) Authorized() bool {
	return r == ResultPass
}

// maxDnsLookups は1回の評価で許される DNS 問い合わせ回数の上限である
// (RFC 7208 4.6.4)。上限を超えた場合は permerror となる。
const maxDnsLookups = 10

// Evaluation は評価の結果と、その結果に至った根拠をまとめたものである。
type Evaluation struct {
	// Result は最終的な評価結果。
	Result Result
	// MatchedBy は結果を決めた mechanism のレコード上の表記、
	// MatchedAt はその mechanism が書かれていたドメインである。
	// include を辿った先で一致した場合は、辿った先のドメインになる。
	MatchedBy string
	MatchedAt string
	// Lookups は実際に行った DNS 問い合わせの回数。
	Lookups int
	// Warnings は評価を中断するほどではないが利用者に伝えるべき事象である。
	// 未対応の項目を読み飛ばしたことなどを含む。
	Warnings []string
}

// Evaluator は SPF レコードを辿って IP アドレスが認可されているかを判定する。
//
// recursive が false の場合、評価は対象ドメインのレコード内にとどまる。
// さらに DNS 問い合わせを要する項目 (include, redirect, a, mx, exists) は
// 評価せず、警告として報告する。
//
// 1つの Evaluator は1回の評価にのみ使う。ルックアップ回数などの状態を
// 持つため、使い回すと結果が正しくならない。
type Evaluator struct {
	resolver  Resolver
	recursive bool

	// lookups はこれまでに消費した DNS 問い合わせ回数。
	lookups int
	// skipped は recursive が false のために評価しなかった項目があるかを表す。
	skipped bool
	// warnings は報告済みの警告。同じ内容は重複して積まない。
	warnings []string
	// seen は現在辿っている include の経路上のドメインで、
	// include のループを検出するために使う。
	seen map[string]struct{}
	// propagate は、include 先で一致した mechanism を呼び出し元に
	// そのまま伝えるかどうかを表す。判定根拠として include 自体ではなく
	// 実際に一致した mechanism を報告するために使う。
	propagate bool

	matchedBy   string
	matchedAt   string
	matchedName string
}

// NewEvaluator は Evaluator を生成する。resolver に nil を渡した場合は
// DefaultResolver を使う。recursive に false を指定すると、対象ドメインの
// レコード内だけで評価する。
func NewEvaluator(resolver Resolver, recursive bool) *Evaluator {
	if resolver == nil {
		resolver = DefaultResolver
	}
	return &Evaluator{resolver: resolver, recursive: recursive, seen: map[string]struct{}{}}
}

// Check は取得済みの txtRecord を domain のレコードとして評価し、
// ipaddr が認可されているかを判定する。
//
// レコードは呼び出し側が取得したものを受け取る。表示やエラー処理のために
// 呼び出し側が既に持っている前提で、同じ問い合わせを繰り返さないためである。
func (e *Evaluator) Check(ctx context.Context, domain, txtRecord string, ipaddr net.IP) *Evaluation {
	e.seen[normalizeDomain(domain)] = struct{}{}
	result := e.evaluateRecord(ctx, ParseSpfRecord(txtRecord), domain, ipaddr)

	// 評価しなかった項目がある状態で all に一致した場合、その結論は
	// 読み飛ばした項目次第で変わりうる。確定した結果と誤解されないよう
	// 警告を添える。
	if e.skipped && result != ResultPass && e.matchedName == MechanismAll {
		e.warn("result is inconclusive: %q matched but -direct left some terms unevaluated", e.matchedBy)
	}

	return &Evaluation{
		Result:    result,
		MatchedBy: e.matchedBy,
		MatchedAt: e.matchedAt,
		Lookups:   e.lookups,
		Warnings:  e.warnings,
	}
}

// evaluateDomain は domain の SPF レコードを取得して評価する。
// include や redirect の評価から呼ばれる。
func (e *Evaluator) evaluateDomain(ctx context.Context, domain string, ipaddr net.IP) Result {
	txtRecord, err := lookupSpfRecord(ctx, e.resolver, domain)
	switch {
	case errors.Is(err, ErrMultipleSpfRecords):
		e.warn("%s publishes more than one spf record", domain)
		return ResultPermError
	case errors.Is(err, ErrNoSpfRecord), errors.Is(err, ErrNoTxtRecord):
		return ResultNone
	case err != nil:
		e.warn("lookup of %s failed: %v", domain, err)
		return ResultTempError
	}
	return e.evaluateRecord(ctx, ParseSpfRecord(txtRecord), domain, ipaddr)
}

// evaluateRecord は解析済みのレコードを先頭から順に評価する。
// 最初に一致した mechanism の修飾子が結果になる。
func (e *Evaluator) evaluateRecord(ctx context.Context, record *SpfRecord, domain string, ipaddr net.IP) Result {
	for _, unknown := range record.Unknown {
		e.warn("ignoring unrecognized term %q in the record of %s", unknown, domain)
	}

	for _, mechanism := range record.Mechanisms {
		matched, abort := e.matches(ctx, mechanism, domain, ipaddr)
		if abort != "" {
			return abort
		}
		if matched {
			// include 先の一致を伝播している場合は、そちらを判定根拠として残す。
			if !e.propagate {
				e.matchedBy = mechanism.Raw
				e.matchedAt = domain
				e.matchedName = mechanism.Name
			}
			e.propagate = false
			return mechanism.Qualifier.Result()
		}
	}

	// redirect はどの mechanism も一致しなかった場合にのみ適用される
	// (RFC 7208 6.1)。
	if record.Redirect != "" {
		if !e.recursive {
			e.skip("redirect=%s in the record of %s was not followed (-direct)", record.Redirect, domain)
			return ResultNeutral
		}
		if containsMacro(record.Redirect) {
			e.warn("redirect=%s uses macros, which are not supported", record.Redirect)
			return ResultPermError
		}
		if !e.spend() {
			return ResultPermError
		}
		return e.evaluateDomain(ctx, record.Redirect, ipaddr)
	}

	return ResultNeutral
}

// matches は mechanism が ipaddr に一致するかを返す。
//
// 第2戻り値が空でない場合、その結果で評価全体を打ち切る。一致・不一致では
// 表せない permerror や temperror を伝えるために使う。
func (e *Evaluator) matches(ctx context.Context, mechanism Mechanism, domain string, ipaddr net.IP) (bool, Result) {
	switch mechanism.Name {
	case MechanismAll:
		return true, ""

	case MechanismIP4, MechanismIP6:
		matched, err := matchAddressSpec(mechanism.Value, ipaddr, mechanism.Name == MechanismIP4)
		if err != nil {
			// 誤った表記の項目1つで残りの項目が評価されなくなるのを避ける。
			e.warn("ignoring %q in the record of %s: %v", mechanism.Raw, domain, err)
			return false, ""
		}
		return matched, ""

	case MechanismInclude:
		return e.matchInclude(ctx, mechanism, domain, ipaddr)

	case MechanismA:
		return e.matchAddressLookup(ctx, mechanism, domain, ipaddr)

	case MechanismMX:
		return e.matchMX(ctx, mechanism, domain, ipaddr)

	case MechanismExists:
		return e.matchExists(ctx, mechanism, domain)

	case MechanismPTR:
		e.warn("ignoring %q in the record of %s: the ptr mechanism is not supported", mechanism.Raw, domain)
		return false, ""

	default:
		e.warn("ignoring %q in the record of %s: unsupported mechanism", mechanism.Raw, domain)
		return false, ""
	}
}

// matchInclude は include 先のレコードを評価する。
// include は評価結果が pass のときだけ一致とみなす (RFC 7208 5.2)。
func (e *Evaluator) matchInclude(ctx context.Context, mechanism Mechanism, domain string, ipaddr net.IP) (bool, Result) {
	target, ok := e.resolveTarget(mechanism, mechanism.Value, domain)
	if !ok {
		return false, ""
	}

	// include のループを検出する。ルックアップ上限でも最終的には止まるが、
	// 先に検出することで報告するルックアップ回数が実態と合う。
	key := normalizeDomain(target)
	if _, visited := e.seen[key]; visited {
		e.warn("skipping %q in the record of %s: include loop detected", mechanism.Raw, domain)
		return false, ""
	}
	if !e.spend() {
		return false, ResultPermError
	}
	// 経路上のドメインとして記録し、評価が終わったら取り除く。同じドメインを
	// 別の経路から include するのは正当なので、経路単位で判定する。
	e.seen[key] = struct{}{}
	defer delete(e.seen, key)

	previousBy, previousAt, previousName := e.matchedBy, e.matchedAt, e.matchedName

	switch result := e.evaluateDomain(ctx, target, ipaddr); result {
	case ResultPass:
		// 判定根拠として include 自体ではなく、include 先で実際に一致した
		// mechanism を報告する。
		e.propagate = true
		return true, ""
	case ResultTempError:
		return false, ResultTempError
	case ResultPermError, ResultNone:
		e.warn("include:%s from the record of %s could not be evaluated (%s)", target, domain, result)
		return false, ResultPermError
	default:
		// include が一致しなかった以上、その中で一致した mechanism は
		// このレコードの判定根拠ではない。
		e.matchedBy, e.matchedAt, e.matchedName = previousBy, previousAt, previousName
		return false, ""
	}
}

// matchAddressLookup は a mechanism を評価する。対象ドメインのアドレスを
// 引き、ipaddr と一致するかを調べる (RFC 7208 5.3)。
func (e *Evaluator) matchAddressLookup(ctx context.Context, mechanism Mechanism, domain string, ipaddr net.IP) (bool, Result) {
	target, ok := e.resolveTarget(mechanism, defaultTarget(mechanism.Value, domain), domain)
	if !ok {
		return false, ""
	}
	if !e.spend() {
		return false, ResultPermError
	}

	addrs, err := e.resolver.LookupIP(ctx, "ip", target)
	if err != nil {
		// 引けなかった場合は一致しなかったものとして扱い、評価は続ける。
		e.warn("address lookup of %s (from %q) failed: %v", target, mechanism.Raw, err)
		return false, ""
	}
	return anyAddressMatches(addrs, mechanism, ipaddr), ""
}

// matchMX は mx mechanism を評価する。対象ドメインの MX ホストのアドレスを
// 引き、ipaddr と一致するかを調べる (RFC 7208 5.4)。
func (e *Evaluator) matchMX(ctx context.Context, mechanism Mechanism, domain string, ipaddr net.IP) (bool, Result) {
	target, ok := e.resolveTarget(mechanism, defaultTarget(mechanism.Value, domain), domain)
	if !ok {
		return false, ""
	}
	if !e.spend() {
		return false, ResultPermError
	}

	mxRecords, err := e.resolver.LookupMX(ctx, target)
	if err != nil {
		e.warn("mx lookup of %s (from %q) failed: %v", target, mechanism.Raw, err)
		return false, ""
	}
	// RFC 7208 4.6.4 は mx 1つが引けるアドレス数に上限を設けている。
	if len(mxRecords) > maxDnsLookups {
		e.warn("%s has more than %d mx hosts; only the first %d are checked", target, maxDnsLookups, maxDnsLookups)
		mxRecords = mxRecords[:maxDnsLookups]
	}

	for _, mxRecord := range mxRecords {
		addrs, err := e.resolver.LookupIP(ctx, "ip", mxRecord.Host)
		if err != nil {
			e.warn("address lookup of mx host %s failed: %v", mxRecord.Host, err)
			continue
		}
		if anyAddressMatches(addrs, mechanism, ipaddr) {
			return true, ""
		}
	}
	return false, ""
}

// matchExists は exists mechanism を評価する。対象ドメインの A レコードが
// 存在するかどうかだけを見る (RFC 7208 5.7)。
//
// この mechanism は本来マクロと組み合わせて使うものだが、マクロは未対応の
// ため、実用上はマクロを含まない指定のときにしか働かない。
func (e *Evaluator) matchExists(ctx context.Context, mechanism Mechanism, domain string) (bool, Result) {
	target, ok := e.resolveTarget(mechanism, mechanism.Value, domain)
	if !ok {
		return false, ""
	}
	if !e.spend() {
		return false, ResultPermError
	}

	addrs, err := e.resolver.LookupIP(ctx, "ip4", target)
	if err != nil {
		return false, ""
	}
	return len(addrs) > 0, ""
}

// resolveTarget は DNS 問い合わせを伴う mechanism に共通の前提を確認し、
// 問い合わせ先のドメインを返す。評価しない場合は ok に false を返す。
//
// 非再帰モードでの読み飛ばし、未対応のマクロ、対象ドメインが空の場合を
// ここでまとめて扱う。
func (e *Evaluator) resolveTarget(mechanism Mechanism, target, domain string) (string, bool) {
	if !e.recursive {
		e.skip("%q in the record of %s was not followed (-direct)", mechanism.Raw, domain)
		return "", false
	}
	if target == "" {
		e.warn("ignoring %q in the record of %s: no target domain", mechanism.Raw, domain)
		return "", false
	}
	if containsMacro(target) {
		e.warn("ignoring %q in the record of %s: macros are not supported", mechanism.Raw, domain)
		return "", false
	}
	return target, true
}

// spend は DNS 問い合わせを1回分消費する。上限を超えた場合は警告を残して
// false を返す。呼び出し側はこれを permerror として扱う。
func (e *Evaluator) spend() bool {
	e.lookups++
	if e.lookups > maxDnsLookups {
		e.warn("%v (%d)", ErrTooManyDnsLookups, maxDnsLookups)
		return false
	}
	return true
}

// skip は非再帰モードで項目を読み飛ばしたことを記録する。
// 記録した事実は、all に一致したときの結論が確定するかどうかの判断に使う。
func (e *Evaluator) skip(format string, args ...any) {
	e.skipped = true
	e.warn(format, args...)
}

// warn は警告を積む。同じ内容が既にあれば積まない。
// 複数の include で同じ警告が繰り返されるのを避けるためである。
func (e *Evaluator) warn(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	for _, existing := range e.warnings {
		if existing == message {
			return
		}
	}
	e.warnings = append(e.warnings, message)
}

// matchAddressSpec は ip4:/ip6: の値に ipaddr が含まれるかを判定する。
// wantIPv4 には ip4 mechanism なら true を渡す。
//
// プレフィックス長は省略でき、省略時はアドレスとの完全一致となる
// (RFC 7208 5.6)。ip4 が IPv6 アドレスに一致することはなく、その逆もない。
func matchAddressSpec(spec string, ipaddr net.IP, wantIPv4 bool) (bool, error) {
	address, prefix, hasPrefix := strings.Cut(spec, "/")

	base := net.ParseIP(address)
	if base == nil {
		return false, fmt.Errorf("invalid ip address %q", address)
	}
	if isIPv4(base) != wantIPv4 {
		return false, fmt.Errorf("address %q does not match the mechanism family", address)
	}

	bits := 128
	if wantIPv4 {
		bits = 32
	}
	length := bits
	if hasPrefix {
		if err := parsePrefixLength(prefix, bits, &length); err != nil {
			return false, fmt.Errorf("invalid prefix length %q", prefix)
		}
	}

	// アドレス族が違えば比較するまでもなく不一致である。
	if isIPv4(ipaddr) != wantIPv4 {
		return false, nil
	}

	mask := net.CIDRMask(length, bits)
	network := net.IPNet{IP: base.Mask(mask), Mask: mask}
	return network.Contains(ipaddr), nil
}

// anyAddressMatches は addrs のいずれかが ipaddr と一致するかを返す。
// a/mx で引いたアドレス群との比較に使う。
func anyAddressMatches(addrs []net.IP, mechanism Mechanism, ipaddr net.IP) bool {
	for _, addr := range addrs {
		if addressMatches(addr, mechanism, ipaddr) {
			return true
		}
	}
	return false
}

// addressMatches は candidate と ipaddr が、mechanism の dual-cidr-length で
// 定まる範囲において一致するかを返す。プレフィックス長の指定がない場合は
// 完全一致 (/32, /128) とする。
func addressMatches(candidate net.IP, mechanism Mechanism, ipaddr net.IP) bool {
	if isIPv4(candidate) != isIPv4(ipaddr) {
		return false
	}

	if isIPv4(ipaddr) {
		length := mechanism.Prefix4
		if length < 0 {
			length = 32
		}
		mask := net.CIDRMask(length, 32)
		return candidate.To4().Mask(mask).Equal(ipaddr.To4().Mask(mask))
	}

	length := mechanism.Prefix6
	if length < 0 {
		length = 128
	}
	mask := net.CIDRMask(length, 128)
	return candidate.To16().Mask(mask).Equal(ipaddr.To16().Mask(mask))
}

// isIPv4 はアドレスが IPv4 かどうかを返す。
// IPv4 射影 IPv6 アドレスは IPv4 として扱う。
func isIPv4(ipaddr net.IP) bool {
	return ipaddr.To4() != nil
}

// defaultTarget は mechanism にドメイン名の指定がない場合に、
// 評価中のドメインを補う。a と mx はドメイン名を省略できる。
func defaultTarget(value, domain string) string {
	if value == "" {
		return domain
	}
	return value
}

// containsMacro は値がマクロ展開 (RFC 7208 7) を含むかを返す。
// マクロは未対応のため、含む項目は評価せず警告の対象とする。
func containsMacro(value string) bool {
	return strings.Contains(value, "%{")
}

// normalizeDomain はドメイン名を比較用に正規化する。
// DNS 名は大文字小文字を区別せず、末尾のドットの有無も同じ名前を指す。
func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}
