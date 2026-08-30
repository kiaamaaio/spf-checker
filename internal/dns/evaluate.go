package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Result is the outcome of evaluating an spf record against an ip address
// (RFC 7208 2.6).
type Result string

const (
	ResultPass      Result = "pass"
	ResultFail      Result = "fail"
	ResultSoftFail  Result = "softfail"
	ResultNeutral   Result = "neutral"
	ResultNone      Result = "none"
	ResultPermError Result = "permerror"
	ResultTempError Result = "temperror"
)

// Authorized reports whether the result means the ip may send for the domain.
func (r Result) Authorized() bool {
	return r == ResultPass
}

// maxDnsLookups is the RFC 7208 4.6.4 limit on the number of dns queries a
// single evaluation may trigger.
const maxDnsLookups = 10

// Evaluation is the outcome of a check, together with what produced it.
type Evaluation struct {
	Result Result
	// MatchedBy is the raw text of the mechanism that decided the result,
	// and MatchedAt the domain whose record contained it.
	MatchedBy string
	MatchedAt string
	Lookups   int
	Warnings  []string
}

// Evaluator walks an spf record and decides whether an ip is authorized.
// When recursive is false the evaluation stays inside the record of the domain
// being checked: terms that would require further dns queries (include,
// redirect, a, mx, exists) are skipped and reported as warnings.
type Evaluator struct {
	resolver  Resolver
	recursive bool

	lookups int
	skipped bool
	// propagate carries the match of an included record up to the caller so
	// that the reported term is the one that really matched.
	propagate   bool
	warnings    []string
	seen        map[string]struct{}
	matchedBy   string
	matchedAt   string
	matchedName string
}

func NewEvaluator(resolver Resolver, recursive bool) *Evaluator {
	if resolver == nil {
		resolver = DefaultResolver
	}
	return &Evaluator{resolver: resolver, recursive: recursive, seen: map[string]struct{}{}}
}

// Check evaluates the already fetched record of domain against ipaddr.
func (e *Evaluator) Check(ctx context.Context, domain, txtRecord string, ipaddr net.IP) *Evaluation {
	e.seen[normalizeDomain(domain)] = struct{}{}
	result := e.evaluateRecord(ctx, ParseSpfRecord(txtRecord), domain, ipaddr)

	// A conclusive "all" verdict cannot be trusted when terms were skipped.
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
			if !e.propagate {
				e.matchedBy = mechanism.Raw
				e.matchedAt = domain
				e.matchedName = mechanism.Name
			}
			e.propagate = false
			return mechanism.Qualifier.Result()
		}
	}

	// redirect only applies when no mechanism matched (RFC 7208 6.1).
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

// matches reports whether the mechanism matches ipaddr. A non-empty second
// return value aborts the whole evaluation with that result.
func (e *Evaluator) matches(ctx context.Context, mechanism Mechanism, domain string, ipaddr net.IP) (bool, Result) {
	switch mechanism.Name {
	case MechanismAll:
		return true, ""

	case MechanismIP4, MechanismIP6:
		matched, err := matchAddressSpec(mechanism.Value, ipaddr, mechanism.Name == MechanismIP4)
		if err != nil {
			// A malformed address must not hide the rest of the record.
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

func (e *Evaluator) matchInclude(ctx context.Context, mechanism Mechanism, domain string, ipaddr net.IP) (bool, Result) {
	target, ok := e.resolveTarget(mechanism, mechanism.Value, domain)
	if !ok {
		return false, ""
	}

	// Guard against include loops; the lookup budget alone would also stop
	// them, but this keeps the reported lookup count honest.
	key := normalizeDomain(target)
	if _, visited := e.seen[key]; visited {
		e.warn("skipping %q in the record of %s: include loop detected", mechanism.Raw, domain)
		return false, ""
	}
	if !e.spend() {
		return false, ResultPermError
	}
	e.seen[key] = struct{}{}
	defer delete(e.seen, key)

	previousBy, previousAt, previousName := e.matchedBy, e.matchedAt, e.matchedName

	switch result := e.evaluateDomain(ctx, target, ipaddr); result {
	case ResultPass:
		// Keep the term the included record matched on, not this include.
		e.propagate = true
		return true, ""
	case ResultTempError:
		return false, ResultTempError
	case ResultPermError, ResultNone:
		e.warn("include:%s from the record of %s could not be evaluated (%s)", target, domain, result)
		return false, ResultPermError
	default:
		// The include did not match, so anything it matched internally is
		// not what decides this record.
		e.matchedBy, e.matchedAt, e.matchedName = previousBy, previousAt, previousName
		return false, ""
	}
}

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
		e.warn("address lookup of %s (from %q) failed: %v", target, mechanism.Raw, err)
		return false, ""
	}
	return anyAddressMatches(addrs, mechanism, ipaddr), ""
}

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
	// RFC 7208 4.6.4 caps the address lookups a single mx term may trigger.
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

// resolveTarget applies the checks shared by every dns-querying mechanism:
// the recursive flag, macro support and an empty target.
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

// spend consumes one unit of the dns lookup budget.
func (e *Evaluator) spend() bool {
	e.lookups++
	if e.lookups > maxDnsLookups {
		e.warn("%v (%d)", ErrTooManyDnsLookups, maxDnsLookups)
		return false
	}
	return true
}

func (e *Evaluator) skip(format string, args ...any) {
	e.skipped = true
	e.warn(format, args...)
}

func (e *Evaluator) warn(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	for _, existing := range e.warnings {
		if existing == message {
			return
		}
	}
	e.warnings = append(e.warnings, message)
}

// matchAddressSpec matches ipaddr against an ip4:/ip6: value. The prefix
// length is optional (RFC 7208 5.6); an address without one matches exactly.
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

	// An ipv4 mechanism never matches an ipv6 query and vice versa.
	if isIPv4(ipaddr) != wantIPv4 {
		return false, nil
	}

	mask := net.CIDRMask(length, bits)
	network := net.IPNet{IP: base.Mask(mask), Mask: mask}
	return network.Contains(ipaddr), nil
}

func anyAddressMatches(addrs []net.IP, mechanism Mechanism, ipaddr net.IP) bool {
	for _, addr := range addrs {
		if addressMatches(addr, mechanism, ipaddr) {
			return true
		}
	}
	return false
}

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

func isIPv4(ipaddr net.IP) bool {
	return ipaddr.To4() != nil
}

func defaultTarget(value, domain string) string {
	if value == "" {
		return domain
	}
	return value
}

func containsMacro(value string) bool {
	return strings.Contains(value, "%{")
}

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}
