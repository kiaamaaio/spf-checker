package dns

import (
	"fmt"
	"strconv"
	"strings"
)

// Qualifier is the prefix character that decides the result of a matching
// mechanism (RFC 7208 4.6.2). An absent qualifier means "+".
type Qualifier byte

const (
	QualifierPass     Qualifier = '+'
	QualifierFail     Qualifier = '-'
	QualifierSoftFail Qualifier = '~'
	QualifierNeutral  Qualifier = '?'
)

// Result maps a qualifier onto the result it produces when its mechanism
// matches.
func (q Qualifier) Result() Result {
	switch q {
	case QualifierFail:
		return ResultFail
	case QualifierSoftFail:
		return ResultSoftFail
	case QualifierNeutral:
		return ResultNeutral
	default:
		return ResultPass
	}
}

// Mechanism names. They are compared lowercased; spf terms are case
// insensitive.
const (
	MechanismAll     = "all"
	MechanismInclude = "include"
	MechanismA       = "a"
	MechanismMX      = "mx"
	MechanismPTR     = "ptr"
	MechanismIP4     = "ip4"
	MechanismIP6     = "ip6"
	MechanismExists  = "exists"
)

// Mechanism is a single parsed spf term.
type Mechanism struct {
	Raw       string
	Qualifier Qualifier
	Name      string
	// Value is the text after ":" - an address for ip4/ip6, a domain for
	// include/a/mx/exists. Empty when the term carries no value.
	Value string
	// Prefix4 and Prefix6 hold the dual-cidr-length of a/mx terms, or -1
	// when the term does not specify one.
	Prefix4 int
	Prefix6 int
}

// SpfRecord is a parsed spf TXT record.
type SpfRecord struct {
	Txt        string
	Mechanisms []Mechanism
	Redirect   string
	Exp        string
	// Unknown holds terms that could not be parsed. They are reported to the
	// user rather than silently dropped.
	Unknown []string
}

// ParseSpfRecord parses a TXT record into its terms. Terms that cannot be
// understood are collected in Unknown instead of failing the whole record.
func ParseSpfRecord(txtRecord string) *SpfRecord {
	record := &SpfRecord{Txt: txtRecord}

	for i, field := range strings.Fields(txtRecord) {
		if i == 0 && strings.EqualFold(field, spfVersion) {
			continue
		}

		if name, value, ok := splitModifier(field); ok {
			switch name {
			case "redirect":
				record.Redirect = value
			case "exp":
				record.Exp = value
			default:
				record.Unknown = append(record.Unknown, field)
			}
			continue
		}

		mechanism, err := parseMechanism(field)
		if err != nil {
			record.Unknown = append(record.Unknown, field)
			continue
		}
		record.Mechanisms = append(record.Mechanisms, mechanism)
	}

	return record
}

// splitModifier recognises "name=value" terms. A "=" that appears after a ":"
// or "/" belongs to a mechanism value, not to a modifier.
func splitModifier(field string) (name, value string, ok bool) {
	equals := strings.Index(field, "=")
	if equals <= 0 {
		return "", "", false
	}
	if strings.ContainsAny(field[:equals], ":/") {
		return "", "", false
	}
	return strings.ToLower(field[:equals]), field[equals+1:], true
}

func parseMechanism(field string) (Mechanism, error) {
	mechanism := Mechanism{Raw: field, Qualifier: QualifierPass, Prefix4: -1, Prefix6: -1}

	term := field
	switch term[0] {
	case '+', '-', '~', '?':
		mechanism.Qualifier = Qualifier(term[0])
		term = term[1:]
	}
	if term == "" {
		return mechanism, ErrInvalidMechanism
	}

	name, rest := term, ""
	if i := strings.IndexAny(term, ":/"); i >= 0 {
		name, rest = term[:i], term[i:]
	}
	mechanism.Name = strings.ToLower(name)

	switch mechanism.Name {
	case MechanismIP4, MechanismIP6:
		// The address keeps its "/len" so that it can be parsed as a whole.
		if !strings.HasPrefix(rest, ":") {
			return mechanism, ErrInvalidMechanism
		}
		mechanism.Value = rest[1:]
		if mechanism.Value == "" {
			return mechanism, ErrInvalidMechanism
		}

	case MechanismA, MechanismMX:
		if strings.HasPrefix(rest, ":") {
			rest = rest[1:]
			if slash := strings.Index(rest, "/"); slash >= 0 {
				mechanism.Value, rest = rest[:slash], rest[slash:]
			} else {
				mechanism.Value, rest = rest, ""
			}
			if mechanism.Value == "" {
				return mechanism, ErrInvalidMechanism
			}
		}
		if rest != "" {
			if err := parseDualCidrLength(rest, &mechanism); err != nil {
				return mechanism, err
			}
		}

	case MechanismInclude, MechanismExists:
		if !strings.HasPrefix(rest, ":") || rest == ":" {
			return mechanism, ErrInvalidMechanism
		}
		mechanism.Value = rest[1:]

	case MechanismAll:
		if rest != "" {
			return mechanism, ErrInvalidMechanism
		}

	case MechanismPTR:
		if strings.HasPrefix(rest, ":") {
			mechanism.Value = rest[1:]
		} else if rest != "" {
			return mechanism, ErrInvalidMechanism
		}

	default:
		return mechanism, ErrInvalidMechanism
	}

	return mechanism, nil
}

// parseDualCidrLength parses the ["/" ip4-len] ["//" ip6-len] suffix of a/mx.
func parseDualCidrLength(suffix string, mechanism *Mechanism) error {
	if strings.HasPrefix(suffix, "//") {
		return parsePrefixLength(suffix[2:], 128, &mechanism.Prefix6)
	}

	body := suffix[1:]
	if i := strings.Index(body, "//"); i >= 0 {
		if err := parsePrefixLength(body[:i], 32, &mechanism.Prefix4); err != nil {
			return err
		}
		return parsePrefixLength(body[i+2:], 128, &mechanism.Prefix6)
	}
	return parsePrefixLength(body, 32, &mechanism.Prefix4)
}

func parsePrefixLength(text string, max int, dst *int) error {
	length, err := strconv.Atoi(text)
	if err != nil || length < 0 || length > max {
		return fmt.Errorf("%w: invalid prefix length %q", ErrInvalidMechanism, text)
	}
	*dst = length
	return nil
}
