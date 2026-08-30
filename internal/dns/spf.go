package dns

import (
	"fmt"
	"strconv"
	"strings"
)

// Qualifier は mechanism の先頭に置かれる修飾子である (RFC 7208 4.6.2)。
// 修飾子が省略された場合は "+" を指定したものとして扱う。
type Qualifier byte

// SPF で使える修飾子。
const (
	QualifierPass     Qualifier = '+' // 一致したら pass
	QualifierFail     Qualifier = '-' // 一致したら fail
	QualifierSoftFail Qualifier = '~' // 一致したら softfail
	QualifierNeutral  Qualifier = '?' // 一致したら neutral
)

// Result は、この修飾子を持つ mechanism が一致したときの評価結果を返す。
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

// mechanism の名前。SPF の項目は大文字小文字を区別しないため、
// 解析時に小文字へ正規化したうえでこれらと比較する。
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

// Mechanism は解析済みの mechanism 1つを表す。
type Mechanism struct {
	// Raw はレコード上の表記をそのまま保持する。警告や判定根拠の
	// 表示に使うため、解析結果とは別に元の文字列を残している。
	Raw string
	// Qualifier は先頭の修飾子。省略時は QualifierPass。
	Qualifier Qualifier
	// Name は小文字化した mechanism 名。
	Name string
	// Value は ":" より後ろの文字列。ip4/ip6 ではアドレス、
	// include/a/mx/exists ではドメイン名を表す。値を伴わない場合は空。
	Value string
	// Prefix4 と Prefix6 は a/mx が持つ dual-cidr-length を表す。
	// 指定がない場合は -1 とし、評価時に既定値 (/32, /128) を補う。
	Prefix4 int
	Prefix6 int
}

// SpfRecord は解析済みの SPF レコードを表す。
type SpfRecord struct {
	// Txt は元の TXT レコード。
	Txt string
	// Mechanisms はレコードに現れた順の mechanism。SPF は先に一致した
	// mechanism で結果が決まるため、順序に意味がある。
	Mechanisms []Mechanism
	// Redirect は redirect= 修飾子の値。指定がなければ空。
	Redirect string
	// Exp は exp= 修飾子の値。指定がなければ空。
	Exp string
	// Unknown は解釈できなかった項目である。黙って捨てると誤った判定に
	// 気づけないため、利用者に報告できるよう保持する。
	Unknown []string
}

// ParseSpfRecord は TXT レコードを解析して各項目に分解する。
//
// 解釈できない項目があってもレコード全体を失敗とはせず、Unknown に集めて
// 残りの項目の解析を続ける。1つの誤りで正しい項目まで評価されなくなるのを
// 避けるためである。
func ParseSpfRecord(txtRecord string) *SpfRecord {
	record := &SpfRecord{Txt: txtRecord}

	for i, field := range strings.Fields(txtRecord) {
		// 先頭のバージョン文字列は modifier と同じ "name=value" の形を
		// しているため、先に読み飛ばす。
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

// splitModifier は "name=value" 形式の modifier を名前と値に分解する。
// modifier でない場合は ok に false を返す。
//
// ":" や "/" より後ろの "=" は mechanism の値の一部なので、modifier の
// 区切りとは見なさない。
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

// parseMechanism は項目1つを Mechanism に解析する。
// mechanism として解釈できない場合は ErrInvalidMechanism を返す。
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

	// mechanism 名は ":" (値) か "/" (プレフィックス長) の手前までである。
	name, rest := term, ""
	if i := strings.IndexAny(term, ":/"); i >= 0 {
		name, rest = term[:i], term[i:]
	}
	mechanism.Name = strings.ToLower(name)

	// 値の形式は mechanism ごとに異なるため、名前で分岐して解析する。
	switch mechanism.Name {
	case MechanismIP4, MechanismIP6:
		// アドレスは "/len" を含めたまま保持し、評価時にまとめて解釈する。
		if !strings.HasPrefix(rest, ":") {
			return mechanism, ErrInvalidMechanism
		}
		mechanism.Value = rest[1:]
		if mechanism.Value == "" {
			return mechanism, ErrInvalidMechanism
		}

	case MechanismA, MechanismMX:
		// ドメイン名は省略でき、その後ろに dual-cidr-length が続きうる。
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
		// これらはドメイン名が必須である。
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

// parseDualCidrLength は a/mx に続く ["/" ip4-len] ["//" ip6-len] を解析し、
// mechanism の Prefix4 と Prefix6 に格納する。suffix は "/" で始まる。
func parseDualCidrLength(suffix string, mechanism *Mechanism) error {
	// "//64" のように IPv6 側だけを指定する形を先に判定する。
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

// parsePrefixLength はプレフィックス長を解析して dst に格納する。
// max はアドレス長 (IPv4 なら 32、IPv6 なら 128) を指定する。
func parsePrefixLength(text string, max int, dst *int) error {
	length, err := strconv.Atoi(text)
	if err != nil || length < 0 || length > max {
		return fmt.Errorf("%w: invalid prefix length %q", ErrInvalidMechanism, text)
	}
	*dst = length
	return nil
}
