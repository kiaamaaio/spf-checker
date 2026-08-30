// Package output は、解析済みの SPF レコードを人が読みやすい形へ整形する。
package output

import (
	"fmt"
	"strings"

	"spf-checker/internal/dns"
)

// labelWidth はラベル欄の桁数。値の開始位置を揃えるために使う。
const labelWidth = 15

// mechanismLabels は mechanism 名に対応する表示用のラベルである。
// ここに無い mechanism は "Other" として表示する。
var mechanismLabels = map[string]string{
	dns.MechanismIP4:     "IPv4",
	dns.MechanismIP6:     "IPv6",
	dns.MechanismInclude: "Include",
	dns.MechanismA:       "A",
	dns.MechanismMX:      "MX",
	dns.MechanismPTR:     "PTR",
	dns.MechanismExists:  "Exists",
	dns.MechanismAll:     "All Mechanism",
}

// FormatSpfRecordAligned は SPF レコードを1項目1行に整形して返す。
//
// 項目はレコードに現れた順に並べる。SPF は先に一致した mechanism で結果が
// 決まるため、順序自体が読み手にとっての情報になるためである。
// 解釈できなかった項目も "Unknown" として表示し、黙って省かない。
func FormatSpfRecordAligned(record *dns.SpfRecord) string {
	var rows []string

	if fields := strings.Fields(record.Txt); len(fields) > 0 && strings.HasPrefix(strings.ToLower(fields[0]), "v=spf") {
		rows = append(rows, row("Version", fields[0]))
	}
	for _, mechanism := range record.Mechanisms {
		label, ok := mechanismLabels[mechanism.Name]
		if !ok {
			label = "Other"
		}
		rows = append(rows, row(label, mechanism.Raw))
	}
	if record.Redirect != "" {
		rows = append(rows, row("Redirect", "redirect="+record.Redirect))
	}
	if record.Exp != "" {
		rows = append(rows, row("Explanation", "exp="+record.Exp))
	}
	for _, unknown := range record.Unknown {
		rows = append(rows, row("Unknown", unknown))
	}

	return strings.Join(rows, "\n")
}

// row はラベルと値を桁揃えした1行を返す。
func row(label, value string) string {
	return fmt.Sprintf("%-*s : %s", labelWidth, label, value)
}
