package output

import (
	"fmt"
	"strings"

	"spf-checker/internal/dns"
)

const labelWidth = 15

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

// FormatSpfRecordAligned renders a parsed spf record as one labelled row per
// term, in the order they appear in the record.
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

func row(label, value string) string {
	return fmt.Sprintf("%-*s : %s", labelWidth, label, value)
}
