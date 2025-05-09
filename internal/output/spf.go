package output

import (
	"fmt"
	"strings"
)

func FormatSpfRecordAligned(spfRecord string) string {
	parts := strings.Fields(spfRecord)
	var rows []string
	for _, part := range parts {
		var label string
		switch {
		case strings.HasPrefix(part, "v="):
			label = "Version"
		case strings.HasPrefix(part, "ip4:"):
			label = "IPv4"
		case strings.HasPrefix(part, "ip6:"):
			label = "IPv6"
		case strings.HasPrefix(part, "include:"):
			label = "Include"
		case strings.HasPrefix(part, "exists:"):
			label = "Exists"
		case part == "~all" || part == "-all" || part == "?all" || part == "+all":
			label = "All Mechanism"
		default:
			label = "Other"
		}
		rows = append(rows, fmt.Sprintf("%-15s : %s", label, part))
	}
	return strings.Join(rows, "\n")
}
