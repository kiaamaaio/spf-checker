package delimiter

import "strings"

var newlineCode string = "\n"

func Whitespace(value string) string {
	return strings.Join(strings.Fields(value), newlineCode)
}

func Element(values []string) string {
	var sb strings.Builder
	for i, value := range values {
		if i > 0 {
			sb.WriteString(newlineCode)
		}
		sb.WriteString(value)
	}
	return sb.String()
}
