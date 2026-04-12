package bill

import "strings"

// splitCSV splits a comma-separated string and trims whitespace from each
// resulting token, dropping empty entries.
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// uniqueAppend appends v to items if it isn't already present, preserving
// insertion order.
func uniqueAppend(items []string, v string) []string {
	for _, it := range items {
		if it == v {
			return items
		}
	}
	return append(items, v)
}
