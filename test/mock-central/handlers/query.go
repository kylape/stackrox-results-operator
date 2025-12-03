package handlers

import (
	"strings"
)

// QueryFilter represents a parsed query filter
type QueryFilter struct {
	Field string
	Value string
}

// ParseQuery parses the StackRox query format into filters
// Format: "Field1:value1+Field2:value2+Field3:value3"
// Example: "Namespace:default+Severity:CRITICAL+Lifecycle Stage:RUNTIME"
func ParseQuery(query string) []QueryFilter {
	if query == "" {
		return nil
	}

	var filters []QueryFilter
	parts := strings.Split(query, "+")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split on first colon to handle values that may contain colons
		colonIdx := strings.Index(part, ":")
		if colonIdx == -1 {
			continue
		}

		field := strings.TrimSpace(part[:colonIdx])
		value := strings.TrimSpace(part[colonIdx+1:])

		filters = append(filters, QueryFilter{
			Field: field,
			Value: value,
		})
	}

	return filters
}

// GetFilterValue returns the first value for a given field name, or empty string if not found
func GetFilterValue(filters []QueryFilter, field string) string {
	for _, f := range filters {
		if strings.EqualFold(f.Field, field) {
			return f.Value
		}
	}
	return ""
}

// GetFilterValues returns all values for a given field name
func GetFilterValues(filters []QueryFilter, field string) []string {
	var values []string
	for _, f := range filters {
		if strings.EqualFold(f.Field, field) {
			values = append(values, f.Value)
		}
	}
	return values
}

// HasFilter checks if a filter for the given field exists
func HasFilter(filters []QueryFilter, field string) bool {
	for _, f := range filters {
		if strings.EqualFold(f.Field, field) {
			return true
		}
	}
	return false
}

// SeverityLevel represents severity levels with numeric values for comparison
type SeverityLevel int

const (
	SeverityUnknown SeverityLevel = 0
	SeverityLow     SeverityLevel = 1
	SeverityMedium  SeverityLevel = 2
	SeverityHigh    SeverityLevel = 3
	SeverityCritical SeverityLevel = 4
)

// ParseSeverity converts a severity string to a SeverityLevel
func ParseSeverity(severity string) SeverityLevel {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "CRITICAL_SEVERITY":
		return SeverityCritical
	case "HIGH", "HIGH_SEVERITY", "IMPORTANT", "IMPORTANT_VULNERABILITY_SEVERITY":
		return SeverityHigh
	case "MEDIUM", "MEDIUM_SEVERITY", "MODERATE", "MODERATE_VULNERABILITY_SEVERITY":
		return SeverityMedium
	case "LOW", "LOW_SEVERITY":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// IsSeverityAtLeast checks if severity meets the minimum threshold
func IsSeverityAtLeast(severity string, minSeverity string) bool {
	severityLevel := ParseSeverity(severity)
	minLevel := ParseSeverity(minSeverity)
	return severityLevel >= minLevel
}
