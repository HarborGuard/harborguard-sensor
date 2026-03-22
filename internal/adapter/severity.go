package adapter

import (
	"fmt"
	"math"
	"strings"
)

// MapSeverity normalizes a severity string to the standard set.
func MapSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "INFO", "NEGLIGIBLE", "UNKNOWN":
		return "INFO"
	default:
		return "INFO"
	}
}

// MapOsvSeverity derives severity from OSV CVSS_V3 score.
func MapOsvSeverity(severities []interface{}) string {
	if len(severities) == 0 {
		return "INFO"
	}

	for _, sev := range severities {
		m, ok := sev.(map[string]interface{})
		if !ok {
			continue
		}
		if t, _ := m["type"].(string); t == "CVSS_V3" {
			score := toFloat64(m["score"])
			if score >= 9.0 {
				return "CRITICAL"
			}
			if score >= 7.0 {
				return "HIGH"
			}
			if score >= 4.0 {
				return "MEDIUM"
			}
			if score >= 0.1 {
				return "LOW"
			}
		}
	}

	return "INFO"
}

// ExtractOsvScore extracts the CVSS_V3 score from OSV severity data.
func ExtractOsvScore(severities []interface{}) *float64 {
	if len(severities) == 0 {
		return nil
	}

	for _, sev := range severities {
		m, ok := sev.(map[string]interface{})
		if !ok {
			continue
		}
		if t, _ := m["type"].(string); t == "CVSS_V3" {
			score := toFloat64(m["score"])
			if score > 0 {
				return &score
			}
		}
	}

	return nil
}

// MapDockleCategory maps a dockle level to a category string.
func MapDockleCategory(level string) string {
	switch level {
	case "FATAL":
		return "Security"
	case "WARN":
		return "BestPractice"
	case "INFO":
		return "CIS"
	default:
		return "BestPractice"
	}
}

// MapDockleSeverity maps a dockle level to a normalized severity.
func MapDockleSeverity(level string) string {
	switch level {
	case "FATAL":
		return "CRITICAL"
	case "WARN":
		return "MEDIUM"
	case "INFO":
		return "LOW"
	default:
		return "INFO"
	}
}

// SeverityOrder returns the sort rank of a severity (lower = more severe).
func SeverityOrder(severity string) int {
	switch severity {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	case "INFO":
		return 4
	default:
		return 5
	}
}

// CalculateRiskScore computes the risk score from vulnerability counts and CVSS.
func CalculateRiskScore(counts map[string]int, avgCvss float64) int {
	score := float64(counts["critical"])*25 +
		float64(counts["high"])*10 +
		float64(counts["medium"])*3 +
		float64(counts["low"])*1 +
		avgCvss*5

	rounded := int(math.Round(score))
	if rounded > 100 {
		return 100
	}
	return rounded
}

func toFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case string:
		// Try parsing
		var f float64
		if _, err := fmt.Sscanf(n, "%f", &f); err == nil {
			return f
		}
	}
	return 0
}
