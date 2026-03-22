package adapter

import (
	"fmt"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// ExtractDockleCompliance extracts normalized compliance findings from dockle JSON.
func ExtractDockleCompliance(report interface{}) []types.NormalizedCompliance {
	var findings []types.NormalizedCompliance

	data, ok := report.(map[string]interface{})
	if !ok {
		return findings
	}

	details, ok := data["details"].([]interface{})
	if !ok {
		return findings
	}

	for _, d := range details {
		detail, ok := d.(map[string]interface{})
		if !ok {
			continue
		}

		alerts, ok := detail["alerts"].([]interface{})
		if !ok {
			continue
		}

		level := getString(detail, "level")

		for _, a := range alerts {
			var message string
			switch v := a.(type) {
			case string:
				message = v
			case map[string]interface{}:
				message = getString(v, "message")
				if message == "" {
					message = fmt.Sprintf("%v", v)
				}
			default:
				message = fmt.Sprintf("%v", v)
			}

			findings = append(findings, types.NormalizedCompliance{
				Source:   "dockle",
				RuleID:   getString(detail, "code"),
				RuleName: getString(detail, "title"),
				Category: MapDockleCategory(level),
				Severity: MapDockleSeverity(level),
				Message:  message,
			})
		}
	}

	return findings
}
