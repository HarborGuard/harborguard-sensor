package adapter

import (
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// ExtractGrypeVulnerabilities extracts normalized vulnerabilities from grype JSON.
func ExtractGrypeVulnerabilities(report interface{}) []types.NormalizedVulnerability {
	var findings []types.NormalizedVulnerability

	data, ok := report.(map[string]interface{})
	if !ok {
		return findings
	}

	matches, ok := data["matches"].([]interface{})
	if !ok {
		return findings
	}

	for _, m := range matches {
		match, ok := m.(map[string]interface{})
		if !ok {
			continue
		}

		vuln, _ := match["vulnerability"].(map[string]interface{})
		artifact, _ := match["artifact"].(map[string]interface{})
		if vuln == nil || artifact == nil {
			continue
		}

		var fixedVersion string
		if fix, ok := vuln["fix"].(map[string]interface{}); ok {
			if versions, ok := fix["versions"].([]interface{}); ok && len(versions) > 0 {
				if v, ok := versions[0].(string); ok {
					fixedVersion = v
				}
			}
		}

		var cvssScore *float64
		if cvssArr, ok := vuln["cvss"].([]interface{}); ok && len(cvssArr) > 0 {
			if first, ok := cvssArr[0].(map[string]interface{}); ok {
				if metrics, ok := first["metrics"].(map[string]interface{}); ok {
					if s, ok := metrics["baseScore"].(float64); ok {
						cvssScore = &s
					}
				}
			}
		}

		var vulnURL string
		if urls, ok := vuln["urls"].([]interface{}); ok && len(urls) > 0 {
			if u, ok := urls[0].(string); ok {
				vulnURL = u
			}
		}

		findings = append(findings, types.NormalizedVulnerability{
			Source:           "grype",
			CveID:            getString(vuln, "id"),
			PackageName:      getString(artifact, "name"),
			InstalledVersion: getString(artifact, "version"),
			FixedVersion:     fixedVersion,
			Severity:         MapSeverity(getString(vuln, "severity")),
			CvssScore:        cvssScore,
			VulnerabilityURL: vulnURL,
			Description:      getString(vuln, "description"),
		})
	}

	return findings
}
