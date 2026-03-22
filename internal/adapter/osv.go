package adapter

import (
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// ExtractOsvVulnerabilities extracts normalized vulnerabilities from osv-scanner JSON.
func ExtractOsvVulnerabilities(report interface{}) []types.NormalizedVulnerability {
	var findings []types.NormalizedVulnerability

	data, ok := report.(map[string]interface{})
	if !ok {
		return findings
	}

	results, ok := data["results"].([]interface{})
	if !ok {
		return findings
	}

	for _, r := range results {
		result, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		pkgs, ok := result["packages"].([]interface{})
		if !ok {
			continue
		}

		for _, p := range pkgs {
			pkgEntry, ok := p.(map[string]interface{})
			if !ok {
				continue
			}

			var packageName, installedVersion string
			if pkg, ok := pkgEntry["package"].(map[string]interface{}); ok {
				packageName = getString(pkg, "name")
				installedVersion = getString(pkg, "version")
			}
			if packageName == "" {
				packageName = "unknown"
			}

			vulns, ok := pkgEntry["vulnerabilities"].([]interface{})
			if !ok {
				continue
			}

			for _, v := range vulns {
				vuln, ok := v.(map[string]interface{})
				if !ok {
					continue
				}

				var severities []interface{}
				if s, ok := vuln["severity"].([]interface{}); ok {
					severities = s
				}

				var vulnURL string
				if refs, ok := vuln["references"].([]interface{}); ok && len(refs) > 0 {
					if ref, ok := refs[0].(map[string]interface{}); ok {
						vulnURL = getString(ref, "url")
					}
				}

				findings = append(findings, types.NormalizedVulnerability{
					Source:           "osv",
					CveID:            getString(vuln, "id"),
					PackageName:      packageName,
					InstalledVersion: installedVersion,
					Severity:         MapOsvSeverity(severities),
					CvssScore:        ExtractOsvScore(severities),
					VulnerabilityURL: vulnURL,
					Title:            getString(vuln, "summary"),
					Description:      getString(vuln, "details"),
				})
			}
		}
	}

	return findings
}
