package adapter

import (
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// ExtractTrivyVulnerabilities extracts normalized vulnerabilities from trivy JSON.
func ExtractTrivyVulnerabilities(report interface{}) []types.NormalizedVulnerability {
	var findings []types.NormalizedVulnerability

	data, ok := report.(map[string]interface{})
	if !ok {
		return findings
	}

	results, ok := data["Results"].([]interface{})
	if !ok {
		return findings
	}

	for _, r := range results {
		result, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		vulns, ok := result["Vulnerabilities"].([]interface{})
		if !ok {
			continue
		}
		for _, v := range vulns {
			vuln, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			cveID := getString(vuln, "VulnerabilityID")
			if cveID == "" {
				cveID = getString(vuln, "PkgID")
			}
			pkgName := getString(vuln, "PkgName")
			if pkgName == "" {
				pkgName = getString(vuln, "PkgID")
			}

			var cvssScore *float64
			if cvss, ok := vuln["CVSS"].(map[string]interface{}); ok {
				if nvd, ok := cvss["nvd"].(map[string]interface{}); ok {
					if s, ok := nvd["V3Score"].(float64); ok {
						cvssScore = &s
					}
				}
				if cvssScore == nil {
					if rh, ok := cvss["redhat"].(map[string]interface{}); ok {
						if s, ok := rh["V3Score"].(float64); ok {
							cvssScore = &s
						}
					}
				}
			}

			findings = append(findings, types.NormalizedVulnerability{
				Source:           "trivy",
				CveID:            cveID,
				PackageName:      pkgName,
				InstalledVersion: getString(vuln, "InstalledVersion"),
				FixedVersion:     getString(vuln, "FixedVersion"),
				Severity:         MapSeverity(getString(vuln, "Severity")),
				CvssScore:        cvssScore,
				VulnerabilityURL: getString(vuln, "PrimaryURL"),
				Title:            getString(vuln, "Title"),
				Description:      getString(vuln, "Description"),
			})
		}
	}

	return findings
}

// ExtractTrivyPackages extracts normalized packages from trivy JSON.
func ExtractTrivyPackages(report interface{}) []types.NormalizedPackage {
	var findings []types.NormalizedPackage

	data, ok := report.(map[string]interface{})
	if !ok {
		return findings
	}

	results, ok := data["Results"].([]interface{})
	if !ok {
		return findings
	}

	for _, r := range results {
		result, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		resultType := getString(result, "Type")
		if resultType == "" {
			resultType = "unknown"
		}

		pkgs, ok := result["Packages"].([]interface{})
		if !ok {
			continue
		}
		for _, p := range pkgs {
			pkg, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			version := getString(pkg, "Version")

			findings = append(findings, types.NormalizedPackage{
				Source:  "trivy",
				Name:    getString(pkg, "Name"),
				Version: version,
				Type:    resultType,
				License: formatLicense(pkg["License"]),
			})
		}
	}

	return findings
}

// formatLicense handles string, array, and object license formats.
func formatLicense(license interface{}) string {
	if license == nil {
		return ""
	}
	switch v := license.(type) {
	case string:
		return v
	case []interface{}:
		var parts []string
		for _, l := range v {
			if s := formatLicense(l); s != "" {
				parts = append(parts, s)
			}
		}
		if len(parts) > 0 {
			return joinStrings(parts, ", ")
		}
		return ""
	case map[string]interface{}:
		for _, key := range []string{"value", "spdxExpression", "name", "license", "expression"} {
			if s, ok := v[key].(string); ok && s != "" {
				return s
			}
		}
		// Find first non-"declared" string value
		for _, val := range v {
			if s, ok := val.(string); ok && s != "declared" {
				return s
			}
		}
	}
	return ""
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func joinStrings(parts []string, sep string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += sep
		}
		result += p
	}
	return result
}
