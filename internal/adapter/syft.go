package adapter

import (
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// ExtractSyftPackages extracts normalized packages from syft JSON.
func ExtractSyftPackages(report interface{}) []types.NormalizedPackage {
	var findings []types.NormalizedPackage

	data, ok := report.(map[string]interface{})
	if !ok {
		return findings
	}

	artifacts, ok := data["artifacts"].([]interface{})
	if !ok {
		return findings
	}

	for _, a := range artifacts {
		artifact, ok := a.(map[string]interface{})
		if !ok {
			continue
		}

		pkgType := getString(artifact, "type")
		if pkgType == "" {
			pkgType = "unknown"
		}

		findings = append(findings, types.NormalizedPackage{
			Source:  "syft",
			Name:    getString(artifact, "name"),
			Version: getString(artifact, "version"),
			Type:    pkgType,
			Purl:    getString(artifact, "purl"),
			License: formatLicense(artifact["licenses"]),
		})
	}

	return findings
}
