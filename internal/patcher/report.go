package patcher

import (
	"encoding/json"
	"fmt"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// trivyReport is a minimal subset of the Trivy v2 JSON schema — only the
// fields Copa consumes when deciding which OS packages to upgrade.
type trivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Metadata      trivyMetadata `json:"Metadata"`
	Results       []trivyResult `json:"Results"`
}

type trivyMetadata struct {
	OS trivyOS `json:"OS"`
}

type trivyOS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

type trivyResult struct {
	Target          string              `json:"Target"`
	Class           string              `json:"Class"`
	Type            string              `json:"Type"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
}

// BuildTrivyReport constructs a synthetic Trivy-shaped JSON from a list of
// packages to upgrade. osType is one of "ubuntu", "debian", "alpine", "centos",
// "redhat", "amazon", "fedora", "oracle", "rocky", "almalinux", "cbl-mariner".
//
// All packages must share the same OS family (Copa groups by the Results[]
// Type field). If per-package packageManager values conflict, return an error.
func BuildTrivyReport(imageRef, osType string, pkgs []types.PatchPackage) ([]byte, error) {
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages to patch")
	}
	if osType == "" {
		return nil, fmt.Errorf("osType required")
	}

	// Confirm packageManager homogeneity when supplied.
	var pmSeen string
	for _, p := range pkgs {
		if p.PackageManager == "" {
			continue
		}
		if pmSeen == "" {
			pmSeen = p.PackageManager
			continue
		}
		if p.PackageManager != pmSeen {
			return nil, fmt.Errorf("mixed packageManager in one job not supported (%s vs %s)", pmSeen, p.PackageManager)
		}
	}

	vulns := make([]trivyVulnerability, 0, len(pkgs))
	for i, p := range pkgs {
		if p.Name == "" || p.TargetVersion == "" {
			return nil, fmt.Errorf("package[%d] missing name or targetVersion", i)
		}
		vulns = append(vulns, trivyVulnerability{
			VulnerabilityID:  fmt.Sprintf("HG-PATCH-%04d", i+1),
			PkgName:          p.Name,
			InstalledVersion: "",
			FixedVersion:     p.TargetVersion,
			Severity:         "UNKNOWN",
		})
	}

	report := trivyReport{
		SchemaVersion: 2,
		ArtifactName:  imageRef,
		ArtifactType:  "container_image",
		Metadata: trivyMetadata{
			OS: trivyOS{
				Family: osType,
				Name:   "",
			},
		},
		Results: []trivyResult{{
			Target:          fmt.Sprintf("%s (%s)", imageRef, osType),
			Class:           "os-pkgs",
			Type:            osType,
			Vulnerabilities: vulns,
		}},
	}
	return json.MarshalIndent(report, "", "  ")
}

// OSTypeFromPackageManager maps a packageManager hint to a Copa-compatible
// Trivy OS family string. Returns empty string for unknowns — callers should
// run osdetect in that case.
func OSTypeFromPackageManager(pm string) string {
	switch pm {
	case "apt":
		return "ubuntu" // Copa treats ubuntu/debian identically
	case "apk":
		return "alpine"
	case "yum":
		return "centos"
	case "dnf":
		return "fedora"
	default:
		return ""
	}
}
