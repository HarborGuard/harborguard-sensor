package adapter

import (
	"strings"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const sensorVersion = "0.1.0"

// BuildEnvelope constructs a ScanEnvelope from job and scan output.
func BuildEnvelope(job types.ScanJob, output *types.ScanOutput) *types.ScanEnvelope {
	var vulnerabilities []types.NormalizedVulnerability
	var packages []types.NormalizedPackage
	var compliance []types.NormalizedCompliance
	var efficiency []types.NormalizedEfficiency

	for scanner, result := range output.Results {
		if !result.Success || result.Data == nil {
			continue
		}
		data := result.Data

		switch scanner {
		case "trivy":
			vulnerabilities = append(vulnerabilities, ExtractTrivyVulnerabilities(data)...)
			packages = append(packages, ExtractTrivyPackages(data)...)
		case "grype":
			vulnerabilities = append(vulnerabilities, ExtractGrypeVulnerabilities(data)...)
		case "syft":
			packages = append(packages, ExtractSyftPackages(data)...)
		case "dockle":
			compliance = append(compliance, ExtractDockleCompliance(data)...)
		case "dive":
			efficiency = append(efficiency, ExtractDiveEfficiency(data)...)
		case "osv":
			vulnerabilities = append(vulnerabilities, ExtractOsvVulnerabilities(data)...)
		}
	}

	deduped := deduplicateVulnerabilities(vulnerabilities)

	// Count vulnerabilities
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	var totalCvss float64
	var cvssCount int
	for _, v := range deduped {
		key := strings.ToLower(v.Severity)
		if _, ok := counts[key]; ok {
			counts[key]++
		}
		if v.CvssScore != nil {
			totalCvss += *v.CvssScore
			cvssCount++
		}
	}

	avgCvss := 0.0
	if cvssCount > 0 {
		avgCvss = totalCvss / float64(cvssCount)
	}
	riskScore := CalculateRiskScore(counts, avgCvss)

	// Compliance score from dockle raw data
	var complianceScore *int
	var complianceGrade string
	if dockleResult, ok := output.Results["dockle"]; ok && dockleResult.Success {
		if cs, grade := calculateComplianceScore(dockleResult.Data); cs != nil {
			complianceScore = cs
			complianceGrade = grade
		}
	}

	// Determine status
	status := "PARTIAL"
	if output.Cancelled {
		status = "CANCELLED"
	} else {
		successCount := 0
		totalScanners := 0
		for _, r := range output.Results {
			totalScanners++
			if r.Success {
				successCount++
			}
		}
		if successCount == 0 {
			status = "FAILED"
		} else if successCount == totalScanners {
			status = "SUCCESS"
		}
	}

	name, tag := parseImageRef(job.ImageRef)

	// Ensure non-nil slices for JSON
	if deduped == nil {
		deduped = []types.NormalizedVulnerability{}
	}
	if packages == nil {
		packages = []types.NormalizedPackage{}
	}
	if compliance == nil {
		compliance = []types.NormalizedCompliance{}
	}
	if efficiency == nil {
		efficiency = []types.NormalizedEfficiency{}
	}

	return &types.ScanEnvelope{
		Version: "1.0",
		Sensor: types.EnvelopeSensor{
			Version:         sensorVersion,
			ScannerVersions: output.Metadata.ScannerVersions,
		},
		Image: types.EnvelopeImage{
			Ref:       job.ImageRef,
			Digest:    output.Metadata.ImageDigest,
			Platform:  output.Metadata.ImagePlatform,
			SizeBytes: output.Metadata.ImageSizeBytes,
			Name:      name,
			Tag:       tag,
		},
		Scan: types.EnvelopeScan{
			ID:         job.ID,
			StartedAt:  output.StartedAt,
			FinishedAt: output.FinishedAt,
			Status:     status,
		},
		Findings: types.EnvelopeFindings{
			Vulnerabilities: deduped,
			Packages:        packages,
			Compliance:      compliance,
			Efficiency:      efficiency,
		},
		Aggregates: types.EnvelopeAggregates{
			VulnerabilityCounts: types.VulnerabilityCounts{
				Critical: counts["critical"],
				High:     counts["high"],
				Medium:   counts["medium"],
				Low:      counts["low"],
				Info:     counts["info"],
			},
			RiskScore:       riskScore,
			ComplianceScore: complianceScore,
			ComplianceGrade: complianceGrade,
			TotalPackages:   len(packages),
		},
	}
}

func deduplicateVulnerabilities(vulns []types.NormalizedVulnerability) []types.NormalizedVulnerability {
	seen := make(map[string]types.NormalizedVulnerability)
	order := make([]string, 0)

	for _, vuln := range vulns {
		key := vuln.CveID + ":" + vuln.PackageName
		if existing, ok := seen[key]; ok {
			if SeverityOrder(vuln.Severity) < SeverityOrder(existing.Severity) {
				seen[key] = vuln
			}
		} else {
			seen[key] = vuln
			order = append(order, key)
		}
	}

	result := make([]types.NormalizedVulnerability, 0, len(order))
	for _, key := range order {
		result = append(result, seen[key])
	}
	return result
}

func calculateComplianceScore(data interface{}) (*int, string) {
	m, ok := data.(map[string]interface{})
	if !ok {
		return nil, ""
	}

	summary, ok := m["summary"].(map[string]interface{})
	if !ok {
		return nil, ""
	}

	fatal := toInt(summary["fatal"])
	warn := toInt(summary["warn"])
	info := toInt(summary["info"])
	pass := toInt(summary["pass"])

	total := fatal + warn + info + pass
	if total == 0 {
		return nil, ""
	}

	score := int((float64(pass) / float64(total)) * 100)
	grade := "D"
	if score >= 90 {
		grade = "A"
	} else if score >= 80 {
		grade = "B"
	} else if score >= 70 {
		grade = "C"
	}

	return &score, grade
}

func parseImageRef(ref string) (string, string) {
	parts := strings.Split(ref, "/")
	nameAndTag := parts[len(parts)-1]
	if strings.Contains(nameAndTag, ":") {
		split := strings.SplitN(nameAndTag, ":", 2)
		return split[0], split[1]
	}
	return nameAndTag, "latest"
}

func toInt(v interface{}) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return 0
}
