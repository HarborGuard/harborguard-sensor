package adapter

import (
	"fmt"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const (
	largeLayerThreshold = 50 * 1024 * 1024  // 50MB
	hugeLayerThreshold  = 100 * 1024 * 1024 // 100MB
)

// ExtractDiveEfficiency extracts normalized efficiency findings from dive JSON.
func ExtractDiveEfficiency(report interface{}) []types.NormalizedEfficiency {
	var findings []types.NormalizedEfficiency

	data, ok := report.(map[string]interface{})
	if !ok {
		return findings
	}

	layers, ok := data["layer"].([]interface{})
	if !ok {
		return findings
	}

	for _, l := range layers {
		layer, ok := l.(map[string]interface{})
		if !ok {
			continue
		}

		var sizeBytes int64
		switch v := layer["sizeBytes"].(type) {
		case float64:
			sizeBytes = int64(v)
		case int64:
			sizeBytes = v
		}

		if sizeBytes > largeLayerThreshold {
			sizeMB := float64(sizeBytes) / (1024 * 1024)
			severity := "INFO"
			if sizeBytes > hugeLayerThreshold {
				severity = "WARNING"
			}

			command := getString(layer, "command")

			findings = append(findings, types.NormalizedEfficiency{
				Source:      "dive",
				FindingType: "large_layer",
				Title:       fmt.Sprintf("Large layer: %.2fMB", sizeMB),
				Severity:    severity,
				SizeBytes:   &sizeBytes,
				Details:     command,
			})
		}
	}

	return findings
}
