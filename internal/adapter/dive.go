package adapter

import (
	"fmt"
	"sort"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const (
	largeLayerThreshold = 50 * 1024 * 1024  // 50MB
	hugeLayerThreshold  = 100 * 1024 * 1024 // 100MB
)

const maxTopFiles = 20

// ExtractDiveLayers extracts per-layer metadata from dive JSON output.
func ExtractDiveLayers(report interface{}) []types.EnvelopeLayer {
	var layers []types.EnvelopeLayer

	data, ok := report.(map[string]interface{})
	if !ok {
		return layers
	}

	rawLayers, ok := data["layer"].([]interface{})
	if !ok {
		return layers
	}

	for i, l := range rawLayers {
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

		command := getString(layer, "command")
		digest := getString(layer, "digestId")

		// Count files and collect top entries by size
		var fileCount int
		var topFiles []types.LayerFile

		if fileList, ok := layer["fileList"].([]interface{}); ok {
			fileCount = len(fileList)

			// Collect all files with size > 0, then pick top N
			type fileEntry struct {
				path   string
				size   int64
				status string
			}
			var entries []fileEntry

			for _, f := range fileList {
				fm, ok := f.(map[string]interface{})
				if !ok {
					continue
				}

				var fSize int64
				switch v := fm["size"].(type) {
				case float64:
					fSize = int64(v)
				case int64:
					fSize = v
				}

				fPath := getString(fm, "path")
				if fPath == "" {
					continue
				}

				// Determine status from typeFlag: 0=added, 1=modified, 2=removed
				status := "added"
				if tf, ok := fm["typeFlag"].(float64); ok {
					switch int(tf) {
					case 1:
						status = "modified"
					case 2:
						status = "removed"
					}
				}

				// Check isDir to skip directories
				if isDir, ok := fm["isDir"].(bool); ok && isDir {
					continue
				}

				entries = append(entries, fileEntry{path: fPath, size: fSize, status: status})
			}

			// Sort by size descending and take top N
			sort.Slice(entries, func(a, b int) bool {
				return entries[a].size > entries[b].size
			})
			limit := maxTopFiles
			if len(entries) < limit {
				limit = len(entries)
			}
			for _, e := range entries[:limit] {
				topFiles = append(topFiles, types.LayerFile{
					Path:   e.path,
					Size:   e.size,
					Status: e.status,
				})
			}
		}

		layers = append(layers, types.EnvelopeLayer{
			Index:     i,
			Digest:    digest,
			Command:   command,
			SizeBytes: sizeBytes,
			FileCount: fileCount,
			TopFiles:  topFiles,
		})
	}

	return layers
}

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
