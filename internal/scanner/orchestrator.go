package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// Orchestrator runs multiple scanners against an image.
type Orchestrator struct {
	Config *types.SensorConfig
}

// Execute runs all configured scanners for the given job.
// The provided context allows cancellation of in-flight scans.
func (o *Orchestrator) Execute(ctx context.Context, job types.ScanJob) (*types.ScanOutput, error) {
	startedAt := time.Now().UTC().Format(time.RFC3339)
	outputDir := filepath.Join(o.Config.WorkDir, "reports", job.ID)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	scannerNames := job.Scanners
	if len(scannerNames) == 0 {
		scannerNames = o.Config.EnabledScanners
	}

	scanners := make([]Scanner, 0, len(scannerNames))
	for _, name := range scannerNames {
		s, err := NewScanner(name)
		if err != nil {
			return nil, err
		}
		scanners = append(scanners, s)
	}

	// Get versions concurrently
	versionMap := o.fetchVersions(scanners)

	compatible, incompatible := PartitionBySourceSupport(scanners, job.Source)

	results := o.runParallel(ctx, compatible, job.Source, outputDir)

	// Check for cancellation before prefetch
	if ctx.Err() != nil {
		return o.buildCancelledOutput(job, startedAt, results, versionMap), nil
	}

	// For registry source, prefetch image and run incompatible scanners on tar
	if job.Source.Type == "registry" && len(incompatible) > 0 {
		fmt.Fprintf(os.Stderr, "[orchestrator] Prefetching %s for %d incompatible scanner(s)...\n",
			job.Source.Ref, len(incompatible))
		tarPath, err := o.prefetchRegistryImage(ctx, job.Source, outputDir)
		if err != nil {
			if ctx.Err() != nil {
				return o.buildCancelledOutput(job, startedAt, results, versionMap), nil
			}
			fmt.Fprintf(os.Stderr, "[orchestrator] Prefetch failed: %s, skipping %d scanner(s)\n",
				err.Error(), len(incompatible))
			// Record as skipped
			for _, s := range incompatible {
				results[s.Name()] = &types.ScannerResult{
					Scanner: s.Name(), Success: false,
					Error: fmt.Sprintf("Prefetch failed: %s", err.Error()), DurationMs: 0,
				}
			}
		} else {
			// Run incompatible scanners against the tar
			tarSource := types.ImageSource{Type: "tar", Path: tarPath}
			tarResults := o.runParallel(ctx, incompatible, tarSource, outputDir)
			for name, result := range tarResults {
				results[name] = result
			}
			// Clean up tar file
			_ = os.Remove(tarPath)
		}
	} else {
		// Record skipped scanners (original behavior for non-registry)
		for _, s := range incompatible {
			results[s.Name()] = &types.ScannerResult{
				Scanner: s.Name(), Success: false,
				Error: fmt.Sprintf("Source type '%s' not supported", job.Source.Type), DurationMs: 0,
			}
		}
	}

	// Attach versions to results
	for name, version := range versionMap {
		if r, ok := results[name]; ok {
			r.Version = version
		}
	}

	metadata := extractImageMetadata(results)
	// Merge pre-fetched versions
	for name, version := range versionMap {
		if _, exists := metadata.ScannerVersions[name]; !exists {
			metadata.ScannerVersions[name] = version
		}
	}

	finishedAt := time.Now().UTC().Format(time.RFC3339)
	return &types.ScanOutput{
		JobID:      job.ID,
		ImageRef:   job.ImageRef,
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
		Results:    results,
		Metadata:   metadata,
	}, nil
}

func (o *Orchestrator) fetchVersions(scanners []Scanner) map[string]string {
	versions := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, s := range scanners {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()
			v := s.GetVersion()
			mu.Lock()
			versions[s.Name()] = v
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	return versions
}

func (o *Orchestrator) runParallel(ctx context.Context, scanners []Scanner, source types.ImageSource, outputDir string) map[string]*types.ScannerResult {
	results := make(map[string]*types.ScannerResult)
	var mu sync.Mutex

	batchSize := o.Config.MaxConcurrentScanners
	for i := 0; i < len(scanners); i += batchSize {
		// Skip remaining batches if cancelled
		if ctx.Err() != nil {
			for j := i; j < len(scanners); j++ {
				mu.Lock()
				results[scanners[j].Name()] = &types.ScannerResult{
					Scanner: scanners[j].Name(), Success: false, Error: "scan cancelled",
				}
				mu.Unlock()
			}
			break
		}

		end := i + batchSize
		if end > len(scanners) {
			end = len(scanners)
		}
		batch := scanners[i:end]

		var wg sync.WaitGroup
		for _, s := range batch {
			wg.Add(1)
			go func(s Scanner) {
				defer wg.Done()
				outputPath := filepath.Join(outputDir, s.Name()+".json")
				result, err := s.Scan(ctx, source, outputPath)
				if err != nil {
					result = &types.ScannerResult{
						Scanner: s.Name(),
						Success: false,
						Error:   err.Error(),
					}
				}
				mu.Lock()
				results[s.Name()] = result
				mu.Unlock()
			}(s)
		}
		wg.Wait()
	}

	return results
}

func (o *Orchestrator) prefetchRegistryImage(ctx context.Context, source types.ImageSource, outputDir string) (string, error) {
	tarPath := filepath.Join(outputDir, "prefetch.tar")
	ref := source.Ref

	cmd := fmt.Sprintf(`skopeo copy docker://%s docker-archive:%s`, ref, tarPath)
	_, _, err := ExecWithTimeout(ctx, cmd, 300000, nil)
	if err != nil {
		return "", fmt.Errorf("prefetch failed: %w", err)
	}
	return tarPath, nil
}

func (o *Orchestrator) buildCancelledOutput(job types.ScanJob, startedAt string, results map[string]*types.ScannerResult, versionMap map[string]string) *types.ScanOutput {
	for name, version := range versionMap {
		if r, ok := results[name]; ok {
			r.Version = version
		}
	}
	metadata := extractImageMetadata(results)
	for name, version := range versionMap {
		if _, exists := metadata.ScannerVersions[name]; !exists {
			metadata.ScannerVersions[name] = version
		}
	}
	finishedAt := time.Now().UTC().Format(time.RFC3339)
	return &types.ScanOutput{
		JobID:      job.ID,
		ImageRef:   job.ImageRef,
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
		Results:    results,
		Metadata:   metadata,
		Cancelled:  true,
	}
}

func extractImageMetadata(results map[string]*types.ScannerResult) types.ScanOutputMetadata {
	versions := make(map[string]string)
	var imageDigest, imagePlatform string
	var imageSizeBytes *int64

	for name, result := range results {
		if result.Version != "" {
			versions[name] = result.Version
		}

		if result.Data == nil || !result.Success {
			continue
		}

		data, ok := result.Data.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract metadata from Trivy output
		if name == "trivy" {
			if meta, ok := data["Metadata"].(map[string]interface{}); ok {
				if digests, ok := meta["RepoDigests"].([]interface{}); ok && len(digests) > 0 {
					if d, ok := digests[0].(string); ok {
						imageDigest = d
					}
				}
				var osName, arch string
				switch v := meta["OS"].(type) {
				case string:
					osName = v
				case map[string]interface{}:
					if f, ok := v["Family"].(string); ok {
						osName = f
					}
				}
				if a, ok := meta["Architecture"].(string); ok {
					arch = a
				}
				if osName != "" && arch != "" {
					imagePlatform = osName + "/" + arch
				}
				if cfg, ok := meta["ImageConfig"].(map[string]interface{}); ok {
					if s, ok := cfg["size"].(float64); ok {
						size := int64(s)
						imageSizeBytes = &size
					}
				}
			}
		}

		// Extract metadata from Syft output
		if name == "syft" && imageDigest == "" {
			if src, ok := data["source"].(map[string]interface{}); ok {
				if target, ok := src["target"].(map[string]interface{}); ok {
					if d, ok := target["digest"].(string); ok {
						imageDigest = d
					}
					if s, ok := target["imageSize"].(float64); ok && imageSizeBytes == nil {
						size := int64(s)
						imageSizeBytes = &size
					}
				}
			}
		}
	}

	return types.ScanOutputMetadata{
		ScannerVersions: versions,
		ImageDigest:     imageDigest,
		ImagePlatform:   imagePlatform,
		ImageSizeBytes:  imageSizeBytes,
	}
}
