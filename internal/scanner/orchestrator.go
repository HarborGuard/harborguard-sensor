package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/storage"
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// Orchestrator runs multiple scanners against an image.
type Orchestrator struct {
	Config        *types.SensorConfig
	S3Storage     *storage.S3Storage
	RegistryCreds map[string]string // Extra env vars for registry auth (TRIVY_USERNAME, etc.)
}

// Execute runs all configured scanners for the given job.
// The provided context allows cancellation of in-flight scans.
func (o *Orchestrator) Execute(ctx context.Context, job types.ScanJob) (*types.ScanOutput, error) {
	startedAt := time.Now().UTC().Format(time.RFC3339)
	outputDir := filepath.Join(o.Config.WorkDir, "reports", job.ID)
	if err := os.MkdirAll(outputDir, 0700); err != nil {
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

	// For S3 source, download the tar first and run all scanners against it
	if job.Source.Type == "s3" {
		return o.executeS3(ctx, job, scanners, versionMap, startedAt, outputDir)
	}

	compatible, incompatible := PartitionBySourceSupport(scanners, job.Source)

	results := o.runParallel(ctx, compatible, job.Source, outputDir)

	// Check for cancellation before prefetch
	if ctx.Err() != nil {
		return o.buildCancelledOutput(job, startedAt, results, versionMap), nil
	}

	// For registry source, prefetch image and run incompatible scanners on tar
	if job.Source.Type == "registry" && len(incompatible) > 0 {
		names := make([]string, len(incompatible))
		for i, s := range incompatible {
			names[i] = s.Name()
		}
		fmt.Fprintf(os.Stderr, "[orchestrator] Prefetching %s for %d scanner(s): %v\n",
			job.Source.Ref, len(incompatible), names)
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
			var tarSize int64
			if fi, statErr := os.Stat(tarPath); statErr == nil {
				tarSize = fi.Size()
			}
			fmt.Fprintf(os.Stderr, "[orchestrator] Prefetch complete: %s (%d bytes). Running %v against tar.\n",
				tarPath, tarSize, names)
			// Run incompatible scanners against the tar
			tarSource := types.ImageSource{Type: "tar", Path: tarPath}
			tarResults := o.runParallel(ctx, incompatible, tarSource, outputDir)
			for name, result := range tarResults {
				outputFile := filepath.Join(outputDir, name+".json")
				var outSize int64
				if fi, statErr := os.Stat(outputFile); statErr == nil {
					outSize = fi.Size()
				}
				dataShape := describeDataShape(result.Data)
				fmt.Fprintf(os.Stderr, "[orchestrator] Scanner %s on tar: success=%t err=%q outfile=%dB data=%s\n",
					name, result.Success, result.Error, outSize, dataShape)
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

func (o *Orchestrator) executeS3(ctx context.Context, job types.ScanJob, scanners []Scanner, versionMap map[string]string, startedAt string, outputDir string) (*types.ScanOutput, error) {
	if o.S3Storage == nil {
		return nil, fmt.Errorf("S3 source requires S3 storage configuration")
	}

	fmt.Fprintf(os.Stderr, "[orchestrator] Downloading image tar from S3: %s\n", job.Source.S3Key)
	tarPath, err := o.fetchS3Image(ctx, job.Source, outputDir)
	if err != nil {
		if ctx.Err() != nil {
			results := make(map[string]*types.ScannerResult)
			return o.buildCancelledOutput(job, startedAt, results, versionMap), nil
		}
		return nil, fmt.Errorf("S3 download failed: %w", err)
	}
	defer os.Remove(tarPath)

	fmt.Fprintf(os.Stderr, "[orchestrator] Running all scanners against S3 tar: %s\n", job.Source.S3Key)
	tarSource := types.ImageSource{Type: "tar", Path: tarPath}
	results := o.runParallel(ctx, scanners, tarSource, outputDir)

	if ctx.Err() != nil {
		return o.buildCancelledOutput(job, startedAt, results, versionMap), nil
	}

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
	}, nil
}

func (o *Orchestrator) fetchS3Image(_ context.Context, source types.ImageSource, outputDir string) (string, error) {
	tarPath := filepath.Join(outputDir, "s3-image.tar")
	if err := o.S3Storage.DownloadToFile(source.S3Key, tarPath); err != nil {
		return "", fmt.Errorf("downloading from S3: %w", err)
	}
	return tarPath, nil
}

func (o *Orchestrator) prefetchRegistryImage(ctx context.Context, source types.ImageSource, outputDir string) (string, error) {
	tarPath := filepath.Join(outputDir, "prefetch.tar")
	ref := source.Ref

	// Invoke skopeo directly via argv. Passing --src-creds as a literal
	// argument avoids a /bin/sh -c expansion layer that has caused
	// hard-to-debug "invalid credentials" rejections on ECR.
	args := []string{"copy"}
	user, pass, credSource := resolveRegistryCredsSource(o.RegistryCreds)
	if user != "" {
		args = append(args, "--src-creds", user+":"+pass)
		fmt.Fprintf(os.Stderr, "[orchestrator] Prefetch auth: user=%s source=%s (pass=%d chars)\n",
			user, credSource, len(pass))
	} else {
		fmt.Fprintf(os.Stderr, "[orchestrator] Prefetch auth: anonymous (no credentials in RegistryCreds/REGISTRY_USER/TRIVY_USERNAME)\n")
	}
	args = append(args, "docker://"+ref, "docker-archive:"+tarPath)

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	var stderr strings.Builder
	cmd := exec.CommandContext(timeoutCtx, "skopeo", args...)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		return "", fmt.Errorf("prefetch failed: %w (stderr: %s)", err, msg)
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

// resolveRegistryCreds picks the user/pass pair for the skopeo source-pull in
// priority order:
//   1. Orchestrator.RegistryCreds (populated by agent.setupRegistryCreds from
//      dashboard-dispatched job credentials + discoverer fallback).
//   2. REGISTRY_USER / REGISTRY_PASS environment variables (CLI dispatch
//      convention used by the dashboard worker when spawning a Fly machine).
//   3. TRIVY_USERNAME / TRIVY_PASSWORD environment variables (fallback for
//      operators who pass trivy-style env only).
//
// Returns ("", "") when no credentials are available; skopeo will then try an
// anonymous pull, which is correct for public images.
func resolveRegistryCreds(rc map[string]string) (string, string) {
	u, p, _ := resolveRegistryCredsSource(rc)
	return u, p
}

// describeDataShape returns a compact description of a scanner's parsed Data
// field so operators can tell at a glance whether the JSON parsed but is
// structurally different from what the envelope adapters expect.
func describeDataShape(data interface{}) string {
	if data == nil {
		return "nil"
	}
	switch v := data.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		return fmt.Sprintf("object(%d keys: %v)", len(v), keys)
	case []interface{}:
		return fmt.Sprintf("array(%d elements)", len(v))
	default:
		return fmt.Sprintf("%T", v)
	}
}

// resolveRegistryCredsSource returns the same creds plus a label describing
// which source supplied them, for log visibility.
func resolveRegistryCredsSource(rc map[string]string) (string, string, string) {
	if u := rc["TRIVY_USERNAME"]; u != "" {
		return u, rc["TRIVY_PASSWORD"], "RegistryCreds"
	}
	if u := os.Getenv("REGISTRY_USER"); u != "" {
		return u, os.Getenv("REGISTRY_PASS"), "env:REGISTRY_USER"
	}
	if u := os.Getenv("TRIVY_USERNAME"); u != "" {
		return u, os.Getenv("TRIVY_PASSWORD"), "env:TRIVY_USERNAME"
	}
	return "", "", "none"
}
