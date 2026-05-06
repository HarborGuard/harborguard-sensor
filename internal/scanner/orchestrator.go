package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
//
// ScannerVersions is the per-scanner version-string cache. Agent mode
// populates it once at startup (in agent.RunAgentLoop) for every
// scanner.KnownScannerNames() entry, not just the operator-enabled
// set, so a dashboard-dispatched job that names any constructible
// scanner finds a hit without re-probing inside Execute. The map is
// treated as read-only after agent startup; fetchVersions only reads
// from it. Tests and direct callers (cmd/scan.go) may construct an
// Orchestrator with this field nil — fetchVersions then falls back to
// a synchronous GetVersion per scanner, single-shot rather than the
// previous concurrent fan-out that produced "unknown" versions on
// cold containers.
type Orchestrator struct {
	Config          *types.SensorConfig
	S3Storage       *storage.S3Storage
	RegistryCreds   map[string]string // Extra env vars for registry auth (TRIVY_USERNAME, etc.)
	ScannerVersions map[string]string

	// prefetchFn, if set, replaces the default skopeo-backed
	// prefetchRegistryImage. Tests use this to exercise the
	// concurrent prefetch + compatible-batch scheduling without
	// standing up an OCI registry. Production code leaves this nil
	// and the default (skopeo) implementation runs.
	prefetchFn func(ctx context.Context, source types.ImageSource, outputDir string) (string, error)

	// scannerFactory, if set, replaces NewScanner during Execute.
	// Lets tests substitute fake scanners without invoking real
	// trivy/grype/syft binaries. Production leaves this nil.
	scannerFactory func(name string) (Scanner, error)
}

func (o *Orchestrator) prefetch(ctx context.Context, source types.ImageSource, outputDir string) (string, error) {
	if o.prefetchFn != nil {
		return o.prefetchFn(ctx, source, outputDir)
	}
	return o.prefetchRegistryImage(ctx, source, outputDir)
}

// Execute runs all configured scanners for the given job.
// The provided context allows cancellation of in-flight scans.
func (o *Orchestrator) Execute(ctx context.Context, job types.ScanJob) (*types.ScanOutput, error) {
	// Dashboards occasionally embed a URL scheme in the image reference
	// (e.g. `http://host:5000/repo:tag`). Trivy, grype, skopeo and every
	// other tool we invoke parse this with go-containerregistry, which
	// rejects scheme-prefixed refs outright. Strip the scheme once here,
	// remember whether it was http (insecure), and let per-scanner command
	// builders emit the appropriate TLS-skip flag downstream. ScanJob is
	// passed by value so these mutations stay local.
	if normalized, insecure, changed := NormalizeImageRef(job.Source.Ref); changed {
		job.Source.Ref = normalized
		if insecure {
			job.Source.Insecure = true
		}
		fmt.Fprintf(os.Stderr, "[orchestrator] Stripped scheme from source ref: insecure=%t\n", job.Source.Insecure)
	}
	if normalized, _, changed := NormalizeImageRef(job.ImageRef); changed {
		job.ImageRef = normalized
	}

	startedAt := time.Now().UTC().Format(time.RFC3339)
	outputDir := filepath.Join(o.Config.WorkDir, "reports", job.ID)
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	scannerNames := job.Scanners
	if len(scannerNames) == 0 {
		scannerNames = o.Config.EnabledScanners
	}

	factory := o.scannerFactory
	if factory == nil {
		factory = NewScanner
	}
	scanners := make([]Scanner, 0, len(scannerNames))
	for _, name := range scannerNames {
		s, err := factory(name)
		if err != nil {
			return nil, err
		}
		scanners = append(scanners, s)
	}

	versionMap := o.fetchVersions(scanners)

	// For S3 source, download the tar first and run all scanners against it
	if job.Source.Type == "s3" {
		return o.executeS3(ctx, job, scanners, versionMap, startedAt, outputDir)
	}

	compatible, incompatible := PartitionBySourceSupport(scanners, job.Source)

	// Resolve the registry index/manifest digest BEFORE any scanner runs.
	// Trivy's RepoDigests reports the per-architecture leaf manifest digest
	// after Docker-style platform resolution, which:
	//   (a) includes a `repo@` prefix that pollutes the value, and
	//   (b) on registries like ECR is not directly addressable by digest —
	//       only the index/list digest is what `aws ecr describe-images`
	//       returns, and it's what `skopeo copy docker://repo@sha256:...`
	//       can resolve. For single-arch images, the manifest digest IS the
	//       index digest, so this is correct in both cases.
	//
	// `skopeo inspect --raw` returns the bytes of the manifest BEFORE
	// architecture resolution, so its sha256 is the digest the registry
	// itself indexes the tag under.
	preferredDigest := ""
	if job.Source.Type == "registry" {
		if d, err := o.resolveRegistryIndexDigest(ctx, job.Source); err != nil {
			fmt.Fprintf(os.Stderr, "[orchestrator] index digest resolution failed for %s: %v (will fall back to scanner-reported digest)\n",
				job.Source.Ref, err)
		} else {
			preferredDigest = d
			fmt.Fprintf(os.Stderr, "[orchestrator] resolved index digest for %s: %s\n", job.Source.Ref, d)
		}
	}

	// Concurrent-prefetch optimization:
	//
	// Historically, runParallel(compatible) ran to completion BEFORE
	// prefetchRegistryImage was called. On networks with degraded
	// outbound bandwidth (the May 2026 staging incident, see RCA),
	// scanners that talk to the registry directly (Trivy/Grype/OSV)
	// would each pull the image themselves, then we'd still pay the
	// full skopeo prefetch wallclock afterwards before Syft/Dockle/Dive
	// could start. The two batches share zero network artifacts but
	// were serialized.
	//
	// Now: kick off prefetch in a goroutine concurrent with the
	// compatible batch (only for "registry" sources with incompatible
	// scanners to feed; other source types still take the original
	// inline path). The result lands on prefetchCh which the
	// post-compatible-batch code drains before running the incompatible
	// batch against the tar. ctx propagation keeps the goroutine from
	// being orphaned if the compatible batch fails or the parent
	// cancels.
	type prefetchOutcome struct {
		tarPath string
		err     error
	}
	prefetchActive := job.Source.Type == "registry" && len(incompatible) > 0
	var prefetchCh chan prefetchOutcome
	if prefetchActive {
		names := make([]string, len(incompatible))
		for i, s := range incompatible {
			names[i] = s.Name()
		}
		fmt.Fprintf(os.Stderr, "[orchestrator] Prefetching %s for %d scanner(s) concurrently with compatible batch: %v\n",
			job.Source.Ref, len(incompatible), names)
		prefetchCh = make(chan prefetchOutcome, 1)
		go func() {
			tarPath, err := o.prefetch(ctx, job.Source, outputDir)
			prefetchCh <- prefetchOutcome{tarPath: tarPath, err: err}
		}()
	}

	// For pre-supplied tar sources (CLI dispatch with a local archive),
	// emit telemetry up front. Registry sources are handled after prefetch
	// completes; S3 sources are handled in executeS3.
	if job.Source.Type == "tar" && job.Source.Path != "" {
		emitJavaTelemetry(job.ID, job.ImageRef, job.Source.Path)
	}

	results := o.runParallel(ctx, compatible, job.Source, outputDir)

	// Check for cancellation before consuming prefetch
	if ctx.Err() != nil {
		// Drain the prefetch goroutine so it doesn't leak. The
		// underlying skopeo CommandContext is bound to ctx and will
		// terminate; we just have to wait for the channel send.
		if prefetchActive {
			outcome := <-prefetchCh
			if outcome.tarPath != "" {
				_ = os.Remove(outcome.tarPath)
			}
		}
		return o.buildCancelledOutput(job, startedAt, results, versionMap), nil
	}

	// For registry source, run incompatible scanners on the prefetched tar
	if prefetchActive {
		names := make([]string, len(incompatible))
		for i, s := range incompatible {
			names[i] = s.Name()
		}
		outcome := <-prefetchCh
		tarPath, err := outcome.tarPath, outcome.err
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
			// Always-on telemetry: count Java-bearing files in the
			// prefetched tar so we can size bake-vs-fetch tradeoffs
			// for the trivy java-db. Cheap walk, errors logged inline.
			emitJavaTelemetry(job.ID, job.ImageRef, tarPath)
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
	// The registry-resolved index digest, if we got one, is canonical:
	// it's a bare `sha256:<hex>` that the registry itself addresses the
	// tag by. Prefer it over Trivy's per-arch RepoDigests value (which
	// also carries a `repo@` prefix and resolves to the per-arch leaf,
	// not the index — ECR rejects the leaf as `manifest unknown`).
	if preferredDigest != "" {
		metadata.ImageDigest = preferredDigest
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

// fetchVersions returns the version string for each requested scanner,
// reading from the per-orchestrator cache populated at agent startup.
// Falls back to a synchronous GetVersion probe for any scanner the
// cache doesn't know about — this should only happen for direct
// callers (e.g. tests) that constructed an Orchestrator without
// pre-warming the cache; in agent mode every scanner the dashboard
// can dispatch was already probed once at registration.
//
// Used to be a goroutine-per-scanner fan-out with no concurrency cap.
// On cold containers six concurrent fork+execs of `<tool> --version`
// (each pulling 50–100 MB of binary off disk for the first time, with
// trivy additionally reading its DB cache to print DB versions) would
// race past GetToolVersion's 10 s timeout and report "unknown". The
// asymmetry was particularly odd because runParallel below already
// honors MaxConcurrentScanners — the version probe didn't.
func (o *Orchestrator) fetchVersions(scanners []Scanner) map[string]string {
	versions := make(map[string]string, len(scanners))
	for _, s := range scanners {
		if v, ok := o.ScannerVersions[s.Name()]; ok {
			versions[s.Name()] = v
			continue
		}
		// Cache miss — synchronous probe. Single-shot, so the
		// concurrent-fan-out hazard doesn't reappear here.
		versions[s.Name()] = s.GetVersion()
	}
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
				// Successful scanner runs were previously silent — only
				// failures emitted log lines. That made `flyctl logs`
				// useless for diagnosing slow-but-successful scans
				// because timings only lived inside the JSON envelope
				// uploaded at the end. Log start/finish at INFO so
				// per-scanner wallclock is visible in real time.
				fmt.Fprintf(os.Stderr, "[scanner] %s started source=%s\n", s.Name(), source.Type)
				scanStart := time.Now()
				result, err := s.Scan(ctx, source, outputPath)
				durMs := time.Since(scanStart).Milliseconds()
				if err != nil {
					result = &types.ScannerResult{
						Scanner: s.Name(),
						Success: false,
						Error:   err.Error(),
					}
				}
				if result != nil && result.Success {
					fmt.Fprintf(os.Stderr, "[scanner] %s finished duration_ms=%d exit_code=0\n", s.Name(), durMs)
				} else {
					errMsg := ""
					if result != nil {
						errMsg = result.Error
					} else if err != nil {
						errMsg = err.Error()
					}
					fmt.Fprintf(os.Stderr, "[scanner] %s failed duration_ms=%d error=%q\n", s.Name(), durMs, errMsg)
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
	emitJavaTelemetry(job.ID, job.ImageRef, tarPath)
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
	if source.Insecure {
		args = append(args, "--src-tls-verify=false")
	}
	user, pass, credSource := resolveRegistryCredsSource(o.RegistryCreds)
	if user != "" {
		args = append(args, "--src-creds", user+":"+pass)
		fmt.Fprintf(os.Stderr, "[orchestrator] Prefetch auth: user=%s source=%s (pass=%d chars) insecure=%t\n",
			user, credSource, len(pass), source.Insecure)
	} else {
		fmt.Fprintf(os.Stderr, "[orchestrator] Prefetch auth: anonymous (no credentials in RegistryCreds/REGISTRY_USER/TRIVY_USERNAME) insecure=%t\n",
			source.Insecure)
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
						// Trivy reports `<repo>@sha256:<hex>` (and the
						// digest is the per-arch leaf, not the index).
						// Strip the `repo@` prefix so consumers get a
						// bare `sha256:<hex>`. Caller in Execute may
						// override this with the registry-resolved
						// index digest, which is preferred.
						imageDigest = normalizeDigestRef(d)
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
						imageDigest = normalizeDigestRef(d)
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

// NormalizeImageRef strips a URL scheme from an image reference and reports
// whether the scheme was http (insecure). Scanners and skopeo all reject
// scheme-prefixed refs; the boolean drives per-tool TLS-skip flags.
//
// Returns the normalized ref, whether it was http (insecure), and whether
// anything was actually trimmed — callers use the third value to avoid
// emitting noisy "stripped scheme" log lines when nothing changed.
// Exported so callers upstream of Execute (agent loop, cmd) can normalize
// once at the boundary rather than only inside the orchestrator, which
// keeps the scheme out of the envelope displayed on the dashboard.
func NormalizeImageRef(ref string) (string, bool, bool) {
	switch {
	case strings.HasPrefix(ref, "http://"):
		return strings.TrimPrefix(ref, "http://"), true, true
	case strings.HasPrefix(ref, "https://"):
		return strings.TrimPrefix(ref, "https://"), false, true
	default:
		return ref, false, false
	}
}

// normalizeDigestRef strips a `repo@` prefix from a digest ref. Some scanners
// (Trivy's RepoDigests, syft's target.digest in some shapes) report the
// fully-qualified `<repo>@sha256:<hex>` form; downstream consumers want a
// bare `sha256:<hex>`. We deliberately don't attempt to validate the hex —
// callers can do that — only chop everything up to and including the last
// `@`. Inputs already in `sha256:<hex>` form pass through unchanged.
func normalizeDigestRef(d string) string {
	if at := strings.LastIndex(d, "@"); at >= 0 {
		return d[at+1:]
	}
	return d
}

// resolveRegistryIndexDigest fetches the raw manifest bytes for the source ref
// and returns their sha256 in `sha256:<hex>` form. This is the digest the
// registry itself indexes the tag under — for multi-arch images it's the
// index/list digest, for single-arch it's the manifest digest. In both cases
// `skopeo copy docker://<repo>@sha256:<digest>` resolves successfully, which
// is the property the AI-triage path depends on.
//
// We invoke skopeo with `inspect --raw` so no architecture resolution
// happens; the bytes we hash are exactly what the registry served. The same
// credential plumbing as prefetchRegistryImage is used so private registries
// (ECR, GCR, Harbor) work.
func (o *Orchestrator) resolveRegistryIndexDigest(ctx context.Context, source types.ImageSource) (string, error) {
	args := []string{"inspect", "--raw"}
	if source.Insecure {
		args = append(args, "--tls-verify=false")
	}
	user, pass, _ := resolveRegistryCredsSource(o.RegistryCreds)
	if user != "" {
		args = append(args, "--creds", user+":"+pass)
	}
	args = append(args, "docker://"+source.Ref)

	timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(timeoutCtx, "skopeo", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		return "", fmt.Errorf("skopeo inspect --raw: %w (stderr: %s)", err, msg)
	}

	raw := stdout.Bytes()
	if len(raw) == 0 {
		return "", fmt.Errorf("skopeo inspect --raw returned empty body")
	}

	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
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
