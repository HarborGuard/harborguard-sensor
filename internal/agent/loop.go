package agent

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"strings"
	"syscall"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/adapter"
	"github.com/HarborGuard/harborguard-sensor/internal/patcher"
	"github.com/HarborGuard/harborguard-sensor/internal/registry"
	"github.com/HarborGuard/harborguard-sensor/internal/scanner"
	"github.com/HarborGuard/harborguard-sensor/internal/storage"
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const sensorVersion = "0.1.0"

// RunAgentLoop starts the agent registration, heartbeat, and poll loop.
func RunAgentLoop(ctx context.Context, cfg *types.SensorConfig) error {
	if cfg.DashboardURL == "" || cfg.APIKey == "" {
		return fmt.Errorf("Agent mode requires HG_DASHBOARD_URL and HG_API_KEY")
	}

	client := NewAgentClient(cfg.DashboardURL, cfg.APIKey)
	var s3store *storage.S3Storage
	if cfg.S3Bucket != "" && cfg.S3AccessKey != "" && cfg.S3SecretKey != "" {
		var err error
		s3store, err = storage.NewS3Storage(types.S3Config{
			Endpoint:  cfg.S3Endpoint,
			Bucket:    cfg.S3Bucket,
			AccessKey: cfg.S3AccessKey,
			SecretKey: cfg.S3SecretKey,
			Region:    cfg.S3Region,
		})
		if err != nil {
			return fmt.Errorf("initializing S3: %w", err)
		}
	}

	orch := &scanner.Orchestrator{Config: cfg, S3Storage: s3store}

	// Initialize registry discoverer (if configured)
	var discoverer *registry.Discoverer
	if cfg.RegistryURL != "" {
		var discErr error
		discoverer, discErr = registry.NewDiscoverer(types.RegistryConfig{
			URL:                 cfg.RegistryURL,
			Username:            cfg.RegistryUsername,
			Token:               cfg.RegistryToken,
			DiscoveryIntervalMs: cfg.DiscoveryIntervalMs,
		})
		if discErr != nil {
			fmt.Fprintf(os.Stderr, "[agent] Registry discoverer initialization failed: %s\n", discErr.Error())
		} else {
			fmt.Fprintf(os.Stderr, "[agent] Registry discovery enabled for %s (%s)\n",
				cfg.RegistryURL, discoverer.ProviderName())
		}
	}

	scannerVersions := getScannerVersions(cfg.EnabledScanners)

	// Register
	agentName := cfg.AgentName
	if agentName == "" {
		agentName, _ = os.Hostname()
	}

	capabilities := []string{types.CapScan}
	if discoverer != nil {
		capabilities = append(capabilities, types.CapDiscovery)
	}

	// Patch capability probe. The sensor shells out to buildah per job; no
	// long-lived helper daemon to supervise. When probe fails the sensor
	// registers without "patch" and the dashboard will never dispatch patch
	// jobs to it.
	var patcherInstance *patcher.Patcher
	if canPatch, reason := patcher.Probe(); canPatch {
		fmt.Fprintf(os.Stderr, "[agent] %s\n", reason)
		capabilities = append(capabilities, types.CapPatch)
		sensorCreds := resolveSensorRegistryCreds(ctx, discoverer)
		patcherInstance = &patcher.Patcher{
			Config:              cfg,
			S3Storage:           s3store,
			SensorRegistryCreds: sensorCreds,
		}
	} else {
		fmt.Fprintf(os.Stderr, "[agent] patch capability disabled: %s\n", reason)
	}

	agentID, err := registerWithRetry(client, types.AgentRegistration{
		Name:            agentName,
		Version:         sensorVersion,
		Hostname:        hostname(),
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		ScannerVersions: scannerVersions,
		Capabilities:    capabilities,
		S3Configured:    cfg.S3Bucket != "",
		RegistryURL:     cfg.RegistryURL,
		SensorID:        cfg.SensorID,
	}, 10)
	if err != nil {
		return fmt.Errorf("registering agent: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[agent] Registered as %s\n", agentID)

	fmt.Fprintln(os.Stderr, "[agent] Warming up scanner databases...")
	warmupScannerDBs()
	fmt.Fprintln(os.Stderr, "[agent] Scanner databases ready")

	// Context with signal handling
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Heartbeat ticker
	startTime := time.Now()
	activeJobs := 0

	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-heartbeatTicker.C:
				status := "idle"
				if activeJobs > 0 {
					status = "scanning"
				}
				hb := types.AgentHeartbeat{
					AgentID:       agentID,
					Status:        status,
					ActiveScans:   activeJobs,
					UptimeSeconds: int64(time.Since(startTime).Seconds()),
				}
				if err := client.Heartbeat(hb); err != nil {
					fmt.Fprintf(os.Stderr, "[agent] Heartbeat failed: %s\n", err.Error())
				}
			}
		}
	}()

	// Discovery loop (if registry is configured)
	if discoverer != nil {
		discoveryInterval := time.Duration(cfg.DiscoveryIntervalMs) * time.Millisecond
		go func() {
			// Run first discovery immediately
			runDiscovery(ctx, client, discoverer, agentID, cfg.RegistryURL)

			discoveryTicker := time.NewTicker(discoveryInterval)
			defer discoveryTicker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-discoveryTicker.C:
					runDiscovery(ctx, client, discoverer, agentID, cfg.RegistryURL)
				}
			}
		}()
	}

	// Cancel tracking for in-flight jobs
	var cancelMu sync.Mutex
	cancelMap := make(map[string]context.CancelFunc)

	// Poll loop
	fmt.Fprintln(os.Stderr, "[agent] Polling for jobs...")
	pollInterval := time.Duration(cfg.PollIntervalMs) * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "[agent] Shutting down...")
			return nil
		default:
		}

		resp, err := client.PollJobs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[agent] Poll failed: %s\n", err.Error())
		} else {
			// Process cancel signals
			for _, cancelJobID := range resp.CancelJobs {
				cancelMu.Lock()
				if cancelFn, ok := cancelMap[cancelJobID]; ok {
					fmt.Fprintf(os.Stderr, "[agent] Cancelling job: %s\n", cancelJobID)
					cancelFn()
				}
				cancelMu.Unlock()
			}

			for _, job := range resp.Jobs {
				jobType := strings.ToLower(job.Type)
				switch {
				case jobType == "scan" && job.Scan != nil:
					jobCtx, jobCancel := context.WithCancel(ctx)
					cancelMu.Lock()
					cancelMap[job.ID] = jobCancel
					cancelMu.Unlock()

					activeJobs++
					processJob(jobCtx, client, orch, s3store, job, discoverer)
					activeJobs--

					cancelMu.Lock()
					delete(cancelMap, job.ID)
					cancelMu.Unlock()
					jobCancel()

				case jobType == "patch" && job.Patch != nil:
					if patcherInstance == nil {
						msg := "patch job received but sensor has no patch capability"
						fmt.Fprintf(os.Stderr, "[agent] %s (job=%s)\n", msg, job.ID)
						_ = client.ReportJobStatus(job.ID, "failed", msg)
						continue
					}
					jobCtx, jobCancel := context.WithCancel(ctx)
					cancelMu.Lock()
					cancelMap[job.ID] = jobCancel
					cancelMu.Unlock()

					activeJobs++
					processPatchJob(jobCtx, client, patcherInstance, job)
					activeJobs--

					cancelMu.Lock()
					delete(cancelMap, job.ID)
					cancelMu.Unlock()
					jobCancel()
				}
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(pollInterval):
		}
	}
}

func processJob(ctx context.Context, client *AgentClient, orch *scanner.Orchestrator, s3store *storage.S3Storage, job types.AgentJob, discoverer *registry.Discoverer) {
	scan := job.Scan

	// Normalize once at the boundary so the envelope uploaded to the
	// dashboard — as well as every log line — shows a clean
	// `host:port/repo:tag` ref rather than the dashboard's raw
	// `http://host:port/repo:tag`. The orchestrator still normalizes
	// defensively, but doing it here threads the normalized ref through
	// BuildEnvelope (which reads ImageRef directly into Image.Ref / name
	// / tag). Without this the UI card keeps showing the scheme-prefixed
	// ref even though the scan itself runs correctly.
	imageRef, insecure, _ := scanner.NormalizeImageRef(scan.ImageRef)

	fmt.Fprintf(os.Stderr, "[agent] Starting scan: %s\n", imageRef)

	// Clean up report directory when job completes
	reportDir := filepath.Join(orch.Config.WorkDir, "reports", job.ID)
	defer func() {
		if err := os.RemoveAll(reportDir); err != nil {
			fmt.Fprintf(os.Stderr, "[agent] Failed to clean up report dir %s: %s\n", reportDir, err.Error())
		}
	}()

	// Resolve registry credentials for scanner passthrough
	setupRegistryCreds(ctx, orch, scan, discoverer)
	defer func() {
		orch.RegistryCreds = nil
		scanner.SetExtraEnv(nil)
	}()

	source := resolveImageSource(scan)
	source.Ref = imageRef
	if insecure {
		source.Insecure = true
	}
	output, err := orch.Execute(ctx, types.ScanJob{
		ID:       job.ID,
		ImageRef: imageRef,
		Source:   source,
		Scanners: scan.Scanners,
	})
	if err != nil {
		msg := err.Error()
		fmt.Fprintf(os.Stderr, "[agent] Scan failed: %s\n", msg)
		if reportErr := client.ReportJobStatus(job.ID, "failed", msg); reportErr != nil {
			fmt.Fprintf(os.Stderr, "[agent] Status report (failed) did not reach dashboard: %s\n", reportErr.Error())
		}
		return
	}

	// If cancelled, report status and skip uploads
	if output.Cancelled {
		fmt.Fprintf(os.Stderr, "[agent] Scan cancelled: %s\n", imageRef)
		if reportErr := client.ReportJobStatus(job.ID, "cancelled", ""); reportErr != nil {
			fmt.Fprintf(os.Stderr, "[agent] Status report (cancelled) did not reach dashboard: %s\n", reportErr.Error())
		}
		return
	}

	envelope := adapter.BuildEnvelope(
		types.ScanJob{ID: job.ID, ImageRef: imageRef, Source: source},
		output,
	)

	// Upload to S3 if configured
	if s3store != nil {
		rawResults := make(map[string]string)
		for scannerName, result := range output.Results {
			if result.Data != nil {
				key, uploadErr := s3store.UploadRawResult(job.ID, scannerName, result.Data)
				if uploadErr == nil {
					rawResults[scannerName] = key
				}
			}
		}

		var sbom string
		if syftResult, ok := output.Results["syft"]; ok && syftResult.Data != nil {
			if key, uploadErr := s3store.UploadSbom(job.ID, syftResult.Data); uploadErr == nil {
				sbom = key
			}
		}

		envelope.Artifacts = &types.EnvelopeArtifacts{
			S3Prefix:   fmt.Sprintf("scans/%s/", job.ID),
			RawResults: rawResults,
			Sbom:       sbom,
		}

		_, _ = s3store.UploadScanResults(job.ID, envelope)
	}

	// Push results to dashboard. Upload the envelope even when every
	// scanner failed so operators can see the per-scanner error messages
	// on the dashboard — but flag the job as failed, not completed,
	// below. Without this the dashboard previously displayed "COMPLETED
	// with 0 findings" for scans where no scanner actually ran.
	if _, _, err := client.UploadResults(envelope); err != nil {
		fmt.Fprintf(os.Stderr, "[agent] Upload failed: %s\n", err.Error())
		if reportErr := client.ReportJobStatus(job.ID, "failed", err.Error()); reportErr != nil {
			fmt.Fprintf(os.Stderr, "[agent] Status report (failed) did not reach dashboard: %s\n", reportErr.Error())
		}
		return
	}

	if failureMsg := summarizeScannerFailures(output.Results); failureMsg != "" {
		fmt.Fprintf(os.Stderr, "[agent] All scanners failed for %s: %s\n", imageRef, failureMsg)
		if err := client.ReportJobStatus(job.ID, "failed", failureMsg); err != nil {
			fmt.Fprintf(os.Stderr, "[agent] Status report failed: %s\n", err.Error())
		}
		return
	}

	if err := client.ReportJobStatus(job.ID, "completed", ""); err != nil {
		fmt.Fprintf(os.Stderr, "[agent] Status report failed: %s\n", err.Error())
	}
	fmt.Fprintf(os.Stderr, "[agent] Scan complete: %s\n", imageRef)
}

// summarizeScannerFailures returns an error message suitable for reporting
// `failed` status when every scanner in the run failed. Returns "" when at
// least one scanner succeeded — the job is then reported as `completed`
// with PARTIAL envelope status supplying per-scanner detail.
func summarizeScannerFailures(results map[string]*types.ScannerResult) string {
	if len(results) == 0 {
		return "no scanners produced results"
	}
	var failed []string
	for name, r := range results {
		if r == nil || !r.Success {
			msg := "unknown error"
			if r != nil && r.Error != "" {
				msg = r.Error
			}
			failed = append(failed, name+": "+msg)
		}
	}
	if len(failed) != len(results) {
		return "" // at least one succeeded — treat as completed/partial
	}
	return "all scanners failed (" + strings.Join(failed, "; ") + ")"
}

func processPatchJob(ctx context.Context, client *AgentClient, p *patcher.Patcher, job types.AgentJob) {
	patch := *job.Patch // copy so our mutations don't leak into the poll-response struct

	// Normalize source and sink registry refs once at the boundary. Without
	// this, `docker://` + "http://..." produces an invalid skopeo URI and
	// skopeo copy fails with "Invalid source name". The nested patch value
	// is a copy, so these mutations stay local to this job.
	if normalized, insecure, _ := scanner.NormalizeImageRef(patch.Source.Ref); normalized != patch.Source.Ref {
		patch.Source.Ref = normalized
		if insecure {
			patch.Source.Insecure = true
		}
	}
	if patch.Sink.Kind == "registry" && patch.Sink.Registry != nil {
		spec := *patch.Sink.Registry
		if normalized, insecure, _ := scanner.NormalizeImageRef(spec.Ref); normalized != spec.Ref {
			spec.Ref = normalized
			if insecure {
				spec.Insecure = true
			}
			patch.Sink.Registry = &spec
		}
	}

	fmt.Fprintf(os.Stderr, "[agent] Starting patch: %s -> sink=%s\n", patch.Source.Ref, patch.Sink.Kind)

	envelope, err := p.Execute(ctx, types.PatchJob{
		ID:  job.ID,
		Job: patch,
	})
	if err != nil {
		msg := err.Error()
		fmt.Fprintf(os.Stderr, "[agent] Patch failed: %s\n", msg)
		if reportErr := client.ReportJobStatus(job.ID, "failed", msg); reportErr != nil {
			fmt.Fprintf(os.Stderr, "[agent] Patch status report (failed) did not reach dashboard: %s\n", reportErr.Error())
		}
		return
	}

	if _, err := client.UploadPatchResult(envelope); err != nil {
		fmt.Fprintf(os.Stderr, "[agent] Patch upload failed: %s\n", err.Error())
		if reportErr := client.ReportJobStatus(job.ID, "failed", err.Error()); reportErr != nil {
			fmt.Fprintf(os.Stderr, "[agent] Patch status report (failed) did not reach dashboard: %s\n", reportErr.Error())
		}
		return
	}

	// A patch where every package install failed still produces a
	// docker-archive and pushes to the sink (buildah commits the
	// unmodified container), so runBuildah returns (result, nil) — the
	// dashboard previously saw this as a successful completion. Flip to
	// "failed" when the envelope itself carries Patch.Status=FAILED so
	// the patch_operations row reflects reality. PARTIAL still reports
	// as "completed" — some packages did land.
	status := "completed"
	errMsg := ""
	if envelope.Patch.Status == "FAILED" {
		status = "failed"
		errMsg = "all packages failed to install (see result entries)"
	}
	if err := client.ReportJobStatus(job.ID, status, errMsg); err != nil {
		fmt.Fprintf(os.Stderr, "[agent] Patch status report (%s) did not reach dashboard: %s\n", status, err.Error())
	}
	fmt.Fprintf(os.Stderr, "[agent] Patch %s: %s -> %s\n", status, patch.Source.Ref, envelope.Sink.Location)
}

// resolveSensorRegistryCreds pulls out the sensor-level registry credentials
// (e.g. from the registry discoverer) for use as a fallback when a patch job
// doesn't supply its own. Returns nil if unavailable.
func resolveSensorRegistryCreds(ctx context.Context, discoverer *registry.Discoverer) *types.RegistryCredentials {
	if discoverer == nil {
		return nil
	}
	resolved, err := discoverer.GetCredentials(ctx)
	if err != nil || resolved == nil {
		return nil
	}
	return &types.RegistryCredentials{
		Username: resolved.Username,
		Password: resolved.Password,
	}
}

func resolveImageSource(scan *types.AgentJobScan) types.ImageSource {
	switch scan.Source {
	case "tar":
		return types.ImageSource{Type: "tar", Path: scan.TarPath}
	case "registry":
		return types.ImageSource{Type: "registry", Ref: scan.ImageRef}
	case "s3":
		return types.ImageSource{Type: "s3", Ref: scan.ImageRef, S3Key: scan.S3Key}
	default:
		return types.ImageSource{Type: "docker", Ref: scan.ImageRef}
	}
}

func runDiscovery(ctx context.Context, client *AgentClient, discoverer *registry.Discoverer, agentID, registryURL string) {
	report := types.CatalogReport{
		AgentID:      agentID,
		RegistryURL:  registryURL,
		Provider:     string(discoverer.ProviderName()),
		DiscoveredAt: time.Now().UTC().Format(time.RFC3339),
	}

	repos, err := discoverer.Discover(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return // shutting down
		}
		fmt.Fprintf(os.Stderr, "[discovery] Discovery failed: %s\n", err.Error())
		report.Error = err.Error()
		report.Repositories = []types.DiscoveredRepository{}
	} else {
		report.Repositories = repos
	}

	if err := client.ReportCatalog(report); err != nil {
		fmt.Fprintf(os.Stderr, "[discovery] Failed to report catalog: %s\n", err.Error())
	} else {
		totalTags := 0
		for _, r := range report.Repositories {
			totalTags += len(r.Tags)
		}
		fmt.Fprintf(os.Stderr, "[discovery] Catalog reported: %d repositories, %d tags\n",
			len(report.Repositories), totalTags)
	}
}

func setupRegistryCreds(ctx context.Context, orch *scanner.Orchestrator, scan *types.AgentJobScan, discoverer *registry.Discoverer) {
	var creds map[string]string

	// Job-level credentials take precedence
	if scan.RegistryCredentials != nil && scan.RegistryCredentials.Username != "" {
		creds = map[string]string{
			"TRIVY_USERNAME":                 scan.RegistryCredentials.Username,
			"TRIVY_PASSWORD":                 scan.RegistryCredentials.Password,
			"GRYPE_REGISTRY_AUTH_USERNAME":   scan.RegistryCredentials.Username,
			"GRYPE_REGISTRY_AUTH_PASSWORD":   scan.RegistryCredentials.Password,
			"SYFT_REGISTRY_AUTH_USERNAME":    scan.RegistryCredentials.Username,
			"SYFT_REGISTRY_AUTH_PASSWORD":    scan.RegistryCredentials.Password,
		}
	} else if discoverer != nil && scan.Source == "registry" {
		// Use sensor-level credentials from the discoverer
		resolved, err := discoverer.GetCredentials(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[agent] Failed to resolve registry creds for passthrough: %s\n", err.Error())
		} else if resolved != nil {
			creds = map[string]string{
				"TRIVY_USERNAME":                 resolved.Username,
				"TRIVY_PASSWORD":                 resolved.Password,
				"GRYPE_REGISTRY_AUTH_USERNAME":   resolved.Username,
				"GRYPE_REGISTRY_AUTH_PASSWORD":   resolved.Password,
				"SYFT_REGISTRY_AUTH_USERNAME":    resolved.Username,
				"SYFT_REGISTRY_AUTH_PASSWORD":    resolved.Password,
			}
		}
	}

	if creds != nil {
		orch.RegistryCreds = creds
		scanner.SetExtraEnv(creds)
	}
}

func getScannerVersions(scannerNames []string) map[string]string {
	versions := make(map[string]string)
	for _, name := range scannerNames {
		s, err := scanner.NewScanner(name)
		if err != nil {
			continue
		}
		versions[name] = s.GetVersion()
	}
	return versions
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func warmupScannerDBs() {
	// Check if trivy DB exists
	trivyCacheDir := os.Getenv("TRIVY_CACHE_DIR")
	if trivyCacheDir == "" {
		trivyCacheDir = "/workspace/cache/trivy"
	}
	trivyExists := dbDirHasContent(filepath.Join(trivyCacheDir, "db"))

	// Check if grype DB exists
	grypeCacheDir := os.Getenv("GRYPE_DB_CACHE_DIR")
	if grypeCacheDir == "" {
		grypeCacheDir = "/workspace/cache/grype"
	}
	grypeExists := dbDirHasContent(grypeCacheDir)

	type dbCmd struct {
		name string
		cmd  string
	}

	var toWarm []dbCmd
	if trivyExists {
		fmt.Fprintln(os.Stderr, "[agent] trivy DB already present, skipping download")
	} else {
		toWarm = append(toWarm, dbCmd{"trivy", "trivy image --download-db-only"})
	}
	if grypeExists {
		fmt.Fprintln(os.Stderr, "[agent] grype DB already present, skipping download")
	} else {
		toWarm = append(toWarm, dbCmd{"grype", "grype db update"})
	}

	if len(toWarm) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	for _, c := range toWarm {
		wg.Add(1)
		go func(name, cmd string) {
			defer wg.Done()
			_, _, err := scanner.ExecWithTimeout(ctx, cmd, 300000, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[agent] %s DB warmup failed: %s\n", name, err.Error())
			} else {
				fmt.Fprintf(os.Stderr, "[agent] %s DB ready\n", name)
			}
		}(c.name, c.cmd)
	}

	wg.Wait()
}

func dbDirHasContent(dir string) bool {
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) > 0
}

func registerWithRetry(client *AgentClient, reg types.AgentRegistration, maxRetries int) (string, error) {
	var lastErr error
	backoff := time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		agentID, err := client.Register(reg)
		if err == nil {
			return agentID, nil
		}
		lastErr = err
		fmt.Fprintf(os.Stderr, "[agent] Registration failed (attempt %d/%d): %s\n", attempt, maxRetries, err.Error())

		if attempt < maxRetries {
			fmt.Fprintf(os.Stderr, "[agent] Retrying in %s...\n", backoff)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
	return "", fmt.Errorf("registration failed after %d attempts: %w", maxRetries, lastErr)
}
