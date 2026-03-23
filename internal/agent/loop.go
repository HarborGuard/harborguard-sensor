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
	orch := &scanner.Orchestrator{Config: cfg}

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

	scannerVersions := getScannerVersions(cfg.EnabledScanners)

	// Register
	agentName := cfg.AgentName
	if agentName == "" {
		agentName, _ = os.Hostname()
	}

	agentID, err := registerWithRetry(client, types.AgentRegistration{
		Name:            agentName,
		Version:         sensorVersion,
		Hostname:        hostname(),
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		ScannerVersions: scannerVersions,
		Capabilities:    []string{"scan"},
		S3Configured:    cfg.S3Bucket != "",
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
	activeScans := 0

	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-heartbeatTicker.C:
				status := "idle"
				if activeScans > 0 {
					status = "scanning"
				}
				hb := types.AgentHeartbeat{
					AgentID:       agentID,
					Status:        status,
					ActiveScans:   activeScans,
					UptimeSeconds: int64(time.Since(startTime).Seconds()),
				}
				if err := client.Heartbeat(hb); err != nil {
					fmt.Fprintf(os.Stderr, "[agent] Heartbeat failed: %s\n", err.Error())
				}
			}
		}
	}()

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

		jobs, err := client.PollJobs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[agent] Poll failed: %s\n", err.Error())
		} else {
			for _, job := range jobs {
				jobType := strings.ToLower(job.Type)
				if jobType == "scan" && job.Scan != nil {
					activeScans++
					processJob(client, orch, s3store, job)
					activeScans--
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

func processJob(client *AgentClient, orch *scanner.Orchestrator, s3store *storage.S3Storage, job types.AgentJob) {
	scan := job.Scan
	fmt.Fprintf(os.Stderr, "[agent] Starting scan: %s\n", scan.ImageRef)

	source := resolveImageSource(scan)
	output, err := orch.Execute(types.ScanJob{
		ID:       job.ID,
		ImageRef: scan.ImageRef,
		Source:   source,
		Scanners: scan.Scanners,
	})
	if err != nil {
		msg := err.Error()
		fmt.Fprintf(os.Stderr, "[agent] Scan failed: %s\n", msg)
		_ = client.ReportJobStatus(job.ID, "failed", msg)
		return
	}

	envelope := adapter.BuildEnvelope(
		types.ScanJob{ID: job.ID, ImageRef: scan.ImageRef, Source: source},
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

	// Push results to dashboard
	if _, _, err := client.UploadResults(envelope); err != nil {
		fmt.Fprintf(os.Stderr, "[agent] Upload failed: %s\n", err.Error())
		_ = client.ReportJobStatus(job.ID, "failed", err.Error())
		return
	}

	if err := client.ReportJobStatus(job.ID, "completed", ""); err != nil {
		fmt.Fprintf(os.Stderr, "[agent] Status report failed: %s\n", err.Error())
	}
	fmt.Fprintf(os.Stderr, "[agent] Scan complete: %s\n", scan.ImageRef)
}

func resolveImageSource(scan *types.AgentJobScan) types.ImageSource {
	switch scan.Source {
	case "tar":
		return types.ImageSource{Type: "tar", Path: scan.TarPath}
	case "registry":
		return types.ImageSource{Type: "registry", Ref: scan.ImageRef}
	default:
		return types.ImageSource{Type: "docker", Ref: scan.ImageRef}
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
