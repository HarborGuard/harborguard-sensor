package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

var validScanners = map[string]bool{
	"trivy": true, "grype": true, "syft": true,
	"dockle": true, "osv": true, "dive": true,
}

var validLogLevels = map[string]bool{
	"debug": true, "info": true, "warn": true, "error": true,
}

func envOr(keys []string, fallback string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return fallback
}

// LoadConfig reads configuration from environment variables with optional overrides.
func LoadConfig(overrides map[string]string) (*types.SensorConfig, error) {
	override := func(key string) string {
		if v, ok := overrides[key]; ok && v != "" {
			return v
		}
		return ""
	}

	// Scanners
	scannersRaw := override("scanners")
	if scannersRaw == "" {
		scannersRaw = envOr([]string{"HG_ENABLED_SCANNERS", "ENABLED_SCANNERS"}, "trivy,grype,syft,dockle,osv,dive")
	}
	scanners := splitTrim(scannersRaw)

	var errs []string

	if len(scanners) == 0 {
		errs = append(errs, "enabledScanners: At least one scanner must be enabled")
	}
	var invalid []string
	for _, s := range scanners {
		if !validScanners[s] {
			invalid = append(invalid, s)
		}
	}
	if len(invalid) > 0 {
		validList := "trivy, grype, syft, dockle, osv, dive"
		errs = append(errs, fmt.Sprintf("enabledScanners: Invalid scanners: %s. Valid: %s", strings.Join(invalid, ", "), validList))
	}

	// Timeout
	timeoutRaw := override("timeout")
	if timeoutRaw == "" {
		timeoutRaw = envOr([]string{"HG_SCAN_TIMEOUT_MINUTES", "SCAN_TIMEOUT_MINUTES"}, "30")
	}
	timeout, err := strconv.Atoi(timeoutRaw)
	if err != nil {
		errs = append(errs, "scanTimeoutMinutes: must be a number")
		timeout = 30
	}
	if timeout < 5 || timeout > 180 {
		errs = append(errs, "scanTimeoutMinutes: Number must be greater than or equal to 5 and less than or equal to 180")
	}

	// Concurrency
	concurrencyRaw := override("concurrency")
	if concurrencyRaw == "" {
		concurrencyRaw = envOr([]string{"HG_MAX_CONCURRENT_SCANNERS"}, "3")
	}
	concurrency, err := strconv.Atoi(concurrencyRaw)
	if err != nil {
		errs = append(errs, "maxConcurrentScanners: must be a number")
		concurrency = 3
	}
	if concurrency < 1 || concurrency > 10 {
		errs = append(errs, "maxConcurrentScanners: Number must be greater than or equal to 1 and less than or equal to 10")
	}

	// Dashboard URL
	dashboardURL := override("dashboardUrl")
	if dashboardURL == "" {
		dashboardURL = envOr([]string{"HG_DASHBOARD_URL"}, "")
	}
	if dashboardURL != "" {
		if _, err := url.ParseRequestURI(dashboardURL); err != nil {
			errs = append(errs, "dashboardUrl: Invalid url")
		}
	}

	// API Key
	apiKey := override("apiKey")
	if apiKey == "" {
		apiKey = envOr([]string{"HG_API_KEY"}, "")
	}

	// Agent name
	agentName := override("agentName")
	if agentName == "" {
		agentName = envOr([]string{"HG_AGENT_NAME"}, "")
	}

	// Poll interval
	pollRaw := override("pollInterval")
	if pollRaw == "" {
		pollRaw = envOr([]string{"HG_POLL_INTERVAL_MS"}, "10000")
	}
	pollInterval, err := strconv.Atoi(pollRaw)
	if err != nil {
		errs = append(errs, "pollIntervalMs: must be a number")
		pollInterval = 10000
	}
	if pollInterval < 1000 {
		errs = append(errs, "pollIntervalMs: Number must be greater than or equal to 1000")
	}

	// S3
	s3Endpoint := envOr([]string{"HG_S3_ENDPOINT", "S3_ENDPOINT"}, "")
	s3Bucket := envOr([]string{"HG_S3_BUCKET", "S3_BUCKET"}, "")
	s3AccessKey := envOr([]string{"HG_S3_ACCESS_KEY", "AWS_ACCESS_KEY_ID"}, "")
	s3SecretKey := envOr([]string{"HG_S3_SECRET_KEY", "AWS_SECRET_ACCESS_KEY"}, "")
	s3Region := envOr([]string{"HG_S3_REGION", "AWS_REGION"}, "us-east-1")

	// Work/cache dirs
	workDir := envOr([]string{"HG_WORK_DIR", "SCANNER_WORKDIR"}, "/workspace")
	cacheDir := envOr([]string{"HG_CACHE_DIR"}, "/workspace/cache")

	// Log level
	logLevelRaw := override("logLevel")
	if logLevelRaw == "" {
		logLevelRaw = envOr([]string{"HG_LOG_LEVEL", "LOG_LEVEL"}, "info")
	}
	logLevel := strings.ToLower(logLevelRaw)
	if !validLogLevels[logLevel] {
		errs = append(errs, fmt.Sprintf("logLevel: Invalid enum value. Expected 'debug' | 'info' | 'warn' | 'error', received '%s'", logLevel))
	}

	if len(errs) > 0 {
		msg := "[config] Validation errors:\n"
		for _, e := range errs {
			msg += "  " + e + "\n"
		}
		fmt.Fprint(os.Stderr, msg)
		return nil, fmt.Errorf("Invalid sensor configuration")
	}

	return &types.SensorConfig{
		EnabledScanners:       scanners,
		ScanTimeoutMinutes:    timeout,
		MaxConcurrentScanners: concurrency,
		DashboardURL:          dashboardURL,
		APIKey:                apiKey,
		AgentName:             agentName,
		PollIntervalMs:        pollInterval,
		S3Endpoint:            s3Endpoint,
		S3Bucket:              s3Bucket,
		S3AccessKey:           s3AccessKey,
		S3SecretKey:           s3SecretKey,
		S3Region:              s3Region,
		WorkDir:               workDir,
		CacheDir:              cacheDir,
		LogLevel:              logLevel,
	}, nil
}

func splitTrim(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
