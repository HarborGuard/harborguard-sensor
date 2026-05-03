package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/HarborGuard/harborguard-sensor/internal/config"
	"github.com/HarborGuard/harborguard-sensor/internal/exporter"
	"github.com/HarborGuard/harborguard-sensor/internal/scanner"
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const exportSensorVersion = "0.1.0"

var exportCmd = &cobra.Command{
	Use:   "export <imageRef>",
	Short: "One-shot export of a container image to a presigned S3 URL",
	Long: `Pulls the named container image, packages it as a docker-archive
tarball, and uploads it to a dashboard-minted presigned S3 URL.

Intended for ephemeral Fly Machine invocations: the dashboard mints the
URL, dispatches a single machine to run "harborguard-sensor export",
the machine pulls + uploads + reports back to --upload-result-url, then
exits. No agent registration, no polling.`,
	Args: cobra.ExactArgs(1),
	RunE: runExport,
}

func init() {
	exportCmd.Flags().String("export-id", "", "Dashboard image_export row ID (required)")
	exportCmd.Flags().String("upload-url", "", "Presigned S3 PUT URL for the tarball (required for non-multipart, or as the single-PUT fallback)")
	exportCmd.Flags().String("expected-key", "", "S3 object key the dashboard expects (required)")
	exportCmd.Flags().String("upload-result-url", "", "URL to POST the result envelope back to (required) — typically the dashboard's /api/exports/upload")
	exportCmd.Flags().String("api-key", "", "Bearer token for the result POST and any multipart init/complete/abort calls (required)")
	exportCmd.Flags().String("bucket", "", "Bucket name (informational, mirrored into ExportSink)")
	exportCmd.Flags().Int("expires-in-seconds", 0, "Expiry of the presigned URL (informational; helps trace expired-URL failures)")
	exportCmd.Flags().Bool("compress", false, "Gzip the tarball before upload (must agree with the file extension implied by --expected-key)")

	// Multipart support flags. Empty strings (the defaults) disable
	// multipart and the sensor falls back to single-PUT. Match the
	// ExportSink type so a dashboard that has shipped multipart support
	// can wire all four through and the one-shot path goes multipart on
	// large tarballs the same way the agent path already does.
	exportCmd.Flags().Int64("multipart-threshold-bytes", 0, "Files larger than this go multipart; 0 disables multipart")
	exportCmd.Flags().String("multipart-init-url", "", "Dashboard endpoint to initiate a multipart upload (POST {sizeBytes})")
	exportCmd.Flags().String("multipart-complete-url", "", "Dashboard endpoint to finalize a multipart upload")
	exportCmd.Flags().String("multipart-abort-url", "", "Dashboard endpoint to abort an in-flight multipart upload after init failure")

	exportCmd.Flags().Bool("insecure", false, "Pull source over plain http / skip TLS verification (set automatically if the imageRef carries http://)")
}

// exportExecuteFn is the package-level seam for unit tests. Production
// path points at exporter.Exporter.Execute via runExport; tests swap
// this to a stub so they don't need a real registry or skopeo binary.
//
// NOTE: this is a package-global mutated by withStubExportExecute.
// Tests that touch it MUST NOT call t.Parallel() — sibling tests in
// the same package would race on the swap. Same constraint applies
// to patchExecuteFn.
var exportExecuteFn = func(ctx context.Context, e *exporter.Exporter, job types.ExportJob) (*types.ExportEnvelope, error) {
	return e.Execute(ctx, job)
}

func runExport(cmd *cobra.Command, args []string) error {
	imageRef := args[0]

	exportID, _ := cmd.Flags().GetString("export-id")
	uploadURL, _ := cmd.Flags().GetString("upload-url")
	expectedKey, _ := cmd.Flags().GetString("expected-key")
	uploadResultURL, _ := cmd.Flags().GetString("upload-result-url")
	apiKey, _ := cmd.Flags().GetString("api-key")
	bucket, _ := cmd.Flags().GetString("bucket")
	expiresIn, _ := cmd.Flags().GetInt("expires-in-seconds")
	compress, _ := cmd.Flags().GetBool("compress")
	multipartThreshold, _ := cmd.Flags().GetInt64("multipart-threshold-bytes")
	multipartInitURL, _ := cmd.Flags().GetString("multipart-init-url")
	multipartCompleteURL, _ := cmd.Flags().GetString("multipart-complete-url")
	multipartAbortURL, _ := cmd.Flags().GetString("multipart-abort-url")
	insecureFlag, _ := cmd.Flags().GetBool("insecure")

	if missing := requiredMissing(map[string]string{
		"--export-id":         exportID,
		"--upload-url":        uploadURL,
		"--expected-key":      expectedKey,
		"--upload-result-url": uploadResultURL,
		"--api-key":           apiKey,
	}); len(missing) > 0 {
		return fmt.Errorf("missing required flags: %s", strings.Join(missing, ", "))
	}

	cfg, err := config.LoadConfig(map[string]string{
		// Threading the API key through the SensorConfig is what the
		// exporter package picks up when it has to authenticate
		// multipart init/complete/abort calls back to the dashboard.
		// Without this, multipart uploads would land on the dashboard
		// missing their bearer token even when --api-key was supplied
		// on the cmd line.
		"apiKey": apiKey,
	})
	if err != nil {
		return err
	}

	// Strip http(s):// scheme from the ref before it reaches skopeo,
	// matching the agent loop's processExportJob normalization.
	normalizedRef, schemeWasHTTP, _ := scanner.NormalizeImageRef(imageRef)
	insecure := insecureFlag || schemeWasHTTP

	source := types.ImageSource{
		Type:     "registry",
		Ref:      normalizedRef,
		Insecure: insecure,
	}

	// REGISTRY_USER / REGISTRY_PASS are read by the SensorRegistryCreds
	// path inside Exporter.Execute when job.Job.SourceCredentials is nil.
	// We mirror agent-mode by passing creds through the Exporter struct
	// rather than embedding them in the job. This keeps the job spec a
	// pure description of "what to export and where to put it" while
	// the sensor-level secrets stay at the boundary.
	var sensorCreds *types.RegistryCredentials
	if user := os.Getenv("REGISTRY_USER"); user != "" {
		sensorCreds = &types.RegistryCredentials{
			Username: user,
			Password: os.Getenv("REGISTRY_PASS"),
		}
	}

	job := types.ExportJob{
		ID: exportID,
		Job: types.AgentJobExport{
			Source: source,
			Sink: types.ExportSink{
				UploadURL:               uploadURL,
				ExpectedKey:             expectedKey,
				Bucket:                  bucket,
				ExpiresInSeconds:        expiresIn,
				MultipartThresholdBytes: multipartThreshold,
				MultipartInitUrl:        multipartInitURL,
				MultipartCompleteUrl:    multipartCompleteURL,
				MultipartAbortUrl:       multipartAbortURL,
			},
			Compress: compress,
		},
	}

	exp := &exporter.Exporter{
		Config:              cfg,
		SensorRegistryCreds: sensorCreds,
	}

	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stderr, "[export] %s: starting (ref=%s, key=%s, compress=%t)\n",
		exportID, normalizedRef, expectedKey, compress)

	envelope, execErr := exportExecuteFn(ctx, exp, job)
	if execErr != nil {
		fmt.Fprintf(os.Stderr, "[export] %s: failed: %s\n", exportID, execErr.Error())
		failedEnvelope := buildFailedExportEnvelope(cfg, exportID, normalizedRef, execErr)
		// Best-effort error envelope. If this POST also fails the
		// dashboard's row is left in PENDING — that's the same outcome
		// as agent-mode when ReportJobStatus's POST fails, so it's
		// consistent with the existing behavior. We still log both
		// errors so an operator can correlate the two.
		if postErr := postResultEnvelope(ctx, uploadResultURL, apiKey, failedEnvelope); postErr != nil {
			fmt.Fprintf(os.Stderr, "[export] %s: failure-envelope POST also failed: %s\n", exportID, postErr.Error())
		}
		return fmt.Errorf("export failed: %w", execErr)
	}

	// Pre-flight log mirrors the scan-cmd practice — useful when a
	// 30s timeout trips on the result POST and we need to know whether
	// the body itself was the size-driven cause.
	fmt.Fprintf(os.Stderr, "[export] %s: posting result envelope (key=%s, size=%d, sha256=%s)\n",
		exportID, envelope.Sink.Key, envelope.Sink.SizeBytes, envelope.Sink.Sha256)

	if err := postResultEnvelope(ctx, uploadResultURL, apiKey, envelope); err != nil {
		fmt.Fprintf(os.Stderr, "[export] %s: result POST failed: %s\n", exportID, err.Error())
		return fmt.Errorf("posting result envelope: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[export] %s: complete\n", exportID)
	return nil
}

// buildFailedExportEnvelope synthesizes an ExportEnvelope with
// Status="FAILED" and an error message so the dashboard's upload route
// can flip the export row to FAILED in-band, the same way it would
// react to a SUCCESS envelope.
//
// Why a FAILED-status envelope instead of a separate status POST:
// agent-mode reports failure via /api/agent/jobs/{id}/status but the
// one-shot path has no agent registration and therefore no /api/agent
// endpoints to call. Folding the failure signal into the same envelope
// shape the dashboard already understands keeps the dashboard surface
// area unchanged.
//
// Note: EnvelopeExport.Status doc claims "always SUCCESS" — that is
// no longer true now that the one-shot subcommand exists. The doc
// reflects agent-mode behavior, which never produces an envelope at
// all on failure.
func buildFailedExportEnvelope(cfg *types.SensorConfig, exportID, ref string, execErr error) *types.ExportEnvelope {
	now := time.Now().UTC().Format(time.RFC3339)
	name, tag := splitImageNameTag(ref)
	return &types.ExportEnvelope{
		Version: "1.0",
		Sensor: types.EnvelopeSensor{
			ID:      cfg.SensorID,
			Name:    cfg.AgentName,
			Version: exportSensorVersion,
		},
		Source: types.EnvelopeImage{
			Ref:  ref,
			Name: name,
			Tag:  tag,
		},
		Export: types.EnvelopeExport{
			ID:         exportID,
			StartedAt:  now,
			FinishedAt: now,
			Status:     "FAILED",
			// Dashboard's /api/exports/upload reads body.error ?? body.export?.error
			// — populating Export.Error here is what flips the row to FAILED.
			// We mirror it into Tooling["error"] for human-readable diagnostics
			// (it shows up in tooling JSON dumps and audit logs alongside the
			// runtime descriptor), but Tooling alone is not consumed by the
			// upload route.
			Error: execErr.Error(),
		},
		Sink: types.EnvelopeExportSink{
			Kind: "s3",
		},
		Tooling: map[string]string{
			"runtime": runtime.GOOS + "/" + runtime.GOARCH,
			"error":   execErr.Error(),
		},
	}
}

// splitImageNameTag mirrors exporter.splitNameTag but exported here so
// the failure-envelope path doesn't have to import unexported helpers.
// Best-effort; an unparseable ref still gets sent through (Name=ref,
// Tag="") so the dashboard sees what the sensor was asked to export.
func splitImageNameTag(ref string) (string, string) {
	at := strings.LastIndex(ref, "@")
	if at != -1 {
		ref = ref[:at]
	}
	colon := strings.LastIndex(ref, ":")
	slash := strings.LastIndex(ref, "/")
	if colon > slash {
		return ref[:colon], ref[colon+1:]
	}
	return ref, ""
}

// requiredMissing returns the names of any flags whose value is empty.
// Used at the top of every subcommand to surface a single error
// listing all the flags the caller forgot, rather than failing on the
// first one.
func requiredMissing(flags map[string]string) []string {
	var missing []string
	for name, val := range flags {
		if val == "" {
			missing = append(missing, name)
		}
	}
	// Stable order so unit tests can assert deterministic strings.
	stableSort(missing)
	return missing
}

// stableSort: avoid pulling sort just for a tiny slice of flag names.
func stableSort(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
