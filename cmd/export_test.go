package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/pflag"

	"github.com/HarborGuard/harborguard-sensor/internal/exporter"
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// withStubExportExecute swaps exportExecuteFn for the duration of a
// test. Restores the prior value via t.Cleanup so test interleaving
// can't leak the stub into a sibling test.
func withStubExportExecute(t *testing.T, stub func(ctx context.Context, e *exporter.Exporter, job types.ExportJob) (*types.ExportEnvelope, error)) {
	t.Helper()
	orig := exportExecuteFn
	exportExecuteFn = stub
	t.Cleanup(func() { exportExecuteFn = orig })
}

// resetExportFlags clears any sticky flag values so a sibling test can
// run with a different flag set. cobra/pflag retains the last-parsed
// value across rootCmd.Execute() invocations in the same process —
// without resetting, a test that omits --upload-url will silently
// inherit the value from a previous test that set it.
func resetExportFlags(t *testing.T) {
	t.Helper()
	exportCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
	})
}

// withEnv sets one env var for the test, restoring it on cleanup. Used
// to drive REGISTRY_USER/REGISTRY_PASS through runExport without
// polluting the surrounding test process.
func withEnv(t *testing.T, key, val string) {
	t.Helper()
	prior, hadPrior := os.LookupEnv(key)
	if val == "" {
		_ = os.Unsetenv(key)
	} else {
		_ = os.Setenv(key, val)
	}
	t.Cleanup(func() {
		if hadPrior {
			_ = os.Setenv(key, prior)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

// recorder captures the result envelope POST so a test can inspect what
// the subcommand sent back to the dashboard.
type recorder struct {
	hits        atomic.Int32
	method      string
	authHeader  string
	contentType string
	body        []byte
}

func newRecorderServer(t *testing.T) (*httptest.Server, *recorder) {
	t.Helper()
	r := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		r.method = req.Method
		r.authHeader = req.Header.Get("Authorization")
		r.contentType = req.Header.Get("Content-Type")
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		r.body = body
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, r
}

func TestRunExportSuccess(t *testing.T) {
	srv, rec := newRecorderServer(t)

	var capturedJob types.ExportJob
	withStubExportExecute(t, func(ctx context.Context, e *exporter.Exporter, job types.ExportJob) (*types.ExportEnvelope, error) {
		capturedJob = job
		return &types.ExportEnvelope{
			Version: "1.0",
			Sensor:  types.EnvelopeSensor{Version: "0.1.0"},
			Source:  types.EnvelopeImage{Ref: job.Job.Source.Ref, Name: "alpine", Tag: "3.18"},
			Export: types.EnvelopeExport{
				ID:     job.ID,
				Status: "SUCCESS",
			},
			Sink: types.EnvelopeExportSink{
				Kind:      "s3",
				Key:       job.Job.Sink.ExpectedKey,
				SizeBytes: 12345,
				Sha256:    "abc",
			},
			Tooling: map[string]string{"runtime": "linux/amd64"},
		}, nil
	})

	// REGISTRY_USER/REGISTRY_PASS should land on the Exporter's
	// SensorRegistryCreds via runExport. We can't observe the
	// Exporter struct from the stub directly because the stub
	// receives the Exporter by pointer — but we can verify the env
	// fan-out path doesn't crash with creds set.
	withEnv(t, "REGISTRY_USER", "alice")
	withEnv(t, "REGISTRY_PASS", "hunter2")

	resetExportFlags(t)
	rootCmd.SetArgs([]string{
		"export",
		"alpine:3.18",
		"--export-id", "exp-123",
		"--upload-url", "https://s3.example.com/put",
		"--expected-key", "exports/exp-123/image.tar",
		"--upload-result-url", srv.URL,
		"--api-key", "test-api-key",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// One POST should have hit the result URL.
	if got := rec.hits.Load(); got != 1 {
		t.Fatalf("recorder hits = %d, want 1", got)
	}
	if rec.method != http.MethodPost {
		t.Errorf("method = %q, want POST", rec.method)
	}
	if rec.authHeader != "Bearer test-api-key" {
		t.Errorf("auth = %q, want %q", rec.authHeader, "Bearer test-api-key")
	}
	if rec.contentType != "application/json" {
		t.Errorf("content-type = %q, want application/json", rec.contentType)
	}

	// Verify the envelope landed unmodified.
	var got types.ExportEnvelope
	if err := json.Unmarshal(rec.body, &got); err != nil {
		t.Fatalf("decoding posted body: %v", err)
	}
	if got.Export.ID != "exp-123" {
		t.Errorf("envelope.Export.ID = %q, want exp-123", got.Export.ID)
	}
	if got.Export.Status != "SUCCESS" {
		t.Errorf("envelope.Export.Status = %q, want SUCCESS", got.Export.Status)
	}
	if got.Sink.Key != "exports/exp-123/image.tar" {
		t.Errorf("envelope.Sink.Key = %q", got.Sink.Key)
	}

	// And the job we built from flags ought to match.
	if capturedJob.ID != "exp-123" {
		t.Errorf("captured job.ID = %q", capturedJob.ID)
	}
	if capturedJob.Job.Source.Ref != "alpine:3.18" {
		t.Errorf("captured source.ref = %q", capturedJob.Job.Source.Ref)
	}
	if capturedJob.Job.Sink.UploadURL != "https://s3.example.com/put" {
		t.Errorf("captured uploadURL = %q", capturedJob.Job.Sink.UploadURL)
	}
	if capturedJob.Job.Sink.ExpectedKey != "exports/exp-123/image.tar" {
		t.Errorf("captured expectedKey = %q", capturedJob.Job.Sink.ExpectedKey)
	}
}

func TestRunExportFailureSendsFailedEnvelope(t *testing.T) {
	srv, rec := newRecorderServer(t)

	withStubExportExecute(t, func(ctx context.Context, e *exporter.Exporter, job types.ExportJob) (*types.ExportEnvelope, error) {
		return nil, errors.New("skopeo: simulated pull failure")
	})

	resetExportFlags(t)
	rootCmd.SetArgs([]string{
		"export",
		"alpine:3.18",
		"--export-id", "exp-fail",
		"--upload-url", "https://s3.example.com/put",
		"--expected-key", "exports/exp-fail/image.tar",
		"--upload-result-url", srv.URL,
		"--api-key", "k",
	})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !strings.Contains(err.Error(), "skopeo: simulated pull failure") {
		t.Errorf("error should wrap underlying cause: %v", err)
	}

	// A failure-envelope POST is still sent — the dashboard needs to
	// flip the row to FAILED in-band since the one-shot path has no
	// /api/agent/jobs/{id}/status endpoint.
	if got := rec.hits.Load(); got != 1 {
		t.Fatalf("recorder hits = %d, want 1 (failure envelope)", got)
	}
	var env types.ExportEnvelope
	if err := json.Unmarshal(rec.body, &env); err != nil {
		t.Fatalf("decoding posted body: %v", err)
	}
	if env.Export.Status != "FAILED" {
		t.Errorf("Export.Status = %q, want FAILED", env.Export.Status)
	}
	if env.Export.Error == "" || !strings.Contains(env.Export.Error, "skopeo: simulated pull failure") {
		t.Errorf("Export.Error should carry the failure message, got %q", env.Export.Error)
	}
	if env.Tooling["error"] == "" {
		t.Errorf("Tooling[error] should carry the failure message")
	}
}

// TestRunExportFailureEnvelopeMatchesDashboardContract is the
// regression-net for the dashboard-contract bug we fixed: the
// /api/exports/upload route reads `body.error ?? body.export?.error`
// to decide whether to flip the export row to FAILED. If the error
// string is buried in tooling.error (where it was before) the
// dashboard never sees it and the row sits in DISPATCHED forever.
//
// Drive this test through a full JSON marshal/unmarshal of what the
// HTTP body would be — not just inspecting the Go struct — to mirror
// what the dashboard actually does (it doesn't share Go types; it
// reads named keys off the parsed JSON).
func TestRunExportFailureEnvelopeMatchesDashboardContract(t *testing.T) {
	srv, rec := newRecorderServer(t)

	withStubExportExecute(t, func(ctx context.Context, e *exporter.Exporter, job types.ExportJob) (*types.ExportEnvelope, error) {
		return nil, errors.New("skopeo: registry unreachable")
	})

	resetExportFlags(t)
	rootCmd.SetArgs([]string{
		"export",
		"alpine:3.18",
		"--export-id", "exp-contract",
		"--upload-url", "https://s3.example.com/put",
		"--expected-key", "exports/exp-contract/image.tar",
		"--upload-result-url", srv.URL,
		"--api-key", "k",
	})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected non-nil error from failing export")
	}

	if rec.hits.Load() != 1 {
		t.Fatalf("recorder hits = %d", rec.hits.Load())
	}

	// Loose decode = what the dashboard's TS does.
	var asMap map[string]any
	if err := json.Unmarshal(rec.body, &asMap); err != nil {
		t.Fatalf("decoding wire JSON: %v", err)
	}

	// Dashboard reads body.error ?? body.export?.error. We exercise the
	// second leg (body.export.error) — which is where the new field
	// lives — but assert in a way that tolerates either path being
	// populated, matching the dashboard's nullish-coalesce.
	export, _ := asMap["export"].(map[string]any)
	if export == nil {
		t.Fatalf("export key absent from wire body: %s", string(rec.body))
	}
	topErr, _ := asMap["error"].(string)
	exportErr, _ := export["error"].(string)
	resolved := topErr
	if resolved == "" {
		resolved = exportErr
	}
	if resolved == "" {
		t.Errorf("dashboard read `body.error ?? body.export.error` is empty — neither path populated. Body = %s", string(rec.body))
	}
	if !strings.Contains(resolved, "registry unreachable") {
		t.Errorf("error string lost — got %q", resolved)
	}

	// Status still FAILED at the typed level too (for completeness).
	if export["status"] != "FAILED" {
		t.Errorf("export.status = %v, want FAILED", export["status"])
	}

	// Strict round-trip — would catch a future dev removing omitempty
	// in the wrong direction or renaming the JSON tag.
	var strict types.ExportEnvelope
	if err := json.Unmarshal(rec.body, &strict); err != nil {
		t.Fatalf("strict round-trip decoding: %v", err)
	}
	if strict.Export.Error == "" {
		t.Errorf("strict Export.Error is empty — JSON tag drift?")
	}
}

func TestRunExportMissingFlags(t *testing.T) {
	// Don't expect any Execute call when flags are bad.
	withStubExportExecute(t, func(ctx context.Context, e *exporter.Exporter, job types.ExportJob) (*types.ExportEnvelope, error) {
		t.Fatal("Execute should not be called when required flags are missing")
		return nil, nil
	})

	resetExportFlags(t)
	rootCmd.SetArgs([]string{
		"export",
		"alpine:3.18",
		"--export-id", "exp-1",
		// upload-url, expected-key, upload-result-url, api-key all
		// missing
	})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing flags")
	}
	if !strings.Contains(err.Error(), "missing required flags") {
		t.Errorf("error should call out missing flags: %v", err)
	}
	for _, want := range []string{"--upload-url", "--expected-key", "--upload-result-url", "--api-key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
}

func TestPostResultEnvelope(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rec.hits.Add(1)
		rec.method = req.Method
		rec.authHeader = req.Header.Get("Authorization")
		rec.contentType = req.Header.Get("Content-Type")
		body, _ := io.ReadAll(req.Body)
		rec.body = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	type payload struct {
		Hello string `json:"hello"`
	}
	if err := postResultEnvelope(context.Background(), srv.URL, "k", payload{Hello: "world"}); err != nil {
		t.Fatalf("postResultEnvelope: %v", err)
	}
	if rec.hits.Load() != 1 {
		t.Fatal("expected one hit")
	}
	if rec.authHeader != "Bearer k" {
		t.Errorf("auth = %q", rec.authHeader)
	}
	if rec.contentType != "application/json" {
		t.Errorf("content-type = %q", rec.contentType)
	}
	if !strings.Contains(string(rec.body), `"hello":"world"`) {
		t.Errorf("body = %q", string(rec.body))
	}
}

func TestPostResultEnvelopeNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "forbidden body")
	}))
	defer srv.Close()
	err := postResultEnvelope(context.Background(), srv.URL, "k", map[string]string{"x": "y"})
	if err == nil {
		t.Fatal("expected error on 403")
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "forbidden body") {
		t.Errorf("error should surface status + body: %v", err)
	}
}

func TestPostResultEnvelopeRequiresURL(t *testing.T) {
	if err := postResultEnvelope(context.Background(), "", "k", map[string]string{}); err == nil {
		t.Fatal("expected error for empty url")
	}
}

// stableSort is a tiny in-package helper; assert it actually sorts so
// the missing-flags test above can rely on a deterministic order.
func TestStableSort(t *testing.T) {
	in := []string{"c", "a", "b"}
	stableSort(in)
	if got := fmt.Sprintf("%v", in); got != "[a b c]" {
		t.Errorf("stableSort = %v", in)
	}
}

