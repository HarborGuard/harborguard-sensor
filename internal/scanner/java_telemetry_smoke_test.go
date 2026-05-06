package scanner

import (
	"bytes"
	"os"
	"testing"
)

// TestEmitJavaTelemetrySmoke is a manual smoke harness; skipped unless
// HG_SMOKE_JAVA_TAR is set to a docker-archive tar file path. Used to
// validate the walker against real images during development.
//
//	HG_SMOKE_JAVA_TAR=/tmp/jt-smoke/nginx.tar go test -run TestEmitJavaTelemetrySmoke -v ./internal/scanner
func TestEmitJavaTelemetrySmoke(t *testing.T) {
	tarPath := os.Getenv("HG_SMOKE_JAVA_TAR")
	if tarPath == "" {
		t.Skip("set HG_SMOKE_JAVA_TAR to a docker-archive tar path to run this smoke test")
	}
	imageRef := os.Getenv("HG_SMOKE_IMAGE_REF")
	if imageRef == "" {
		imageRef = "smoke:unknown"
	}

	// Capture stderr so we can assert on the emitted line.
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	emitJavaTelemetry("smoke-job", imageRef, tarPath)
	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	t.Logf("telemetry output:\n%s", buf.String())
}
