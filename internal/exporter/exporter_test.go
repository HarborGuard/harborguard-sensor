package exporter

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

func TestSplitNameTag(t *testing.T) {
	cases := []struct {
		in        string
		wantName  string
		wantTag   string
	}{
		{"alpine:3.18", "alpine", "3.18"},
		{"docker.io/library/nginx:1.25", "docker.io/library/nginx", "1.25"},
		{"ghcr.io/org/app", "ghcr.io/org/app", ""},
		{"host:5000/repo:tag", "host:5000/repo", "tag"},
		{"alpine:3.18@sha256:abc", "alpine", "3.18"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			name, tag := splitNameTag(c.in)
			if name != c.wantName || tag != c.wantTag {
				t.Errorf("splitNameTag(%q) = (%q, %q); want (%q, %q)",
					c.in, name, tag, c.wantName, c.wantTag)
			}
		})
	}
}

func TestValidateJob(t *testing.T) {
	complete := types.ExportJob{
		ID: "j1",
		Job: types.AgentJobExport{
			Source: types.ImageSource{Ref: "alpine:3.18"},
			Sink: types.ExportSink{
				UploadURL:   "https://example.com/put",
				ExpectedKey: "exports/j1/image.tar",
			},
		},
	}
	t.Run("ok", func(t *testing.T) {
		if err := validateJob(complete); err != nil {
			t.Fatalf("unexpected: %v", err)
		}
	})

	missing := []struct {
		name  string
		mut   func(*types.ExportJob)
	}{
		{"missing id", func(j *types.ExportJob) { j.ID = "" }},
		{"missing source ref", func(j *types.ExportJob) { j.Job.Source.Ref = "" }},
		{"missing uploadUrl", func(j *types.ExportJob) { j.Job.Sink.UploadURL = "" }},
		{"missing expectedKey", func(j *types.ExportJob) { j.Job.Sink.ExpectedKey = "" }},
	}
	for _, m := range missing {
		t.Run(m.name, func(t *testing.T) {
			j := complete
			m.mut(&j)
			if err := validateJob(j); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestScrubCreds(t *testing.T) {
	t.Run("redacts password when present", func(t *testing.T) {
		err := fmt.Errorf("auth failed: bad creds (user=alice pass=hunter2)")
		got := scrubCreds(err, &types.RegistryCredentials{Username: "alice", Password: "hunter2"})
		if got == nil || got.Error() == err.Error() {
			t.Fatalf("expected redaction; got %q", got)
		}
		if !strings.Contains(got.Error(), "***REDACTED***") {
			t.Errorf("expected REDACTED marker, got %q", got)
		}
		if strings.Contains(got.Error(), "hunter2") {
			t.Errorf("password not redacted: %q", got)
		}
	})
	t.Run("passthrough when password not in message", func(t *testing.T) {
		err := fmt.Errorf("network unreachable")
		got := scrubCreds(err, &types.RegistryCredentials{Password: "hunter2"})
		if got != err {
			t.Errorf("expected identity passthrough, got %q", got)
		}
	})
	t.Run("nil creds passthrough", func(t *testing.T) {
		err := fmt.Errorf("oops")
		if got := scrubCreds(err, nil); got != err {
			t.Errorf("expected identity passthrough, got %q", got)
		}
	})
	t.Run("nil err returns nil", func(t *testing.T) {
		if got := scrubCreds(nil, &types.RegistryCredentials{Password: "x"}); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

func TestGzipFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "in.bin")
	payload := []byte("the quick brown fox jumps over the lazy dog\n")
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "in.bin.gz")
	if err := gzipFile(src, dst); err != nil {
		t.Fatalf("gzipFile: %v", err)
	}
	f, err := os.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	got, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("decoded payload = %q, want %q", got, payload)
	}
}

// httpPutFile contract: PUTs the file to the URL, returns size and
// SHA-256 of the bytes as they appear on the wire. The fake server
// captures the request body, recomputes the hash, and asserts it
// matches what the function reports.
func TestHttpPutFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "payload.bin")
	// 5 MB of random-ish content so we exercise the streaming path,
	// not just a tiny buffer that fits in a single packet.
	payload := make([]byte, 5*1024*1024)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	wantHasher := sha256.Sum256(payload)
	wantSha := hex.EncodeToString(wantHasher[:])

	var (
		mu          sync.Mutex
		gotMethod   string
		gotBody     []byte
		gotContent  string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotMethod = r.Method
		gotContent = r.Header.Get("Content-Type")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		gotBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	size, sha, err := httpPutFile(context.Background(), srv.URL, src)
	if err != nil {
		t.Fatalf("httpPutFile: %v", err)
	}
	if size != int64(len(payload)) {
		t.Errorf("size = %d, want %d", size, len(payload))
	}
	if sha != wantSha {
		t.Errorf("sha = %q, want %q", sha, wantSha)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotContent != "" {
		t.Errorf("Content-Type = %q, want empty (so presigned URLs that don't sign Content-Type accept the request)", gotContent)
	}
	if len(gotBody) != len(payload) {
		t.Fatalf("body length = %d, want %d", len(gotBody), len(payload))
	}
	wireHash := sha256.Sum256(gotBody)
	if hex.EncodeToString(wireHash[:]) != wantSha {
		t.Errorf("on-the-wire hash != reported hash")
	}
}

func TestHttpPutFileSurfacesNon2xx(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("SignatureDoesNotMatch"))
	}))
	defer srv.Close()

	_, _, err := httpPutFile(context.Background(), srv.URL, src)
	if err == nil {
		t.Fatal("expected error on 403")
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Errorf("error should surface status + body, got %q", err.Error())
	}
}
