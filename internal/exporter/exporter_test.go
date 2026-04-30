package exporter

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	t.Run("missing id", func(t *testing.T) {
		if err := validateJob(types.ExportJob{
			Job: types.AgentJobExport{Source: types.ImageSource{Ref: "alpine:3.18"}},
		}); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("missing source ref", func(t *testing.T) {
		if err := validateJob(types.ExportJob{ID: "j1"}); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("ok", func(t *testing.T) {
		if err := validateJob(types.ExportJob{
			ID:  "j1",
			Job: types.AgentJobExport{Source: types.ImageSource{Ref: "alpine:3.18"}},
		}); err != nil {
			t.Fatalf("unexpected: %v", err)
		}
	})
}

func TestNormalizeKeyPrefix(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		jobID   string
		want    string
		wantErr bool
	}{
		{"empty falls back to default", "", "exp_123", "exports/exp_123", false},
		{"trailing slash trimmed", "exports/foo/", "exp_123", "exports/foo", false},
		{"no slash preserved", "tenant-a", "exp_123", "tenant-a", false},
		{"leading slash rejected", "/etc/passwd", "exp_123", "", true},
		{"double-dot segment rejected", "../other-tenant", "exp_123", "", true},
		{"double-dot deep rejected", "tenant/../escape", "exp_123", "", true},
		{"NUL byte rejected", "foo\x00bar", "exp_123", "", true},
		{"double-dot prefix on segment rejected", "../..foo", "exp_123", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := normalizeKeyPrefix(c.raw, c.jobID)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
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
