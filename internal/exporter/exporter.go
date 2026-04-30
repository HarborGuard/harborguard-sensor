// Package exporter packages a source container image as a tarball and
// HTTP-PUTs it to a presigned URL minted by the dashboard. It is the
// third sensor capability alongside scan and patch and reuses the same
// skopeo/docker-archive pull pattern.
//
// Storage credentials live entirely on the dashboard; the sensor never
// needs an S3 client of its own. The dashboard mints a presigned PUT
// URL for the expected key, and the sensor's only job is "produce the
// bytes and PUT them." This keeps tenant isolation, key naming, and
// bucket policy concerns in one place rather than spread across every
// sensor deployment.
//
// The sensor stays stateless: the tarball lives in workDir only between
// pull and upload; the workdir is removed on every exit path so a
// crash mid-upload doesn't leak multi-GB files.
package exporter

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/scanner"
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const (
	sensorVersion       = "0.1.0"
	skopeoBinary        = "skopeo"
	skopeoPullTimeoutMs = 600_000
	uploadTimeout       = 30 * time.Minute
)

// Exporter orchestrates an export job end-to-end. The struct holds no
// S3 client — the dashboard owns all storage primitives via the
// presigned PUT URL on the job.
type Exporter struct {
	Config              *types.SensorConfig
	SensorRegistryCreds *types.RegistryCredentials
}

// Execute runs the full export pipeline and returns an envelope describing
// the outcome. workDir is cleaned up on every exit path.
func (e *Exporter) Execute(ctx context.Context, job types.ExportJob) (*types.ExportEnvelope, error) {
	// Defensive normalization — agent loop strips schemes at the boundary,
	// but a direct caller of Execute needs this too. Idempotent.
	if normalized, insecure, _ := scanner.NormalizeImageRef(job.Job.Source.Ref); normalized != job.Job.Source.Ref {
		job.Job.Source.Ref = normalized
		if insecure {
			job.Job.Source.Insecure = true
		}
	}

	if err := validateJob(job); err != nil {
		return nil, err
	}

	startedAt := time.Now().UTC().Format(time.RFC3339)

	workDir := filepath.Join(e.Config.WorkDir, "exports", job.ID)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating work dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(workDir) }()

	tarPath := filepath.Join(workDir, "image.tar")

	pullCreds := job.Job.SourceCredentials
	if pullCreds == nil {
		pullCreds = e.SensorRegistryCreds
	}

	fmt.Fprintf(os.Stderr, "[exporter] %s: pulling %s (insecure=%t)\n",
		job.ID, job.Job.Source.Ref, job.Job.Source.Insecure)

	if err := skopeoPullToArchive(ctx, job.Job.Source.Ref, job.Job.Source.Insecure, tarPath, pullCreds); err != nil {
		return nil, fmt.Errorf("pull source: %w", scrubCreds(err, pullCreds))
	}

	uploadPath := tarPath
	if job.Job.Compress {
		gzPath := tarPath + ".gz"
		fmt.Fprintf(os.Stderr, "[exporter] %s: compressing tarball\n", job.ID)
		if err := gzipFile(tarPath, gzPath); err != nil {
			return nil, fmt.Errorf("gzip tarball: %w", err)
		}
		_ = os.Remove(tarPath)
		uploadPath = gzPath
	}

	fmt.Fprintf(os.Stderr, "[exporter] %s: uploading to presigned URL (key=%s, expiresIn=%ds)\n",
		job.ID, job.Job.Sink.ExpectedKey, job.Job.Sink.ExpiresInSeconds)

	uploadCtx, uploadCancel := context.WithTimeout(ctx, uploadTimeout)
	defer uploadCancel()
	size, sha, err := httpPutFile(uploadCtx, job.Job.Sink.UploadURL, uploadPath)
	if err != nil {
		return nil, fmt.Errorf("upload: %w", err)
	}

	finishedAt := time.Now().UTC().Format(time.RFC3339)

	envelope := &types.ExportEnvelope{
		Version: "1.0",
		Sensor: types.EnvelopeSensor{
			ID:      e.Config.SensorID,
			Name:    e.Config.AgentName,
			Version: sensorVersion,
		},
		Source: imageFromRef(job.Job.Source.Ref),
		Export: types.EnvelopeExport{
			ID:         job.ID,
			StartedAt:  startedAt,
			FinishedAt: finishedAt,
			Status:     "SUCCESS",
		},
		Sink: types.EnvelopeExportSink{
			Kind:       "s3",
			Key:        job.Job.Sink.ExpectedKey,
			SizeBytes:  size,
			Sha256:     sha,
			Compressed: job.Job.Compress,
		},
		Tooling: map[string]string{
			"skopeo":  SkopeoVersion(),
			"runtime": runtime.GOOS + "/" + runtime.GOARCH,
		},
	}
	return envelope, nil
}

func validateJob(job types.ExportJob) error {
	if job.ID == "" {
		return fmt.Errorf("job.ID required")
	}
	if job.Job.Source.Ref == "" {
		return fmt.Errorf("source.ref required")
	}
	if job.Job.Sink.UploadURL == "" {
		return fmt.Errorf("sink.uploadUrl required")
	}
	if job.Job.Sink.ExpectedKey == "" {
		return fmt.Errorf("sink.expectedKey required")
	}
	return nil
}

// httpPutFile streams a local file via HTTP PUT to uploadURL and
// returns the byte count + SHA-256 of the bytes uploaded.
//
// Hash is computed in a separate pre-pass over the file (rather than a
// TeeReader during upload). The TeeReader pattern would corrupt the
// hash on retry: net/http rewinds the request body via Seek for redirects
// or transient retries, but the captured hash state would not reset.
// Two reads of the same file are cheap (the second hits the OS page
// cache), and passing *os.File directly preserves seek-based retry.
//
// Caller is responsible for the upload context's timeout. We do NOT
// set Content-Type here — the dashboard mints presigned URLs without
// signing it, which makes the request match-anything compatible. If a
// dashboard ever signs Content-Type into the URL it must agree with
// what's sent or S3 returns SignatureDoesNotMatch; the design contract
// is "don't sign Content-Type."
//
// Single PUT only — this means image tarballs > 5 GB will fail against
// AWS S3 (MinIO accepts larger). Multipart-presigned uploads are a
// separate dashboard-side workflow (initiate, mint per-part URLs,
// complete) and intentionally out of scope here.
func httpPutFile(ctx context.Context, uploadURL, filePath string) (int64, string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return 0, "", err
	}
	size := stat.Size()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return 0, "", fmt.Errorf("hashing source: %w", err)
	}
	sha := hex.EncodeToString(hasher.Sum(nil))

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, "", fmt.Errorf("rewinding source: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, f)
	if err != nil {
		return 0, "", err
	}
	req.ContentLength = size

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, "", fmt.Errorf("PUT %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return size, sha, nil
}

// scrubCreds replaces any occurrence of the password in err.Error() with
// "***REDACTED***". Belt-and-suspenders: skopeo doesn't currently echo
// --src-creds in its failure messages, but a future version that did
// would otherwise be a credential exfil since the error string is
// reported to the dashboard via ReportJobStatus.
func scrubCreds(err error, creds *types.RegistryCredentials) error {
	if err == nil || creds == nil || creds.Password == "" {
		return err
	}
	msg := err.Error()
	if !strings.Contains(msg, creds.Password) {
		return err
	}
	return fmt.Errorf("%s", strings.ReplaceAll(msg, creds.Password, "***REDACTED***"))
}

// skopeoPullToArchive mirrors patcher.skopeoPullToArchive — direct argv,
// raw user:pass passed via --src-creds with no shell expansion. Duplicated
// to avoid layering exporter on top of patcher.
func skopeoPullToArchive(ctx context.Context, sourceRef string, insecure bool, destTar string, creds *types.RegistryCredentials) error {
	args := []string{"copy"}
	if insecure {
		args = append(args, "--src-tls-verify=false")
	}
	if creds != nil && creds.Username != "" {
		args = append(args, "--src-creds", creds.Username+":"+creds.Password)
	}
	args = append(args, "docker://"+sourceRef, "docker-archive:"+destTar)

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(skopeoPullTimeoutMs)*time.Millisecond)
	defer cancel()

	var stderr strings.Builder
	cmd := exec.CommandContext(timeoutCtx, skopeoBinary, args...)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		return fmt.Errorf("skopeo copy: %w (stderr: %s)", err, msg)
	}
	return nil
}

func gzipFile(srcPath, destPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer dst.Close()
	gz := gzip.NewWriter(dst)
	if _, err := io.Copy(gz, src); err != nil {
		_ = gz.Close()
		return err
	}
	return gz.Close()
}

func imageFromRef(ref string) types.EnvelopeImage {
	name, tag := splitNameTag(ref)
	return types.EnvelopeImage{Ref: ref, Name: name, Tag: tag}
}

func splitNameTag(ref string) (string, string) {
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

// SkopeoVersion returns the skopeo --version string for reporting.
func SkopeoVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, skopeoBinary, "--version").Output()
	if err != nil {
		return "unknown"
	}
	return strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
}
