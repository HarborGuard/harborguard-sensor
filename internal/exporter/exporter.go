// Package exporter packages a source container image as a tarball and
// ships it to S3. It is the third sensor capability alongside scan and
// patch and reuses the same skopeo/docker-archive pull pattern as those
// flows.
//
// The exporter keeps the sensor stateless: the tarball lives in workDir
// only between pull and upload; the workdir is removed on every exit
// path so a crash mid-upload doesn't leak multi-GB files.
package exporter

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/scanner"
	"github.com/HarborGuard/harborguard-sensor/internal/storage"
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const (
	sensorVersion       = "0.1.0"
	skopeoBinary        = "skopeo"
	skopeoPullTimeoutMs = 600_000
	defaultPresignTTL   = 3600
	uploadTimeout       = 30 * time.Minute
)

// Exporter orchestrates an export job end-to-end.
type Exporter struct {
	Config              *types.SensorConfig
	S3Storage           *storage.S3Storage
	SensorRegistryCreds *types.RegistryCredentials
}

// Execute runs the full export pipeline and returns an envelope describing
// the outcome. workDir is cleaned up on every exit path.
func (e *Exporter) Execute(ctx context.Context, job types.ExportJob) (*types.ExportEnvelope, error) {
	if e.S3Storage == nil {
		return nil, fmt.Errorf("export requires sensor S3 storage to be configured")
	}

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
	suffix := ".tar"
	if job.Job.Compress {
		gzPath := tarPath + ".gz"
		fmt.Fprintf(os.Stderr, "[exporter] %s: compressing tarball\n", job.ID)
		if err := gzipFile(tarPath, gzPath); err != nil {
			return nil, fmt.Errorf("gzip tarball: %w", err)
		}
		_ = os.Remove(tarPath)
		uploadPath = gzPath
		suffix = ".tar.gz"
	}

	prefix, err := normalizeKeyPrefix(job.Job.Sink.KeyPrefix, job.ID)
	if err != nil {
		return nil, err
	}
	objectName := "image-" + job.ID + suffix
	key := path.Join(prefix, objectName)

	contentType := "application/x-tar"
	if job.Job.Compress {
		contentType = "application/gzip"
	}

	fmt.Fprintf(os.Stderr, "[exporter] %s: uploading to s3://%s/%s\n",
		job.ID, sinkBucketDescription(job.Job.Sink.Bucket, e.Config.S3Bucket), key)

	uploadCtx, uploadCancel := context.WithTimeout(ctx, uploadTimeout)
	defer uploadCancel()
	size, sha, err := e.S3Storage.UploadArtifactStream(uploadCtx, job.Job.Sink.Bucket, key, uploadPath, contentType)
	if err != nil {
		return nil, fmt.Errorf("s3 upload: %w", err)
	}

	var presignedURL string
	if job.Job.Sink.Presign {
		ttl := job.Job.Sink.TTLSecs
		if ttl <= 0 {
			ttl = defaultPresignTTL
		}
		presignedURL, err = e.S3Storage.PresignGetForBucket(job.Job.Sink.Bucket, key, time.Duration(ttl)*time.Second)
		if err != nil {
			return nil, fmt.Errorf("presigning: %w", err)
		}
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
			Bucket:     job.Job.Sink.Bucket,
			Key:        key,
			URL:        presignedURL,
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
	return nil
}

// normalizeKeyPrefix sanitizes a dashboard-supplied KeyPrefix and falls
// back to "exports/<jobID>" when blank. Rejects values that could escape
// a prefix-keyed bucket policy: leading "/" anchors to the bucket root,
// ".." segments resolve up out of the intended prefix, and NUL bytes
// are nonsense in S3 keys regardless. path.Join cleans ".." but does
// NOT anchor — "../foo" stays "../foo" — so the check has to happen
// before joining.
func normalizeKeyPrefix(raw, jobID string) (string, error) {
	prefix := strings.TrimSuffix(raw, "/")
	if prefix == "" {
		return "exports/" + jobID, nil
	}
	if strings.ContainsRune(prefix, 0) {
		return "", fmt.Errorf("sink.keyPrefix contains NUL byte")
	}
	if strings.HasPrefix(prefix, "/") {
		return "", fmt.Errorf("sink.keyPrefix must not start with '/'")
	}
	for _, seg := range strings.Split(prefix, "/") {
		if seg == ".." {
			return "", fmt.Errorf("sink.keyPrefix must not contain '..' segment")
		}
	}
	return prefix, nil
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

func sinkBucketDescription(override, fallback string) string {
	if override != "" {
		return override
	}
	return fallback
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
