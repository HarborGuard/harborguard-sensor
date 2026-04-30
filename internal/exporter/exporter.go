// Package exporter packages a source container image as a tarball and
// ships it to S3 via a dashboard-minted presigned URL. It is the third
// sensor capability alongside scan and patch and reuses the same
// skopeo/docker-archive pull pattern.
//
// Storage credentials live entirely on the dashboard; the sensor never
// needs an S3 client of its own. For files at or below the dashboard's
// MultipartThresholdBytes the sensor uses a single presigned PUT. For
// larger files it uses a multipart-presigned workflow: the dashboard
// initiates the multipart upload and mints per-part PUT URLs, the
// sensor uploads parts in parallel and reports the ETags back, and the
// dashboard issues the CompleteMultipartUpload. Single PUT alone
// would cap at 5 GB on AWS S3 — image tarballs routinely exceed that.
//
// The sensor stays stateless: the tarball lives in workDir only between
// pull and upload; the workdir is removed on every exit path so a
// crash mid-upload doesn't leak multi-GB files.
package exporter

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/scanner"
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const (
	sensorVersion       = "0.1.0"
	skopeoBinary        = "skopeo"
	skopeoPullTimeoutMs = 600_000
	uploadTimeout       = 30 * time.Minute
	partConcurrency     = 4
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

	uploadCtx, uploadCancel := context.WithTimeout(ctx, uploadTimeout)
	defer uploadCancel()
	size, sha, err := uploadFile(uploadCtx, e.Config.APIKey, job.ID, job.Job.Sink, uploadPath)
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

// uploadFile decides between single-PUT and multipart based on file
// size + sink config, hashes the file in one pre-pass, and dispatches.
//
// Hash is computed in a separate pre-pass over the file rather than via
// a TeeReader during upload. TeeReader-during-upload would corrupt the
// hash on retry: net/http rewinds the body via Seek on redirect/retry
// but the captured hash state would not reset. With multipart upload
// the retry surface is per-part, multiplying the hazard. Two reads of
// the same file are cheap (the second hits the OS page cache after
// the first).
//
// We do NOT set Content-Type on the upload PUTs — the dashboard mints
// presigned URLs without signing it, which makes the request match-
// anything compatible. If a dashboard ever signed Content-Type into a
// URL the request would have to echo it exactly or S3 returns
// SignatureDoesNotMatch.
func uploadFile(ctx context.Context, apiKey, jobID string, sink types.ExportSink, filePath string) (int64, string, error) {
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

	useMultipart := sink.MultipartInitUrl != "" &&
		sink.MultipartThresholdBytes > 0 &&
		size > sink.MultipartThresholdBytes

	if useMultipart {
		fmt.Fprintf(os.Stderr, "[exporter] %s: uploading via multipart (size=%d, threshold=%d)\n",
			jobID, size, sink.MultipartThresholdBytes)
		if err := multipartUpload(ctx, apiKey, jobID, sink, f, size); err != nil {
			return 0, "", err
		}
		return size, sha, nil
	}

	fmt.Fprintf(os.Stderr, "[exporter] %s: uploading via single PUT (size=%d, key=%s)\n",
		jobID, size, sink.ExpectedKey)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, "", fmt.Errorf("rewinding source: %w", err)
	}
	if err := httpPutBody(ctx, sink.UploadURL, f, size); err != nil {
		return 0, "", err
	}
	return size, sha, nil
}

// httpPutBody PUTs body (with known content length) to url and returns
// the response ETag header value (S3 returns the part hash there for
// UploadPart). For the single-PUT case the ETag is unused. No
// Content-Type, no auth header — used for presigned S3 URLs only.
func httpPutBody(ctx context.Context, url string, body io.Reader, contentLength int64) error {
	_, err := httpPutBodyEtag(ctx, url, body, contentLength)
	return err
}

func httpPutBodyEtag(ctx context.Context, url string, body io.Reader, contentLength int64) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, body)
	if err != nil {
		return "", err
	}
	req.ContentLength = contentLength

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("PUT %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	return strings.Trim(resp.Header.Get("ETag"), `"`), nil
}

// httpPostJSON POSTs a JSON body to the dashboard endpoint at url with
// bearer auth. When result is non-nil, the response body is decoded
// into it. Used for multipart init/complete/abort — these go to the
// dashboard, not S3, hence the API-key auth.
func httpPostJSON(ctx context.Context, url, apiKey string, body, result any) error {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("POST %s %d: %s", url, resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}

type multipartInitResponse struct {
	UploadId string   `json:"uploadId"`
	PartSize int64    `json:"partSize"`
	PartUrls []string `json:"partUrls"`
}

type multipartPart struct {
	PartNumber int    `json:"partNumber"`
	ETag       string `json:"etag"`
}

type multipartCompleteRequest struct {
	UploadId string          `json:"uploadId"`
	Parts    []multipartPart `json:"parts"`
}

type multipartAbortRequest struct {
	UploadId string `json:"uploadId"`
}

// multipartUpload runs the init → upload-parts → complete sequence,
// aborting on any failure after a successful init. Parts upload in
// parallel up to partConcurrency. Concurrent reads from the same
// *os.File via io.NewSectionReader use pread under the hood and are
// safe; each goroutine gets its own SectionReader anchored at a
// distinct offset.
func multipartUpload(ctx context.Context, apiKey, jobID string, sink types.ExportSink, f *os.File, size int64) error {
	var initResp multipartInitResponse
	if err := httpPostJSON(ctx, sink.MultipartInitUrl, apiKey,
		map[string]int64{"sizeBytes": size}, &initResp); err != nil {
		return fmt.Errorf("multipart init: %w", err)
	}
	if initResp.UploadId == "" || initResp.PartSize <= 0 || len(initResp.PartUrls) == 0 {
		return fmt.Errorf("multipart init: dashboard returned malformed response (uploadId=%q, partSize=%d, urls=%d)",
			initResp.UploadId, initResp.PartSize, len(initResp.PartUrls))
	}
	expectedParts := int((size + initResp.PartSize - 1) / initResp.PartSize)
	if len(initResp.PartUrls) != expectedParts {
		_ = abortMultipart(ctx, apiKey, sink.MultipartAbortUrl, initResp.UploadId)
		return fmt.Errorf("multipart init: dashboard minted %d urls but file requires %d parts (size=%d, partSize=%d)",
			len(initResp.PartUrls), expectedParts, size, initResp.PartSize)
	}

	fmt.Fprintf(os.Stderr, "[exporter] %s: multipart upload started (uploadId=%s, partSize=%d, parts=%d)\n",
		jobID, initResp.UploadId, initResp.PartSize, len(initResp.PartUrls))

	parts, err := uploadParts(ctx, f, size, initResp.PartSize, initResp.PartUrls)
	if err != nil {
		if abortErr := abortMultipart(ctx, apiKey, sink.MultipartAbortUrl, initResp.UploadId); abortErr != nil {
			fmt.Fprintf(os.Stderr, "[exporter] %s: abort failed: %s\n", jobID, abortErr.Error())
		}
		return fmt.Errorf("uploading parts: %w", err)
	}

	if err := httpPostJSON(ctx, sink.MultipartCompleteUrl, apiKey,
		multipartCompleteRequest{UploadId: initResp.UploadId, Parts: parts}, nil); err != nil {
		if abortErr := abortMultipart(ctx, apiKey, sink.MultipartAbortUrl, initResp.UploadId); abortErr != nil {
			fmt.Fprintf(os.Stderr, "[exporter] %s: abort failed: %s\n", jobID, abortErr.Error())
		}
		return fmt.Errorf("multipart complete: %w", err)
	}
	return nil
}

func abortMultipart(ctx context.Context, apiKey, abortURL, uploadID string) error {
	if abortURL == "" {
		return nil // dashboard didn't supply one; nothing we can do client-side
	}
	// Use a fresh context so a context-cancellation upstream doesn't
	// stop us from trying to free the in-flight multipart upload.
	abortCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = ctx // intentional: we don't want abort to inherit a cancelled parent
	return httpPostJSON(abortCtx, abortURL, apiKey, multipartAbortRequest{UploadId: uploadID}, nil)
}

// uploadParts uploads the file in parallel chunks. Returns parts
// ordered by partNumber (ascending). On first error all in-flight and
// unscheduled goroutines bail via the cancelled context; remaining
// goroutines drain via WaitGroup before returning.
func uploadParts(ctx context.Context, f *os.File, size, partSize int64, urls []string) ([]multipartPart, error) {
	numParts := len(urls)
	results := make([]multipartPart, numParts)

	partCtx, partCancel := context.WithCancel(ctx)
	defer partCancel()

	sem := make(chan struct{}, partConcurrency)
	errCh := make(chan error, numParts)
	var wg sync.WaitGroup

	for i := 0; i < numParts; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-partCtx.Done():
				return
			}
			defer func() { <-sem }()

			if partCtx.Err() != nil {
				return
			}

			partNumber := i + 1
			offset := int64(i) * partSize
			length := partSize
			if offset+length > size {
				length = size - offset
			}
			sec := io.NewSectionReader(f, offset, length)

			etag, err := httpPutBodyEtag(partCtx, urls[i], sec, length)
			if err != nil {
				errCh <- fmt.Errorf("part %d: %w", partNumber, err)
				partCancel()
				return
			}
			if etag == "" {
				errCh <- fmt.Errorf("part %d: response missing ETag header", partNumber)
				partCancel()
				return
			}
			results[i] = multipartPart{PartNumber: partNumber, ETag: etag}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return nil, err
		}
	}
	return results, nil
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
