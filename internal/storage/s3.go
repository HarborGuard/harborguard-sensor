package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	hgtypes "github.com/HarborGuard/harborguard-sensor/internal/types"
)

// Multipart upload tuning. PartSize=10MB is mid-range of the dashboard
// reviewer's 8–16MB recommendation and balances S3 part-count limits
// (10k parts) against memory pressure (PartSize * Concurrency in flight).
// Concurrency=4 saturates a typical 1Gbps egress without thrashing the
// SDK's internal buffer pool.
const (
	uploadPartSize    = 10 * 1024 * 1024
	uploadConcurrency = 4
)

// S3Storage handles uploads and downloads to S3/MinIO.
type S3Storage struct {
	client *s3.Client
	bucket string
}

// NewS3Storage creates a new S3Storage instance.
func NewS3Storage(cfg hgtypes.S3Config) (*S3Storage, error) {
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	ctx := context.Background()
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	opts := func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = &cfg.Endpoint
			o.UsePathStyle = true // Required for MinIO
		}
	}

	client := s3.NewFromConfig(awsCfg, opts)

	return &S3Storage{
		client: client,
		bucket: cfg.Bucket,
	}, nil
}

// UploadScanResults uploads the scan envelope JSON.
func (s *S3Storage) UploadScanResults(scanID string, envelope *hgtypes.ScanEnvelope) (string, error) {
	key := fmt.Sprintf("scans/%s/envelope.json", scanID)
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return "", err
	}
	return key, s.putObject(key, data, "application/json")
}

// UploadRawResult uploads a raw scanner result JSON.
func (s *S3Storage) UploadRawResult(scanID, scannerName string, data interface{}) (string, error) {
	key := fmt.Sprintf("scans/%s/raw/%s.json", scanID, scannerName)
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return key, s.putObject(key, b, "application/json")
}

// UploadSbom uploads the SBOM file.
func (s *S3Storage) UploadSbom(scanID string, data interface{}) (string, error) {
	key := fmt.Sprintf("scans/%s/sbom.cdx.json", scanID)
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return key, s.putObject(key, b, "application/json")
}

// UploadArtifactStream uploads a file from disk to S3 (optionally to an
// override bucket) and returns the size in bytes plus the SHA-256 of the
// bytes uploaded. When bucket is empty, the storage's default bucket is
// used.
//
// Uses the SDK's multipart Uploader so files larger than the 5 GB
// single-PUT cap upload successfully — image tarballs routinely cross
// that line. The Uploader picks single-PUT under PartSize and switches
// to multipart automatically.
//
// Hash is computed in a separate pre-pass rather than via a TeeReader
// during upload. The earlier TeeReader shape was wrong under SDK
// retries: the AWS SDK rewinds Body via Seek to retry signed requests,
// but a TeeReader is not seekable, and the captured hasher would not
// reset between attempts. With multipart upload the retry surface is
// even larger (each part can retry independently), so pre-hashing is
// the only correctness-preserving option. Two reads of the same file
// are cheap (the second hits the OS page cache after the first).
func (s *S3Storage) UploadArtifactStream(ctx context.Context, bucket, key, filePath, contentType string) (int64, string, error) {
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

	dest := s.bucket
	if bucket != "" {
		dest = bucket
	}

	uploader := manager.NewUploader(s.client, func(u *manager.Uploader) {
		u.PartSize = uploadPartSize
		u.Concurrency = uploadConcurrency
	})

	input := &s3.PutObjectInput{
		Bucket: &dest,
		Key:    &key,
		Body:   f,
	}
	if contentType != "" {
		input.ContentType = &contentType
	}

	if _, err := uploader.Upload(ctx, input); err != nil {
		return 0, "", err
	}
	return size, sha, nil
}

// PresignGetForBucket is a bucket-aware variant of GetPresignedURL. When
// bucket is empty, the storage's default bucket is used. Used by the
// exporter so a job can target a non-default bucket and still receive a
// presigned URL pointing at it.
func (s *S3Storage) PresignGetForBucket(bucket, key string, expiresIn time.Duration) (string, error) {
	dest := s.bucket
	if bucket != "" {
		dest = bucket
	}
	presigner := s3.NewPresignClient(s.client)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: &dest,
		Key:    &key,
	}, s3.WithPresignExpires(expiresIn))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

// UploadArtifact uploads a file from disk to an arbitrary S3 key.
func (s *S3Storage) UploadArtifact(key, filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	contentLength := stat.Size()
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        &s.bucket,
		Key:           &key,
		Body:          f,
		ContentLength: &contentLength,
	})
	return key, err
}

// GetPresignedURL returns a presigned download URL for a key.
func (s *S3Storage) GetPresignedURL(key string, expiresIn time.Duration) (string, error) {
	presigner := s3.NewPresignClient(s.client)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: &s.bucket,
		Key:    &key,
	}, s3.WithPresignExpires(expiresIn))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

// Exists checks if an object exists in S3.
func (s *S3Storage) Exists(key string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &s.bucket,
		Key:    &key,
	})
	if err != nil {
		var nsk *types.NotFound
		if ok := isNotFoundError(err, nsk); ok {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// DownloadToFile downloads an S3 object to a local file.
func (s *S3Storage) DownloadToFile(key, destPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &s.bucket,
		Key:    &key,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	f, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func (s *S3Storage) putObject(key string, data []byte, contentType string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &s.bucket,
		Key:         &key,
		Body:        bytes.NewReader(data),
		ContentType: &contentType,
	})
	return err
}

func isNotFoundError(err error, _ *types.NotFound) bool {
	// Simple string check as fallback
	return err != nil && (fmt.Sprintf("%v", err) == "NotFound" || fmt.Sprintf("%T", err) == "*types.NotFound")
}
