package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	hgtypes "github.com/HarborGuard/harborguard-sensor/internal/types"
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
