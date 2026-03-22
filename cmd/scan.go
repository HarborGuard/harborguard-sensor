package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/HarborGuard/harborguard-sensor/internal/adapter"
	"github.com/HarborGuard/harborguard-sensor/internal/agent"
	"github.com/HarborGuard/harborguard-sensor/internal/config"
	"github.com/HarborGuard/harborguard-sensor/internal/scanner"
	"github.com/HarborGuard/harborguard-sensor/internal/storage"
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

var scanCmd = &cobra.Command{
	Use:   "scan <image>",
	Short: "One-shot scan of a container image",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().String("source", "docker", "Image source: docker, registry, tar")
	scanCmd.Flags().String("scanners", "", "Comma-separated scanner list")
	scanCmd.Flags().String("output", "table", "Output format: json, table, envelope")
	scanCmd.Flags().String("output-file", "", "Write results to file")
	scanCmd.Flags().String("upload-url", "", "Upload results to dashboard URL")
	scanCmd.Flags().String("api-key", "", "API key for dashboard upload")
	scanCmd.Flags().String("s3-bucket", "", "S3 bucket for artifact storage")
}

func runScan(cmd *cobra.Command, args []string) error {
	image := args[0]
	sourceType, _ := cmd.Flags().GetString("source")
	scannersFlag, _ := cmd.Flags().GetString("scanners")
	outputFmt, _ := cmd.Flags().GetString("output")
	outputFile, _ := cmd.Flags().GetString("output-file")
	uploadURL, _ := cmd.Flags().GetString("upload-url")
	apiKey, _ := cmd.Flags().GetString("api-key")
	s3Bucket, _ := cmd.Flags().GetString("s3-bucket")

	cfg, err := config.LoadConfig(map[string]string{
		"scanners": scannersFlag,
	})
	if err != nil {
		return err
	}

	var source types.ImageSource
	switch sourceType {
	case "tar":
		source = types.ImageSource{Type: "tar", Path: image}
	case "registry":
		source = types.ImageSource{Type: "registry", Ref: image}
	default:
		source = types.ImageSource{Type: "docker", Ref: image}
	}

	scanID := uuid.New().String()
	orch := &scanner.Orchestrator{Config: cfg}

	fmt.Fprintf(os.Stderr, "[scan] Scanning %s (source: %s)...\n", image, sourceType)

	var scanners []string
	if scannersFlag != "" {
		for _, s := range splitComma(scannersFlag) {
			scanners = append(scanners, s)
		}
	}

	output, err := orch.Execute(types.ScanJob{
		ID:       scanID,
		ImageRef: image,
		Source:   source,
		Scanners: scanners,
	})
	if err != nil {
		return err
	}

	envelope := adapter.BuildEnvelope(
		types.ScanJob{ID: scanID, ImageRef: image, Source: source},
		output,
	)

	// S3 upload if configured
	bucket := s3Bucket
	if bucket == "" {
		bucket = cfg.S3Bucket
	}
	if bucket != "" && cfg.S3AccessKey != "" && cfg.S3SecretKey != "" {
		s3store, s3err := storage.NewS3Storage(types.S3Config{
			Endpoint:  cfg.S3Endpoint,
			Bucket:    bucket,
			AccessKey: cfg.S3AccessKey,
			SecretKey: cfg.S3SecretKey,
			Region:    cfg.S3Region,
		})
		if s3err == nil {
			rawResults := make(map[string]string)
			for scannerName, result := range output.Results {
				if result.Data != nil {
					if key, uploadErr := s3store.UploadRawResult(scanID, scannerName, result.Data); uploadErr == nil {
						rawResults[scannerName] = key
					}
				}
			}

			var sbom string
			if syftResult, ok := output.Results["syft"]; ok && syftResult.Data != nil {
				if key, uploadErr := s3store.UploadSbom(scanID, syftResult.Data); uploadErr == nil {
					sbom = key
				}
			}

			envelope.Artifacts = &types.EnvelopeArtifacts{
				S3Prefix:   fmt.Sprintf("scans/%s/", scanID),
				RawResults: rawResults,
				Sbom:       sbom,
			}

			_, _ = s3store.UploadScanResults(scanID, envelope)
			fmt.Fprintf(os.Stderr, "[scan] Results uploaded to S3: scans/%s/\n", scanID)
		}
	}

	// Dashboard upload
	url := uploadURL
	if url == "" {
		url = cfg.DashboardURL
	}
	key := apiKey
	if key == "" {
		key = cfg.APIKey
	}
	if url != "" && key != "" {
		client := agent.NewAgentClient(url, key)
		if _, _, uploadErr := client.UploadResults(envelope); uploadErr == nil {
			fmt.Fprintln(os.Stderr, "[scan] Results uploaded to dashboard")
		}
	}

	// Output
	if outputFmt == "json" || outputFmt == "envelope" {
		jsonData, _ := json.MarshalIndent(envelope, "", "  ")
		if outputFile != "" {
			if writeErr := os.WriteFile(outputFile, jsonData, 0644); writeErr != nil {
				return writeErr
			}
			fmt.Fprintf(os.Stderr, "[scan] Results written to %s\n", outputFile)
		} else {
			fmt.Println(string(jsonData))
		}
	} else {
		// Table output
		printTable(envelope)
		if outputFile != "" {
			jsonData, _ := json.MarshalIndent(envelope, "", "  ")
			if writeErr := os.WriteFile(outputFile, jsonData, 0644); writeErr != nil {
				return writeErr
			}
			fmt.Fprintf(os.Stderr, "[scan] Full results written to %s\n", outputFile)
		}
	}

	// Exit with non-zero if critical/high vulnerabilities found
	counts := envelope.Aggregates.VulnerabilityCounts
	if counts.Critical > 0 || counts.High > 0 {
		os.Exit(1)
	}

	return nil
}

func printTable(envelope *types.ScanEnvelope) {
	c := envelope.Aggregates.VulnerabilityCounts
	fmt.Println()
	fmt.Printf("Image: %s\n", envelope.Image.Ref)
	fmt.Printf("Scan:  %s (%s)\n", envelope.Scan.ID, envelope.Scan.Status)
	fmt.Println()
	fmt.Println("Vulnerabilities:")
	fmt.Printf("  CRITICAL: %d  HIGH: %d  MEDIUM: %d  LOW: %d  INFO: %d\n",
		c.Critical, c.High, c.Medium, c.Low, c.Info)
	fmt.Printf("  Risk Score: %d/100\n", envelope.Aggregates.RiskScore)
	fmt.Println()
	fmt.Printf("Packages: %d\n", envelope.Aggregates.TotalPackages)

	if envelope.Aggregates.ComplianceScore != nil {
		fmt.Printf("Compliance: %d/100 (%s)\n", *envelope.Aggregates.ComplianceScore, envelope.Aggregates.ComplianceGrade)
	}

	if len(envelope.Findings.Efficiency) > 0 {
		fmt.Printf("Efficiency: %d findings\n", len(envelope.Findings.Efficiency))
	}
	fmt.Println()
}

func splitComma(s string) []string {
	var result []string
	for _, p := range splitTrimFields(s) {
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func splitTrimFields(s string) []string {
	var parts []string
	for _, p := range splitByComma(s) {
		p = trimSpace(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func splitByComma(s string) []string {
	result := []string{""}
	for _, c := range s {
		if c == ',' {
			result = append(result, "")
		} else {
			result[len(result)-1] += string(c)
		}
	}
	return result
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
