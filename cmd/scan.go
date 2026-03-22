package cmd

import "github.com/spf13/cobra"

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
	// Implemented in later step
	return nil
}
