package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/HarborGuard/harborguard-sensor/internal/scanner"
)

const version = "0.1.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print sensor and scanner versions",
	RunE:  runVersion,
}

func runVersion(cmd *cobra.Command, args []string) error {
	fmt.Printf("harborguard-sensor v%s\n", version)
	fmt.Println()

	scannerNames := []string{"trivy", "grype", "syft", "dockle", "dive", "osv"}
	for _, name := range scannerNames {
		s, err := scanner.NewScanner(name)
		if err != nil {
			fmt.Printf("  %s: not installed\n", name)
			continue
		}
		if s.IsAvailable() {
			fmt.Printf("  %s: %s\n", name, s.GetVersion())
		} else {
			fmt.Printf("  %s: not installed\n", name)
		}
	}

	return nil
}
