package cmd

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "harborguard-sensor",
	Short: "HarborGuard container security scanning sensor",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(agentCmd)
	rootCmd.AddCommand(versionCmd)
}
