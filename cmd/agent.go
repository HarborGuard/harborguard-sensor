package cmd

import "github.com/spf13/cobra"

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run as long-lived agent, polling dashboard for jobs",
	RunE:  runAgent,
}

func init() {
	agentCmd.Flags().String("dashboard-url", "", "Dashboard URL (env: HG_DASHBOARD_URL)")
	agentCmd.Flags().String("api-key", "", "API key (env: HG_API_KEY)")
	agentCmd.Flags().String("name", "", "Agent name (env: HG_AGENT_NAME)")
	agentCmd.Flags().String("poll-interval", "10000", "Poll interval in ms")
}

func runAgent(cmd *cobra.Command, args []string) error {
	// Implemented in later step
	return nil
}
