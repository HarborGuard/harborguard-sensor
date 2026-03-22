package cmd

import (
	"context"

	"github.com/spf13/cobra"

	agentpkg "github.com/HarborGuard/harborguard-sensor/internal/agent"
	"github.com/HarborGuard/harborguard-sensor/internal/config"
)

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
	dashboardURL, _ := cmd.Flags().GetString("dashboard-url")
	apiKey, _ := cmd.Flags().GetString("api-key")
	name, _ := cmd.Flags().GetString("name")
	pollInterval, _ := cmd.Flags().GetString("poll-interval")

	cfg, err := config.LoadConfig(map[string]string{
		"dashboardUrl": dashboardURL,
		"apiKey":       apiKey,
		"agentName":    name,
		"pollInterval": pollInterval,
	})
	if err != nil {
		return err
	}

	return agentpkg.RunAgentLoop(context.Background(), cfg)
}
