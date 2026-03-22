package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// AgentClient communicates with the dashboard API.
type AgentClient struct {
	dashboardURL string
	apiKey       string
	agentID      string
	httpClient   *http.Client
}

// NewAgentClient creates a new AgentClient.
func NewAgentClient(dashboardURL, apiKey string) *AgentClient {
	return &AgentClient{
		dashboardURL: dashboardURL,
		apiKey:       apiKey,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
	}
}

// GetAgentID returns the registered agent ID.
func (c *AgentClient) GetAgentID() string {
	return c.agentID
}

func (c *AgentClient) request(method, path string, body interface{}, result interface{}) error {
	url := c.dashboardURL + path

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s failed: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		text, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s failed (%d): %s", method, path, resp.StatusCode, string(text))
	}

	if result != nil && resp.Header.Get("Content-Type") != "" {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}

// Register registers the agent with the dashboard.
func (c *AgentClient) Register(info types.AgentRegistration) (string, error) {
	var result struct {
		AgentID string `json:"agentId"`
	}
	if err := c.request("POST", "/api/agent/register", info, &result); err != nil {
		return "", err
	}
	c.agentID = result.AgentID
	return result.AgentID, nil
}

// Heartbeat sends a heartbeat to the dashboard.
func (c *AgentClient) Heartbeat(status types.AgentHeartbeat) error {
	return c.request("POST", "/api/agent/heartbeat", status, nil)
}

// PollJobs polls for available jobs.
func (c *AgentClient) PollJobs() ([]types.AgentJob, error) {
	if c.agentID == "" {
		return nil, fmt.Errorf("Agent not registered")
	}
	var jobs []types.AgentJob
	path := fmt.Sprintf("/api/agent/jobs?agentId=%s", c.agentID)
	if err := c.request("GET", path, nil, &jobs); err != nil {
		return nil, err
	}
	return jobs, nil
}

// UploadResults uploads scan results to the dashboard.
func (c *AgentClient) UploadResults(envelope *types.ScanEnvelope) (string, string, error) {
	var result struct {
		ScanID  string `json:"scanId"`
		ImageID string `json:"imageId"`
	}
	if err := c.request("POST", "/api/scans/upload", envelope, &result); err != nil {
		return "", "", err
	}
	return result.ScanID, result.ImageID, nil
}

// ReportJobStatus reports the status of a completed job.
func (c *AgentClient) ReportJobStatus(jobID, status string, errMsg string) error {
	body := map[string]interface{}{
		"status": status,
	}
	if errMsg != "" {
		body["error"] = errMsg
	}
	path := fmt.Sprintf("/api/agent/jobs/%s/status", jobID)
	return c.request("POST", path, body, nil)
}
