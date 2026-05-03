package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// postResultEnvelope marshals envelope as JSON and POSTs it to url with
// `Authorization: Bearer apiKey`. Returns an error on non-2xx responses
// or transport failures. Used by the one-shot subcommands (export,
// patch) to deliver their result envelope back to the dashboard.
//
// Mirrors AgentClient.request — same 30s timeout, same JSON content
// type, same bearer scheme — so dashboards can't distinguish a one-shot
// result POST from an agent-mode result POST. Duplicated here rather
// than reusing AgentClient because AgentClient is anchored to a base
// dashboardURL and a `request(method, path, ...)` shape; the one-shot
// flow is supplied a single absolute URL up-front and doesn't need the
// base/path split (the dashboard mints the full URL the same way it
// mints the upload URL for exports).
func postResultEnvelope(ctx context.Context, url, apiKey string, envelope any) error {
	if url == "" {
		return fmt.Errorf("upload-result-url is required")
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshaling envelope: %w", err)
	}
	postCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(postCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("POST %s %d: %s", url, resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	return nil
}
