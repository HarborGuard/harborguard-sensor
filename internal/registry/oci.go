package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// OCIProvider implements Provider using the OCI Distribution Spec API.
type OCIProvider struct {
	registryURL  string
	providerType types.RegistryProvider
	creds        *CredentialResolver
	httpClient   *http.Client

	// Bearer token cache
	tokenMu    sync.Mutex
	tokenCache map[string]*bearerToken
}

type bearerToken struct {
	Token     string
	ExpiresAt time.Time
}

// NewOCIProvider creates a generic OCI registry provider.
func NewOCIProvider(registryURL string, providerType types.RegistryProvider, creds *CredentialResolver) *OCIProvider {
	return &OCIProvider{
		registryURL:  normalizeRegistryURL(registryURL),
		providerType: providerType,
		creds:        creds,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		tokenCache:   make(map[string]*bearerToken),
	}
}

func (o *OCIProvider) Name() types.RegistryProvider {
	return o.providerType
}

func (o *OCIProvider) ListRepositories(ctx context.Context) ([]string, error) {
	var allRepos []string
	url := o.registryURL + "/v2/_catalog?n=1000"

	for url != "" {
		body, nextURL, err := o.doAuthenticatedGet(ctx, url, "registry:catalog:*")
		if err != nil {
			return nil, fmt.Errorf("catalog request: %w", err)
		}

		var result struct {
			Repositories []string `json:"repositories"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("decoding catalog: %w", err)
		}
		allRepos = append(allRepos, result.Repositories...)
		url = nextURL
	}

	return allRepos, nil
}

func (o *OCIProvider) ListTags(ctx context.Context, repo string) ([]string, error) {
	var allTags []string
	url := fmt.Sprintf("%s/v2/%s/tags/list", o.registryURL, repo)
	scope := fmt.Sprintf("repository:%s:pull", repo)

	for url != "" {
		body, nextURL, err := o.doAuthenticatedGet(ctx, url, scope)
		if err != nil {
			return nil, fmt.Errorf("tags request for %s: %w", repo, err)
		}

		var result struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("decoding tags for %s: %w", repo, err)
		}
		allTags = append(allTags, result.Tags...)
		url = nextURL
	}

	return allTags, nil
}

// doAuthenticatedGet performs a GET request with authentication.
// It handles the OCI Bearer token challenge flow automatically.
// Returns body bytes, next pagination URL (empty if none), and error.
func (o *OCIProvider) doAuthenticatedGet(ctx context.Context, url, scope string) ([]byte, string, error) {
	// Try with cached bearer token first
	if token := o.getCachedToken(scope); token != "" {
		body, nextURL, err := o.doGetWithAuth(ctx, url, "Bearer "+token)
		if err == nil {
			return body, nextURL, nil
		}
		// Token may have expired, fall through to re-auth
	}

	// Try with basic auth or no auth
	basicAuth, err := o.getBasicAuthHeader(ctx)
	if err != nil {
		return nil, "", err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}
	if basicAuth != "" {
		req.Header.Set("Authorization", basicAuth)
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// If 401 with WWW-Authenticate Bearer challenge, do token exchange
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("WWW-Authenticate")
		if strings.HasPrefix(challenge, "Bearer ") {
			token, err := o.fetchBearerToken(ctx, challenge, scope, basicAuth)
			if err != nil {
				return nil, "", fmt.Errorf("bearer token exchange: %w", err)
			}
			return o.doGetWithAuth(ctx, url, "Bearer "+token)
		}
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("unauthorized (no bearer challenge): %s", string(body))
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("request failed (%d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("reading response: %w", err)
	}

	return body, getNextLink(resp.Header.Get("Link"), o.registryURL), nil
}

// doGetWithAuth performs a GET with a pre-built Authorization header value.
func (o *OCIProvider) doGetWithAuth(ctx context.Context, url, authHeader string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", authHeader)

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, "", fmt.Errorf("unauthorized with provided credentials")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("request failed (%d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("reading response: %w", err)
	}

	return body, getNextLink(resp.Header.Get("Link"), o.registryURL), nil
}

// fetchBearerToken exchanges credentials for a Bearer token using the WWW-Authenticate challenge.
func (o *OCIProvider) fetchBearerToken(ctx context.Context, challenge, scope, basicAuth string) (string, error) {
	params := parseBearerChallenge(challenge)
	realm := params["realm"]
	if realm == "" {
		return "", fmt.Errorf("no realm in bearer challenge")
	}

	// Build token request URL
	tokenURL := realm
	sep := "?"
	if strings.Contains(tokenURL, "?") {
		sep = "&"
	}
	if service, ok := params["service"]; ok && service != "" {
		tokenURL += sep + "service=" + service
		sep = "&"
	}
	if scope != "" {
		tokenURL += sep + "scope=" + scope
	}

	req, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}
	if basicAuth != "" {
		req.Header.Set("Authorization", basicAuth)
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed (%d): %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}

	token := tokenResp.Token
	if token == "" {
		token = tokenResp.AccessToken
	}
	if token == "" {
		return "", fmt.Errorf("empty token in response")
	}

	// Cache the token
	ttl := time.Duration(tokenResp.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	o.tokenMu.Lock()
	o.tokenCache[scope] = &bearerToken{
		Token:     token,
		ExpiresAt: time.Now().Add(ttl - 30*time.Second), // 30s buffer
	}
	o.tokenMu.Unlock()

	return token, nil
}

// getBasicAuthHeader returns a Basic auth header value from the credential resolver.
func (o *OCIProvider) getBasicAuthHeader(ctx context.Context) (string, error) {
	creds, err := o.creds.GetCredentials(ctx)
	if err != nil {
		return "", err
	}
	if creds == nil {
		return "", nil
	}
	req := &http.Request{Header: http.Header{}}
	req.SetBasicAuth(creds.Username, creds.Password)
	return req.Header.Get("Authorization"), nil
}

// getCachedToken returns a cached bearer token for the given scope, or empty if expired/missing.
func (o *OCIProvider) getCachedToken(scope string) string {
	o.tokenMu.Lock()
	defer o.tokenMu.Unlock()
	if bt, ok := o.tokenCache[scope]; ok && time.Now().Before(bt.ExpiresAt) {
		return bt.Token
	}
	return ""
}

// parseBearerChallenge parses a WWW-Authenticate: Bearer challenge header into key-value pairs.
// Example: Bearer realm="https://auth.example.com/token",service="registry.example.com",scope="repository:foo:pull"
func parseBearerChallenge(challenge string) map[string]string {
	params := make(map[string]string)
	s := strings.TrimPrefix(challenge, "Bearer ")

	for s != "" {
		s = strings.TrimLeft(s, " ,")
		eqIdx := strings.Index(s, "=")
		if eqIdx < 0 {
			break
		}
		key := s[:eqIdx]
		s = s[eqIdx+1:]

		var value string
		if strings.HasPrefix(s, `"`) {
			s = s[1:]
			endQuote := strings.Index(s, `"`)
			if endQuote < 0 {
				value = s
				s = ""
			} else {
				value = s[:endQuote]
				s = s[endQuote+1:]
			}
		} else {
			commaIdx := strings.Index(s, ",")
			if commaIdx < 0 {
				value = s
				s = ""
			} else {
				value = s[:commaIdx]
				s = s[commaIdx:]
			}
		}
		params[key] = value
	}

	return params
}

// normalizeRegistryURL ensures the URL has an https:// scheme and no trailing slash.
func normalizeRegistryURL(rawURL string) string {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	return strings.TrimRight(rawURL, "/")
}

// getNextLink parses the Link header for pagination (RFC 5988).
func getNextLink(linkHeader, baseURL string) string {
	if linkHeader == "" {
		return ""
	}
	// Format: </v2/_catalog?last=xxx&n=100>; rel="next"
	for _, part := range strings.Split(linkHeader, ",") {
		part = strings.TrimSpace(part)
		segments := strings.SplitN(part, ";", 2)
		if len(segments) != 2 {
			continue
		}
		if !strings.Contains(segments[1], `rel="next"`) {
			continue
		}
		url := strings.Trim(strings.TrimSpace(segments[0]), "<>")
		if strings.HasPrefix(url, "/") {
			return baseURL + url
		}
		return url
	}
	return ""
}
