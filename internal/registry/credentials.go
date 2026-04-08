package registry

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// CredentialResolver resolves and caches registry credentials with TTL.
type CredentialResolver struct {
	registryURL   string
	provider      types.RegistryProvider
	explicitUser  string
	explicitToken string

	mu     sync.Mutex
	cached *types.ResolvedCredentials
}

// NewCredentialResolver creates a resolver for the given registry config.
func NewCredentialResolver(cfg types.RegistryConfig, provider types.RegistryProvider) *CredentialResolver {
	return &CredentialResolver{
		registryURL:   cfg.URL,
		provider:      provider,
		explicitUser:  cfg.Username,
		explicitToken: cfg.Token,
	}
}

// GetCredentials returns current valid credentials, re-resolving if expired.
// Returns nil, nil for anonymous access.
func (cr *CredentialResolver) GetCredentials(ctx context.Context) (*types.ResolvedCredentials, error) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	if cr.cached != nil && !cr.isExpired(cr.cached) {
		return cr.cached, nil
	}

	creds, err := cr.resolve(ctx)
	if err != nil {
		return nil, err
	}
	cr.cached = creds
	return creds, nil
}

// isExpired checks if credentials are expired or within 5-minute refresh buffer.
func (cr *CredentialResolver) isExpired(creds *types.ResolvedCredentials) bool {
	if creds.ExpiresAt == nil {
		return false
	}
	return time.Now().Add(5 * time.Minute).After(*creds.ExpiresAt)
}

// resolve implements the credential resolution chain:
// 1. Explicit (HG_REGISTRY_USER + HG_REGISTRY_TOKEN)
// 2. Cloud-native by provider (ECR IAM, GCP service account, Azure AD)
// 3. Anonymous (nil)
func (cr *CredentialResolver) resolve(ctx context.Context) (*types.ResolvedCredentials, error) {
	// Step 1: Explicit credentials
	if cr.explicitUser != "" && cr.explicitToken != "" {
		return &types.ResolvedCredentials{
			Username: cr.explicitUser,
			Password: cr.explicitToken,
		}, nil
	}

	// Step 2: Cloud-native resolution
	switch cr.provider {
	case types.ProviderECR:
		return resolveECRToken(ctx, cr.registryURL)
	case types.ProviderGAR:
		return cr.resolveGAR()
	case types.ProviderACR:
		return cr.resolveACR()
	}

	// Step 3: Anonymous
	return nil, nil
}

// resolveGAR uses Google Application Default Credentials.
func (cr *CredentialResolver) resolveGAR() (*types.ResolvedCredentials, error) {
	credFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(credFile)
	if err != nil {
		return nil, fmt.Errorf("reading GCP credentials file: %w", err)
	}
	expiry := time.Now().Add(55 * time.Minute)
	return &types.ResolvedCredentials{
		Username:  "_json_key",
		Password:  string(data),
		ExpiresAt: &expiry,
	}, nil
}

// resolveACR uses Azure service principal env vars.
func (cr *CredentialResolver) resolveACR() (*types.ResolvedCredentials, error) {
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	tenantID := os.Getenv("AZURE_TENANT_ID")
	if clientID == "" || clientSecret == "" || tenantID == "" {
		return nil, nil
	}
	return &types.ResolvedCredentials{
		Username: clientID,
		Password: clientSecret,
	}, nil
}
