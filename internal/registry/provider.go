package registry

import (
	"context"
	"strings"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// Provider is the interface for registry discovery implementations.
type Provider interface {
	// Name returns the provider identifier.
	Name() types.RegistryProvider

	// ListRepositories returns all repository names in the registry.
	ListRepositories(ctx context.Context) ([]string, error)

	// ListTags returns all tags for a given repository.
	ListTags(ctx context.Context, repo string) ([]string, error)
}

// DetectProvider determines the registry provider from a URL string.
func DetectProvider(registryURL string) types.RegistryProvider {
	host := extractHost(registryURL)
	lower := strings.ToLower(host)

	switch {
	case strings.Contains(lower, ".dkr.ecr.") && strings.HasSuffix(lower, ".amazonaws.com"):
		return types.ProviderECR
	case strings.HasSuffix(lower, "-docker.pkg.dev"):
		return types.ProviderGAR
	case strings.HasSuffix(lower, ".azurecr.io"):
		return types.ProviderACR
	case lower == "docker.io" || lower == "registry-1.docker.io" || lower == "index.docker.io":
		return types.ProviderDockerHub
	case lower == "ghcr.io":
		return types.ProviderGHCR
	case lower == "registry.gitlab.com" || strings.HasSuffix(lower, ":5050"):
		return types.ProviderGitLab
	default:
		return types.ProviderGeneric
	}
}

// extractHost strips scheme and path from a URL, returning the host:port portion.
func extractHost(rawURL string) string {
	s := rawURL
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	return s
}
