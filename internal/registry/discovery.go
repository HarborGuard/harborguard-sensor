package registry

import (
	"context"
	"fmt"
	"os"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// Discoverer manages registry discovery runs.
type Discoverer struct {
	provider Provider
	creds    *CredentialResolver
	cfg      types.RegistryConfig
}

// NewDiscoverer creates a Discoverer from the registry config.
// Returns nil, nil if no registry URL is configured (discovery disabled).
func NewDiscoverer(cfg types.RegistryConfig) (*Discoverer, error) {
	if cfg.URL == "" {
		return nil, nil
	}

	providerType := DetectProvider(cfg.URL)
	credResolver := NewCredentialResolver(cfg, providerType)

	var provider Provider
	var err error

	switch providerType {
	case types.ProviderECR:
		provider, err = NewECRProvider(cfg.URL, credResolver)
		if err != nil {
			return nil, fmt.Errorf("initializing ECR provider: %w", err)
		}
	default:
		provider = NewOCIProvider(cfg.URL, providerType, credResolver)
	}

	return &Discoverer{
		provider: provider,
		creds:    credResolver,
		cfg:      cfg,
	}, nil
}

// Discover runs a single discovery cycle: lists all repos and their tags.
func (d *Discoverer) Discover(ctx context.Context) ([]types.DiscoveredRepository, error) {
	fmt.Fprintf(os.Stderr, "[discovery] Starting catalog discovery for %s (%s)\n",
		d.cfg.URL, d.provider.Name())

	repos, err := d.provider.ListRepositories(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing repositories: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[discovery] Found %d repositories\n", len(repos))

	var discovered []types.DiscoveredRepository
	for _, repo := range repos {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		tags, err := d.provider.ListTags(ctx, repo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[discovery] Failed to list tags for %s: %s\n", repo, err.Error())
			discovered = append(discovered, types.DiscoveredRepository{
				Name: repo,
				Tags: []string{},
			})
			continue
		}

		discovered = append(discovered, types.DiscoveredRepository{
			Name: repo,
			Tags: tags,
		})
	}

	fmt.Fprintf(os.Stderr, "[discovery] Discovery complete: %d repositories cataloged\n", len(discovered))
	return discovered, nil
}

// GetCredentials exposes the credential resolver for scanner passthrough.
func (d *Discoverer) GetCredentials(ctx context.Context) (*types.ResolvedCredentials, error) {
	return d.creds.GetCredentials(ctx)
}

// ProviderName returns the detected provider type.
func (d *Discoverer) ProviderName() types.RegistryProvider {
	return d.provider.Name()
}
