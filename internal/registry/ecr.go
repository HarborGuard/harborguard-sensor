package registry

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// ECRProvider implements Provider using the AWS ECR API.
type ECRProvider struct {
	registryURL string
	region      string
	creds       *CredentialResolver
	ecrClient   *ecr.Client
}

// NewECRProvider creates an ECR-specific provider.
func NewECRProvider(registryURL string, creds *CredentialResolver) (*ECRProvider, error) {
	region := extractECRRegion(registryURL)
	if region == "" {
		return nil, fmt.Errorf("unable to detect AWS region from ECR URL: %s", registryURL)
	}

	ctx := context.Background()
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	return &ECRProvider{
		registryURL: registryURL,
		region:      region,
		creds:       creds,
		ecrClient:   ecr.NewFromConfig(cfg),
	}, nil
}

func (e *ECRProvider) Name() types.RegistryProvider {
	return types.ProviderECR
}

func (e *ECRProvider) ListRepositories(ctx context.Context) ([]string, error) {
	var repos []string
	var nextToken *string

	for {
		result, err := e.ecrClient.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("ECR DescribeRepositories: %w", err)
		}
		for _, repo := range result.Repositories {
			if repo.RepositoryName != nil {
				repos = append(repos, *repo.RepositoryName)
			}
		}
		if result.NextToken == nil {
			break
		}
		nextToken = result.NextToken
	}

	return repos, nil
}

func (e *ECRProvider) ListTags(ctx context.Context, repo string) ([]string, error) {
	var tags []string
	var nextToken *string

	for {
		result, err := e.ecrClient.ListImages(ctx, &ecr.ListImagesInput{
			RepositoryName: &repo,
			Filter:         &ecrtypes.ListImagesFilter{TagStatus: ecrtypes.TagStatusTagged},
			NextToken:      nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("ECR ListImages for %s: %w", repo, err)
		}
		for _, id := range result.ImageIds {
			if id.ImageTag != nil {
				tags = append(tags, *id.ImageTag)
			}
		}
		if result.NextToken == nil {
			break
		}
		nextToken = result.NextToken
	}

	return tags, nil
}

// resolveECRToken obtains an ECR authorization token via GetAuthorizationToken.
// Called by CredentialResolver for ECR registries.
func resolveECRToken(ctx context.Context, registryURL string) (*types.ResolvedCredentials, error) {
	region := extractECRRegion(registryURL)
	if region == "" {
		return nil, fmt.Errorf("cannot detect region from ECR URL: %s", registryURL)
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config for ECR token: %w", err)
	}

	client := ecr.NewFromConfig(cfg)
	result, err := client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, fmt.Errorf("ECR GetAuthorizationToken: %w", err)
	}

	if len(result.AuthorizationData) == 0 {
		return nil, fmt.Errorf("ECR returned no authorization data")
	}

	authData := result.AuthorizationData[0]
	decoded, err := base64.StdEncoding.DecodeString(*authData.AuthorizationToken)
	if err != nil {
		return nil, fmt.Errorf("decoding ECR token: %w", err)
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("unexpected ECR token format")
	}

	return &types.ResolvedCredentials{
		Username:  parts[0], // "AWS"
		Password:  parts[1],
		ExpiresAt: authData.ExpiresAt,
	}, nil
}

// extractECRRegion extracts the AWS region from an ECR URL.
// Pattern: <account>.dkr.ecr.<region>.amazonaws.com
func extractECRRegion(registryURL string) string {
	host := extractHost(registryURL)
	parts := strings.Split(host, ".")
	for i, p := range parts {
		if p == "ecr" && i+1 < len(parts) && parts[len(parts)-2] == "amazonaws" {
			return parts[i+1]
		}
	}
	return ""
}
