package types

import "time"

// RegistryProvider identifies the type of container registry.
type RegistryProvider string

const (
	ProviderECR       RegistryProvider = "ecr"
	ProviderGAR       RegistryProvider = "gar"
	ProviderACR       RegistryProvider = "acr"
	ProviderDockerHub RegistryProvider = "dockerhub"
	ProviderGHCR      RegistryProvider = "ghcr"
	ProviderGitLab    RegistryProvider = "gitlab"
	ProviderGeneric   RegistryProvider = "generic"
)

// RegistryConfig holds configuration for registry discovery.
//
// Insecure is set from HG_REGISTRY_INSECURE and tells the discovery
// client to talk plain http to the registry's v2 endpoints (when no
// scheme is on URL) and to skip TLS verification when an https endpoint
// is reached anyway (e.g. via WWW-Authenticate redirect to a separate
// auth server). An explicit https:// scheme on URL always wins —
// Insecure only governs the otherwise-default scheme choice.
type RegistryConfig struct {
	URL                 string
	Username            string
	Token               string
	DiscoveryIntervalMs int
	Insecure            bool
}

// ResolvedCredentials holds registry credentials with optional expiry for token refresh.
type ResolvedCredentials struct {
	Username  string
	Password  string
	ExpiresAt *time.Time
}

// DiscoveredRepository represents a single repository found in a registry.
type DiscoveredRepository struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// CatalogReport is the payload sent to POST /api/agent/catalog.
type CatalogReport struct {
	AgentID      string                 `json:"agentId"`
	RegistryURL  string                 `json:"registryUrl"`
	Provider     string                 `json:"provider"`
	Repositories []DiscoveredRepository `json:"repositories"`
	DiscoveredAt string                 `json:"discoveredAt"`
	Error        string                 `json:"error,omitempty"`
}

// ImageSource represents the source of a container image to scan.
//
// Insecure is set by the orchestrator when the caller supplies an
// http://-scheme ref, and tells per-scanner command builders to emit
// TLS-skip flags (trivy --insecure, grype/syft GRYPE_REGISTRY_INSECURE_*
// env, skopeo --src-tls-verify=false) rather than letting the scheme
// reach a scanner's image-reference parser — which universally rejects
// it.
type ImageSource struct {
	Type     string `json:"type"` // "docker", "registry", "tar", "s3"
	Ref      string `json:"ref,omitempty"`
	Path     string `json:"path,omitempty"`
	S3Key    string `json:"s3Key,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
}

// ScannerResult holds the output of a single scanner run.
type ScannerResult struct {
	Scanner    string      `json:"scanner"`
	Success    bool        `json:"success"`
	Data       interface{} `json:"data,omitempty"`
	Error      string      `json:"error,omitempty"`
	DurationMs int64       `json:"durationMs"`
	Version    string      `json:"version,omitempty"`
}

// ScanJob describes a scan to execute.
type ScanJob struct {
	ID       string      `json:"id"`
	ImageRef string      `json:"imageRef"`
	Source   ImageSource `json:"source"`
	Scanners []string    `json:"scanners,omitempty"`
}

// ScanOutput is the raw output from the orchestrator.
type ScanOutput struct {
	JobID      string                    `json:"jobId"`
	ImageRef   string                    `json:"imageRef"`
	StartedAt  string                    `json:"startedAt"`
	FinishedAt string                    `json:"finishedAt"`
	Results    map[string]*ScannerResult `json:"results"`
	Metadata   ScanOutputMetadata        `json:"metadata"`
	Cancelled  bool                      `json:"cancelled,omitempty"`
}

// ScanOutputMetadata contains extracted image info.
type ScanOutputMetadata struct {
	ScannerVersions map[string]string `json:"scannerVersions"`
	ImageDigest     string            `json:"imageDigest,omitempty"`
	ImagePlatform   string            `json:"imagePlatform,omitempty"`
	ImageSizeBytes  *int64            `json:"imageSizeBytes,omitempty"`
}

// ScanEnvelope is the top-level JSON output contract.
type ScanEnvelope struct {
	Version    string              `json:"version"`
	Sensor     EnvelopeSensor      `json:"sensor"`
	Image      EnvelopeImage       `json:"image"`
	Scan       EnvelopeScan        `json:"scan"`
	Findings   EnvelopeFindings    `json:"findings"`
	Aggregates EnvelopeAggregates  `json:"aggregates"`
	Layers     []EnvelopeLayer     `json:"layers,omitempty"`
	Artifacts  *EnvelopeArtifacts  `json:"artifacts,omitempty"`
}

type EnvelopeSensor struct {
	ID              string            `json:"id,omitempty"`
	Name            string            `json:"name,omitempty"`
	Version         string            `json:"version"`
	ScannerVersions map[string]string `json:"scannerVersions"`
}

type EnvelopeImage struct {
	Ref       string `json:"ref"`
	Digest    string `json:"digest,omitempty"`
	Platform  string `json:"platform,omitempty"`
	SizeBytes *int64 `json:"sizeBytes,omitempty"`
	Name      string `json:"name"`
	Tag       string `json:"tag"`
}

type EnvelopeScan struct {
	ID         string `json:"id"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	Status     string `json:"status"` // SUCCESS, PARTIAL, FAILED
}

type EnvelopeFindings struct {
	Vulnerabilities []NormalizedVulnerability `json:"vulnerabilities"`
	Packages        []NormalizedPackage       `json:"packages"`
	Compliance      []NormalizedCompliance    `json:"compliance"`
	Efficiency      []NormalizedEfficiency    `json:"efficiency"`
}

type EnvelopeAggregates struct {
	VulnerabilityCounts VulnerabilityCounts `json:"vulnerabilityCounts"`
	RiskScore           int                 `json:"riskScore"`
	ComplianceScore     *int                `json:"complianceScore,omitempty"`
	ComplianceGrade     string              `json:"complianceGrade,omitempty"`
	TotalPackages       int                 `json:"totalPackages"`
}

type VulnerabilityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type EnvelopeArtifacts struct {
	S3Prefix   string            `json:"s3Prefix,omitempty"`
	RawResults map[string]string `json:"rawResults,omitempty"`
	Sbom       string            `json:"sbom,omitempty"`
}

// NormalizedVulnerability is a scanner-agnostic vulnerability finding.
type NormalizedVulnerability struct {
	CveID            string   `json:"cveId"`
	Source           string   `json:"source"`
	Severity         string   `json:"severity"`
	CvssScore        *float64 `json:"cvssScore,omitempty"`
	Title            string   `json:"title,omitempty"`
	Description      string   `json:"description,omitempty"`
	PackageName      string   `json:"packageName"`
	InstalledVersion string   `json:"installedVersion,omitempty"`
	FixedVersion     string   `json:"fixedVersion,omitempty"`
	VulnerabilityURL string   `json:"vulnerabilityUrl,omitempty"`
}

// NormalizedPackage is a scanner-agnostic package finding.
type NormalizedPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	Source  string `json:"source"`
	License string `json:"license,omitempty"`
	Purl    string `json:"purl,omitempty"`
}

// NormalizedCompliance is a scanner-agnostic compliance finding.
type NormalizedCompliance struct {
	RuleID   string `json:"ruleId"`
	RuleName string `json:"ruleName"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
	Category string `json:"category,omitempty"`
	Message  string `json:"message,omitempty"`
}

// EnvelopeLayer describes a single image layer extracted from Dive analysis.
type EnvelopeLayer struct {
	Index     int         `json:"index"`
	Digest    string      `json:"digest,omitempty"`
	Command   string      `json:"command"`
	SizeBytes int64       `json:"sizeBytes"`
	FileCount int         `json:"fileCount"`
	TopFiles  []LayerFile `json:"topFiles,omitempty"`
}

// LayerFile describes a notable file within a layer.
type LayerFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Status string `json:"status"` // "added", "modified", "removed"
}

// NormalizedEfficiency is a scanner-agnostic efficiency finding.
type NormalizedEfficiency struct {
	FindingType string `json:"findingType"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Source      string `json:"source"`
	SizeBytes   *int64 `json:"sizeBytes,omitempty"`
	Details     string `json:"details,omitempty"`
}

// SensorConfig holds all runtime configuration.
type SensorConfig struct {
	EnabledScanners       []string
	ScanTimeoutMinutes    int
	MaxConcurrentScanners int
	DashboardURL          string
	APIKey                string
	AgentName             string
	SensorID              string
	PollIntervalMs        int
	S3Endpoint            string
	S3Bucket              string
	S3AccessKey           string
	S3SecretKey           string
	S3Region              string
	WorkDir               string
	CacheDir              string
	LogLevel              string
	RegistryURL           string
	RegistryUsername      string
	RegistryToken         string
	RegistryInsecure      bool
	DiscoveryIntervalMs   int
}

// S3Config holds S3 storage configuration.
type S3Config struct {
	Endpoint  string
	Bucket    string
	AccessKey string
	SecretKey string
	Region    string
}

// AgentRegistration is sent to the dashboard on agent startup.
type AgentRegistration struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Hostname        string            `json:"hostname"`
	OS              string            `json:"os"`
	Arch            string            `json:"arch"`
	ScannerVersions map[string]string `json:"scannerVersions"`
	Capabilities    []string          `json:"capabilities"`
	S3Configured    bool              `json:"s3Configured"`
	RegistryURL     string            `json:"registryUrl,omitempty"`
	SensorID        string            `json:"sensorId,omitempty"`
}

// AgentHeartbeat is sent periodically to the dashboard.
type AgentHeartbeat struct {
	AgentID       string `json:"agentId"`
	Status        string `json:"status"` // idle, scanning
	ActiveScans   int    `json:"activeScans"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
}

// AgentJob represents a job received from the dashboard.
type AgentJob struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"` // scan, SCAN, patch, PATCH, export, EXPORT
	CreatedAt string          `json:"createdAt"`
	Scan      *AgentJobScan   `json:"scan,omitempty"`
	Patch     *AgentJobPatch  `json:"patch,omitempty"`
	Export    *AgentJobExport `json:"export,omitempty"`
}

type AgentJobScan struct {
	ImageRef            string                `json:"imageRef"`
	Source              string                `json:"source"` // docker, registry, tar, s3
	TarPath             string                `json:"tarPath,omitempty"`
	S3Key               string                `json:"s3Key,omitempty"`
	Scanners            []string              `json:"scanners,omitempty"`
	RegistryCredentials *RegistryCredentials   `json:"registryCredentials,omitempty"`
}

type RegistryCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AgentJobPatch describes a patch job dispatched from the dashboard.
// The sensor takes an explicit list of packages to upgrade; CVE → package
// resolution happens dashboard-side.
type AgentJobPatch struct {
	Source              ImageSource          `json:"source"`
	SourceCredentials   *RegistryCredentials `json:"sourceCredentials,omitempty"`
	Packages            []PatchPackage       `json:"packages"`
	StrategyHint        string               `json:"strategyHint,omitempty"` // auto | apt | apk | yum | dnf
	Sink                PatchSink            `json:"sink"`
	PreserveConfig      bool                 `json:"preserveConfig,omitempty"`
}

// PatchPackage is a single package to upgrade.
// PackageManager is optional; when blank and StrategyHint=="auto", the sensor
// detects it from the source image.
type PatchPackage struct {
	Name           string `json:"name"`
	TargetVersion  string `json:"targetVersion"`
	PackageManager string `json:"packageManager,omitempty"` // apt | apk | yum | dnf
}

// PatchSink is a tagged union describing where the patched image is shipped.
type PatchSink struct {
	Kind      string               `json:"kind"` // "registry" | "s3" | "presigned"
	Registry  *PatchSinkRegistry   `json:"registry,omitempty"`
	S3        *PatchSinkS3         `json:"s3,omitempty"`
	Presigned *PatchSinkPresigned  `json:"presigned,omitempty"`
}

// PatchSinkRegistry pushes the patched image to a container registry.
//
// Insecure is set by the agent when the supplied Ref carries an http://
// scheme (stripped before reaching skopeo) and tells the sink to add
// --dest-tls-verify=false on the push. Mirrors ImageSource.Insecure on
// the pull side.
type PatchSinkRegistry struct {
	Ref         string               `json:"ref"`                   // e.g. registry.example.com/app
	Tag         string               `json:"tag"`                   // required; sensor never picks a tag
	Credentials *RegistryCredentials `json:"credentials,omitempty"` // optional; falls back to sensor creds
	Insecure    bool                 `json:"insecure,omitempty"`
}

// PatchSinkS3 uploads the patched image tarball to S3 under keyPrefix.
type PatchSinkS3 struct {
	Bucket    string `json:"bucket,omitempty"`    // overrides sensor default
	KeyPrefix string `json:"keyPrefix,omitempty"` // e.g. patches/<id>/
}

// PatchSinkPresigned uploads to S3 and returns a presigned GET URL.
type PatchSinkPresigned struct {
	Bucket    string `json:"bucket,omitempty"`
	KeyPrefix string `json:"keyPrefix,omitempty"`
	TTLSecs   int    `json:"ttlSecs,omitempty"` // default 3600 if unset
}

// PatchJob is the internal sensor-side representation (parallels ScanJob).
type PatchJob struct {
	ID  string          `json:"id"`
	Job AgentJobPatch   `json:"job"`
}

// PatchEnvelope is the top-level JSON uploaded to the dashboard after a patch.
type PatchEnvelope struct {
	Version    string                    `json:"version"`
	Sensor     EnvelopeSensor            `json:"sensor"`
	Source     EnvelopeImage             `json:"source"`
	Patched    EnvelopePatchedImage      `json:"patched"`
	Patch      EnvelopePatch             `json:"patch"`
	Results    []PatchPackageResult      `json:"results"`
	Sink       EnvelopePatchSink         `json:"sink"`
	Tooling    map[string]string         `json:"tooling"` // buildah version + runtime
}

type EnvelopePatchedImage struct {
	Digest string `json:"digest,omitempty"`
	Size   int64  `json:"sizeBytes,omitempty"`
}

type EnvelopePatch struct {
	ID         string `json:"id"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	Status     string `json:"status"` // SUCCESS | PARTIAL | FAILED
}

// PatchPackageResult is the outcome of a single package upgrade.
type PatchPackageResult struct {
	Package        string `json:"package"`
	TargetVersion  string `json:"targetVersion"`
	PackageManager string `json:"packageManager"`
	Status         string `json:"status"` // SUCCESS | FAILED | SKIPPED
	Error          string `json:"error,omitempty"`
}

// EnvelopePatchSink reports where the sensor shipped the result.
type EnvelopePatchSink struct {
	Kind     string `json:"kind"`
	Location string `json:"location,omitempty"`    // registry ref or s3 key
	URL      string `json:"url,omitempty"`         // presigned URL, if applicable
}

// Capability constants advertised in AgentRegistration.Capabilities.
const (
	CapScan      = "scan"
	CapDiscovery = "discovery"
	CapPatch     = "patch"
	CapExport    = "export"
)

// AgentJobExport describes a job to package the source image as a tarball
// and ship it to S3 (using the sensor's configured S3 storage).
//
// The sensor pulls the image to a docker-archive via skopeo, optionally
// gzips it, and PUTs the resulting object under sink.KeyPrefix. When
// sink.Presign is set, a time-limited GET URL is returned in the
// envelope so the dashboard can hand the artifact off without proxying
// multi-GB bytes through its own request path.
type AgentJobExport struct {
	Source            ImageSource          `json:"source"`
	SourceCredentials *RegistryCredentials `json:"sourceCredentials,omitempty"`
	Sink              ExportSink           `json:"sink"`
	// Compress: when true, gzip the tarball before upload. Image layers
	// inside a docker-archive are already gzipped, so a second pass
	// typically saves <5% at meaningful CPU cost — left off by default.
	Compress bool `json:"compress,omitempty"`
}

// ExportSink describes the S3 destination for an export job. Bucket and
// KeyPrefix are optional; bucket defaults to the sensor's configured
// bucket and KeyPrefix to "exports/<jobID>/".
type ExportSink struct {
	Bucket    string `json:"bucket,omitempty"`
	KeyPrefix string `json:"keyPrefix,omitempty"`
	Presign   bool   `json:"presign,omitempty"`
	TTLSecs   int    `json:"ttlSecs,omitempty"` // default 3600 if Presign && unset
}

// ExportJob is the internal sensor-side representation (parallels PatchJob).
type ExportJob struct {
	ID  string         `json:"id"`
	Job AgentJobExport `json:"job"`
}

// ExportEnvelope is the top-level JSON uploaded to the dashboard after an export.
type ExportEnvelope struct {
	Version string             `json:"version"`
	Sensor  EnvelopeSensor     `json:"sensor"`
	Source  EnvelopeImage      `json:"source"`
	Export  EnvelopeExport     `json:"export"`
	Sink    EnvelopeExportSink `json:"sink"`
	Tooling map[string]string  `json:"tooling"`
}

type EnvelopeExport struct {
	ID         string `json:"id"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	// Status is always "SUCCESS" — failures don't produce an envelope
	// (the sensor reports failed/cancelled via ReportJobStatus instead),
	// unlike PatchEnvelope where partial-package-failure is meaningful
	// metadata to keep around.
	Status string `json:"status"`
}

// EnvelopeExportSink reports where the sensor shipped the tarball.
//
// Sha256 is computed over the bytes that landed in S3 — i.e. the gzipped
// payload when Compressed=true, the raw docker-archive otherwise. This
// lets a downloader verify integrity by hashing the object they fetched
// without having to decompress first. SizeBytes follows the same rule:
// it's the on-disk size of the uploaded object, not the original tar.
type EnvelopeExportSink struct {
	Kind       string `json:"kind"` // "s3"
	Bucket     string `json:"bucket,omitempty"`
	Key        string `json:"key"`
	URL        string `json:"url,omitempty"` // presigned GET URL, when requested
	SizeBytes  int64  `json:"sizeBytes"`
	Sha256     string `json:"sha256,omitempty"`
	Compressed bool   `json:"compressed,omitempty"`
}

// PollResponse wraps the dashboard poll response to include cancel signals.
type PollResponse struct {
	Jobs       []AgentJob `json:"jobs"`
	CancelJobs []string   `json:"cancelJobs,omitempty"`
}
