package types

// ImageSource represents the source of a container image to scan.
type ImageSource struct {
	Type string `json:"type"` // "docker", "registry", "tar"
	Ref  string `json:"ref,omitempty"`
	Path string `json:"path,omitempty"`
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
	Version string         `json:"version"`
	Sensor  EnvelopeSensor `json:"sensor"`
	Image   EnvelopeImage  `json:"image"`
	Scan    EnvelopeScan   `json:"scan"`
	Findings EnvelopeFindings `json:"findings"`
	Aggregates EnvelopeAggregates `json:"aggregates"`
	Artifacts *EnvelopeArtifacts `json:"artifacts,omitempty"`
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
	EnabledScanners      []string
	ScanTimeoutMinutes   int
	MaxConcurrentScanners int
	DashboardURL         string
	APIKey               string
	AgentName            string
	PollIntervalMs       int
	S3Endpoint           string
	S3Bucket             string
	S3AccessKey          string
	S3SecretKey          string
	S3Region             string
	WorkDir              string
	CacheDir             string
	LogLevel             string
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
	ID        string         `json:"id"`
	Type      string         `json:"type"` // scan, SCAN, patch, PATCH
	CreatedAt string         `json:"createdAt"`
	Scan      *AgentJobScan  `json:"scan,omitempty"`
	Patch     *AgentJobPatch `json:"patch,omitempty"`
}

type AgentJobScan struct {
	ImageRef            string                `json:"imageRef"`
	Source              string                `json:"source"` // docker, registry, tar
	TarPath             string                `json:"tarPath,omitempty"`
	Scanners            []string              `json:"scanners,omitempty"`
	RegistryCredentials *RegistryCredentials   `json:"registryCredentials,omitempty"`
}

type RegistryCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AgentJobPatch struct {
	ImageRef       string   `json:"imageRef"`
	Cves           []string `json:"cves"`
	Strategy       string   `json:"strategy"`
	TargetRegistry string   `json:"targetRegistry,omitempty"`
}

// PollResponse wraps the dashboard poll response to include cancel signals.
type PollResponse struct {
	Jobs       []AgentJob `json:"jobs"`
	CancelJobs []string   `json:"cancelJobs,omitempty"`
}
