export interface NormalizedVulnerability {
  cveId: string;
  source: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cvssScore?: number;
  title?: string;
  description?: string;
  packageName: string;
  installedVersion?: string;
  fixedVersion?: string;
  vulnerabilityUrl?: string;
}

export interface NormalizedPackage {
  name: string;
  version: string;
  type: string;
  source: string;
  license?: string;
  purl?: string;
}

export interface NormalizedCompliance {
  ruleId: string;
  ruleName: string;
  severity: string;
  source: string;
  category?: string;
  message?: string;
}

export interface NormalizedEfficiency {
  findingType: string;
  title: string;
  severity: string;
  source: string;
  sizeBytes?: number;
  details?: string;
}
