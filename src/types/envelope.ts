import type { NormalizedVulnerability, NormalizedPackage, NormalizedCompliance, NormalizedEfficiency } from './findings.js';

export interface ScanEnvelope {
  version: '1.0';
  sensor: {
    id?: string;
    name?: string;
    version: string;
    scannerVersions: Record<string, string>;
  };
  image: {
    ref: string;
    digest?: string;
    platform?: string;
    sizeBytes?: number;
    name: string;
    tag: string;
  };
  scan: {
    id: string;
    startedAt: string;
    finishedAt: string;
    status: 'SUCCESS' | 'PARTIAL' | 'FAILED';
  };
  findings: {
    vulnerabilities: NormalizedVulnerability[];
    packages: NormalizedPackage[];
    compliance: NormalizedCompliance[];
    efficiency: NormalizedEfficiency[];
  };
  aggregates: {
    vulnerabilityCounts: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
    };
    riskScore: number;
    complianceScore?: number;
    complianceGrade?: string;
    totalPackages: number;
  };
  artifacts?: {
    s3Prefix?: string;
    rawResults?: Record<string, string>;
    sbom?: string;
  };
}
