import type { ScanEnvelope, NormalizedVulnerability, NormalizedPackage, NormalizedCompliance, NormalizedEfficiency } from '../types/index.js';
import type { ScanJob, ScanOutput } from '../scanners/orchestrator.js';
import { extractTrivyVulnerabilities, extractTrivyPackages } from './trivy.js';
import { extractGrypeVulnerabilities } from './grype.js';
import { extractSyftPackages } from './syft.js';
import { extractDockleCompliance } from './dockle.js';
import { extractDiveEfficiency } from './dive.js';
import { extractOsvVulnerabilities } from './osv.js';
import { getHighestSeverity } from './severity.js';

const VERSION = '0.1.0';

function parseImageRef(ref: string): { name: string; tag: string } {
  // Strip registry prefix for the name field
  const parts = ref.split('/');
  const nameAndTag = parts[parts.length - 1];
  const [name, tag] = nameAndTag.includes(':') ? nameAndTag.split(':') : [nameAndTag, 'latest'];
  return { name, tag };
}

function deduplicateVulnerabilities(vulns: NormalizedVulnerability[]): NormalizedVulnerability[] {
  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const seen = new Map<string, NormalizedVulnerability>();

  for (const vuln of vulns) {
    const key = `${vuln.cveId}:${vuln.packageName}`;
    const existing = seen.get(key);
    if (!existing) {
      seen.set(key, vuln);
    } else {
      // Keep the one with highest severity
      const existingIdx = severityOrder.indexOf(existing.severity);
      const newIdx = severityOrder.indexOf(vuln.severity);
      if (newIdx < existingIdx) {
        seen.set(key, vuln);
      }
    }
  }

  return Array.from(seen.values());
}

function calculateRiskScore(vulns: NormalizedVulnerability[]): number {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let totalCvss = 0;
  let cvssCount = 0;

  for (const v of vulns) {
    const key = v.severity.toLowerCase() as keyof typeof counts;
    if (key in counts) counts[key]++;
    if (v.cvssScore) {
      totalCvss += v.cvssScore;
      cvssCount++;
    }
  }

  const avgCvss = cvssCount > 0 ? totalCvss / cvssCount : 0;

  return Math.min(
    100,
    Math.round(
      counts.critical * 25 +
      counts.high * 10 +
      counts.medium * 3 +
      counts.low * 1 +
      avgCvss * 5,
    ),
  );
}

function calculateComplianceScore(dockleData: any): { score: number; grade: string } | undefined {
  if (!dockleData?.summary) return undefined;

  const { fatal = 0, warn = 0, info = 0, pass = 0 } = dockleData.summary;
  const total = fatal + warn + info + pass;
  if (total === 0) return undefined;

  const score = Math.round((pass / total) * 100);
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : 'D';
  return { score, grade };
}

export function buildEnvelope(job: ScanJob, output: ScanOutput): ScanEnvelope {
  // Extract findings from each scanner result
  const vulnerabilities: NormalizedVulnerability[] = [];
  const packages: NormalizedPackage[] = [];
  const compliance: NormalizedCompliance[] = [];
  const efficiency: NormalizedEfficiency[] = [];

  for (const [scanner, result] of Object.entries(output.results)) {
    if (!result.success || !result.data) continue;
    const data = result.data;

    switch (scanner) {
      case 'trivy':
        vulnerabilities.push(...extractTrivyVulnerabilities(data));
        packages.push(...extractTrivyPackages(data));
        break;
      case 'grype':
        vulnerabilities.push(...extractGrypeVulnerabilities(data));
        break;
      case 'syft':
        packages.push(...extractSyftPackages(data));
        break;
      case 'dockle':
        compliance.push(...extractDockleCompliance(data));
        break;
      case 'dive':
        efficiency.push(...extractDiveEfficiency(data));
        break;
      case 'osv':
        vulnerabilities.push(...extractOsvVulnerabilities(data));
        break;
    }
  }

  const deduped = deduplicateVulnerabilities(vulnerabilities);

  // Count vulnerabilities
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const v of deduped) {
    const key = v.severity.toLowerCase() as keyof typeof counts;
    if (key in counts) counts[key]++;
  }

  const riskScore = calculateRiskScore(deduped);

  // Compliance from dockle raw data
  const dockleResult = output.results['dockle'];
  const complianceCalc = dockleResult?.success ? calculateComplianceScore(dockleResult.data) : undefined;

  // Determine scan status
  const scannerResults = Object.values(output.results);
  const successCount = scannerResults.filter((r) => r.success).length;
  const status = successCount === 0 ? 'FAILED' : successCount === scannerResults.length ? 'SUCCESS' : 'PARTIAL';

  const { name, tag } = parseImageRef(job.imageRef);

  return {
    version: '1.0',
    sensor: {
      version: VERSION,
      scannerVersions: output.metadata.scannerVersions,
    },
    image: {
      ref: job.imageRef,
      digest: output.metadata.imageDigest,
      platform: output.metadata.imagePlatform,
      sizeBytes: output.metadata.imageSizeBytes,
      name,
      tag,
    },
    scan: {
      id: job.id,
      startedAt: output.startedAt,
      finishedAt: output.finishedAt,
      status,
    },
    findings: {
      vulnerabilities: deduped,
      packages,
      compliance,
      efficiency,
    },
    aggregates: {
      vulnerabilityCounts: counts,
      riskScore,
      complianceScore: complianceCalc?.score,
      complianceGrade: complianceCalc?.grade,
      totalPackages: packages.length,
    },
  };
}
