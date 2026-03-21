import type { NormalizedVulnerability } from '../types/index.js';
import { mapSeverity } from './severity.js';

export function extractGrypeVulnerabilities(report: any): NormalizedVulnerability[] {
  const findings: NormalizedVulnerability[] = [];

  if (report?.matches) {
    for (const match of report.matches) {
      const vuln = match.vulnerability;
      findings.push({
        source: 'grype',
        cveId: vuln.id,
        packageName: match.artifact.name,
        installedVersion: match.artifact.version ?? undefined,
        fixedVersion: vuln.fix?.versions?.[0] ?? undefined,
        severity: mapSeverity(vuln.severity) as NormalizedVulnerability['severity'],
        cvssScore: vuln.cvss?.[0]?.metrics?.baseScore ?? undefined,
        vulnerabilityUrl: vuln.urls?.[0] ?? undefined,
        description: vuln.description ?? undefined,
      });
    }
  }

  return findings;
}
