import type { NormalizedVulnerability } from '../types/index.js';
import { mapOsvSeverity, extractOsvScore } from './severity.js';

export function extractOsvVulnerabilities(report: any): NormalizedVulnerability[] {
  const findings: NormalizedVulnerability[] = [];

  if (report?.results) {
    for (const result of report.results) {
      for (const pkg of result.packages || []) {
        for (const vuln of pkg.vulnerabilities || []) {
          findings.push({
            source: 'osv',
            cveId: vuln.id,
            packageName: pkg.package?.name || 'unknown',
            installedVersion: pkg.package?.version ?? undefined,
            severity: mapOsvSeverity(vuln.severity) as NormalizedVulnerability['severity'],
            cvssScore: extractOsvScore(vuln.severity) ?? undefined,
            vulnerabilityUrl: vuln.references?.[0]?.url ?? undefined,
            title: vuln.summary ?? undefined,
            description: vuln.details ?? undefined,
          });
        }
      }
    }
  }

  return findings;
}
