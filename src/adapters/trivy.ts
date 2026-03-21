import type { NormalizedVulnerability, NormalizedPackage } from '../types/index.js';
import { mapSeverity } from './severity.js';

function formatLicense(license: any): string | undefined {
  if (!license) return undefined;
  if (typeof license === 'string') return license;
  if (Array.isArray(license)) {
    const formatted = license.map((l) => formatLicense(l)).filter(Boolean);
    return formatted.length > 0 ? formatted.join(', ') : undefined;
  }
  if (typeof license === 'object') {
    if (license.value) return license.value;
    if (license.spdxExpression) return license.spdxExpression;
    if (license.name) return license.name;
    if (license.license) return license.license;
    if (license.expression) return license.expression;
    const values = Object.values(license);
    const firstString = values.find((v) => typeof v === 'string' && v !== 'declared');
    if (firstString) return firstString as string;
  }
  return undefined;
}

export function extractTrivyVulnerabilities(report: any): NormalizedVulnerability[] {
  const findings: NormalizedVulnerability[] = [];

  if (report?.Results) {
    for (const result of report.Results) {
      if (result.Vulnerabilities) {
        for (const vuln of result.Vulnerabilities) {
          findings.push({
            source: 'trivy',
            cveId: vuln.VulnerabilityID || vuln.PkgID,
            packageName: vuln.PkgName || vuln.PkgID,
            installedVersion: vuln.InstalledVersion ?? undefined,
            fixedVersion: vuln.FixedVersion ?? undefined,
            severity: mapSeverity(vuln.Severity) as NormalizedVulnerability['severity'],
            cvssScore: vuln.CVSS?.nvd?.V3Score || vuln.CVSS?.redhat?.V3Score || undefined,
            vulnerabilityUrl: vuln.PrimaryURL ?? undefined,
            title: vuln.Title ?? undefined,
            description: vuln.Description ?? undefined,
          });
        }
      }
    }
  }

  return findings;
}

export function extractTrivyPackages(report: any): NormalizedPackage[] {
  const findings: NormalizedPackage[] = [];

  if (report?.Results) {
    for (const result of report.Results) {
      if (result.Packages) {
        for (const pkg of result.Packages) {
          findings.push({
            source: 'trivy',
            name: pkg.Name,
            version: pkg.Version || '',
            type: result.Type || 'unknown',
            license: formatLicense(pkg.License),
          });
        }
      }
    }
  }

  return findings;
}
