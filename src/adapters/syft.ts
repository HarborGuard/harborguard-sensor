import type { NormalizedPackage } from '../types/index.js';

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

export function extractSyftPackages(report: any): NormalizedPackage[] {
  const findings: NormalizedPackage[] = [];

  if (report?.artifacts) {
    for (const artifact of report.artifacts) {
      findings.push({
        source: 'syft',
        name: artifact.name,
        version: artifact.version || '',
        type: artifact.type || 'unknown',
        purl: artifact.purl ?? undefined,
        license: formatLicense(artifact.licenses),
      });
    }
  }

  return findings;
}
