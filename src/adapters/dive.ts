import type { NormalizedEfficiency } from '../types/index.js';

export function extractDiveEfficiency(report: any): NormalizedEfficiency[] {
  const findings: NormalizedEfficiency[] = [];

  if (report?.layer) {
    for (const layer of report.layer) {
      const sizeBytes = Number(layer.sizeBytes || 0);
      if (sizeBytes > 50 * 1024 * 1024) {
        findings.push({
          source: 'dive',
          findingType: 'large_layer',
          title: `Large layer: ${(sizeBytes / 1024 / 1024).toFixed(2)}MB`,
          severity: sizeBytes > 100 * 1024 * 1024 ? 'WARNING' : 'INFO',
          sizeBytes,
          details: layer.command ?? undefined,
        });
      }
    }
  }

  return findings;
}
