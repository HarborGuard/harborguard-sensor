import type { NormalizedCompliance } from '../types/index.js';
import { mapDockleCategory, mapDockleSeverity } from './severity.js';

export function extractDockleCompliance(report: any): NormalizedCompliance[] {
  const findings: NormalizedCompliance[] = [];

  if (report?.details) {
    for (const detail of report.details) {
      for (const alert of detail.alerts || []) {
        findings.push({
          source: 'dockle',
          ruleId: detail.code,
          ruleName: detail.title,
          category: mapDockleCategory(detail.level),
          severity: mapDockleSeverity(detail.level),
          message: typeof alert === 'string' ? alert : alert?.message ?? String(alert),
        });
      }
    }
  }

  return findings;
}
