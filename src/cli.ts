import { Command } from 'commander';
import crypto from 'node:crypto';
import { loadConfig } from './config.js';
import { ScanOrchestrator } from './scanners/orchestrator.js';
import { buildEnvelope } from './adapters/envelope-builder.js';
import { createScanner } from './scanners/index.js';
import { runAgentLoop } from './agent/loop.js';
import { S3Storage } from './storage/s3.js';
import { AgentClient } from './agent/client.js';
import type { ImageSource } from './types/index.js';

const VERSION = '0.1.0';

export const program = new Command();

program
  .name('harborguard-sensor')
  .version(VERSION)
  .description('HarborGuard container security scanning sensor');

// --- scan command ---
program
  .command('scan <image>')
  .description('One-shot scan of a container image')
  .option('--source <type>', 'Image source: docker, registry, tar', 'docker')
  .option('--scanners <list>', 'Comma-separated scanner list')
  .option('--output <format>', 'Output format: json, table, envelope', 'table')
  .option('--output-file <path>', 'Write results to file')
  .option('--upload-url <url>', 'Upload results to dashboard URL')
  .option('--api-key <key>', 'API key for dashboard upload')
  .option('--s3-bucket <bucket>', 'S3 bucket for artifact storage')
  .action(async (image: string, opts: Record<string, string>) => {
    try {
      const config = loadConfig({
        scanners: opts.scanners,
      });

      const source: ImageSource =
        opts.source === 'tar'
          ? { type: 'tar', path: image }
          : opts.source === 'registry'
            ? { type: 'registry', ref: image }
            : { type: 'docker', ref: image };

      const scanId = crypto.randomUUID();
      const orchestrator = new ScanOrchestrator(config);

      console.log(`[scan] Scanning ${image} (source: ${opts.source})...`);

      const output = await orchestrator.execute({
        id: scanId,
        imageRef: image,
        source,
        scanners: opts.scanners?.split(',').map((s) => s.trim()),
      });

      const envelope = buildEnvelope(
        { id: scanId, imageRef: image, source },
        output,
      );

      // S3 upload if configured
      if (opts.s3Bucket || config.s3Bucket) {
        const bucket = opts.s3Bucket || config.s3Bucket!;
        if (config.s3AccessKey && config.s3SecretKey) {
          const storage = new S3Storage({
            endpoint: config.s3Endpoint,
            bucket,
            accessKey: config.s3AccessKey,
            secretKey: config.s3SecretKey,
            region: config.s3Region,
          });

          const rawResults: Record<string, string> = {};
          for (const [scanner, result] of Object.entries(output.results)) {
            if (result.data) {
              rawResults[scanner] = await storage.uploadRawResult(scanId, scanner, result.data);
            }
          }

          const syftResult = output.results['syft'];
          const sbom = syftResult?.data ? await storage.uploadSbom(scanId, syftResult.data) : undefined;

          envelope.artifacts = {
            s3Prefix: `scans/${scanId}/`,
            rawResults,
            sbom,
          };

          await storage.uploadScanResults(scanId, envelope);
          console.log(`[scan] Results uploaded to S3: scans/${scanId}/`);
        }
      }

      // Dashboard upload
      if (opts.uploadUrl || config.dashboardUrl) {
        const url = opts.uploadUrl || config.dashboardUrl!;
        const key = opts.apiKey || config.apiKey;
        if (key) {
          const client = new AgentClient(url, key);
          await client.uploadResults(envelope);
          console.log('[scan] Results uploaded to dashboard');
        }
      }

      // Output
      const { writeFile } = await import('node:fs/promises');

      if (opts.output === 'json' || opts.output === 'envelope') {
        const json = JSON.stringify(envelope, null, 2);
        if (opts.outputFile) {
          await writeFile(opts.outputFile, json);
          console.log(`[scan] Results written to ${opts.outputFile}`);
        } else {
          console.log(json);
        }
      } else {
        // Table output
        printTable(envelope);
        if (opts.outputFile) {
          await writeFile(opts.outputFile, JSON.stringify(envelope, null, 2));
          console.log(`[scan] Full results written to ${opts.outputFile}`);
        }
      }

      // Exit with non-zero if critical/high vulnerabilities found
      const { critical, high } = envelope.aggregates.vulnerabilityCounts;
      if (critical > 0 || high > 0) {
        process.exitCode = 1;
      }
    } catch (err) {
      console.error('[scan] Error:', err instanceof Error ? err.message : err);
      process.exit(2);
    }
  });

// --- agent command ---
program
  .command('agent')
  .description('Run as long-lived agent, polling dashboard for jobs')
  .option('--dashboard-url <url>', 'Dashboard URL (env: HG_DASHBOARD_URL)')
  .option('--api-key <key>', 'API key (env: HG_API_KEY)')
  .option('--name <name>', 'Agent name (env: HG_AGENT_NAME)')
  .option('--poll-interval <ms>', 'Poll interval in ms', '10000')
  .action(async (opts: Record<string, string>) => {
    try {
      const config = loadConfig({
        dashboardUrl: opts.dashboardUrl,
        apiKey: opts.apiKey,
        agentName: opts.name,
        pollInterval: opts.pollInterval,
      });
      await runAgentLoop(config);
    } catch (err) {
      console.error('[agent] Error:', err instanceof Error ? err.message : err);
      process.exit(2);
    }
  });

// --- version command ---
program
  .command('version')
  .description('Print sensor and scanner versions')
  .action(async () => {
    console.log(`harborguard-sensor v${VERSION}`);
    console.log('');

    const scannerNames = ['trivy', 'grype', 'syft', 'dockle', 'dive', 'osv'];
    for (const name of scannerNames) {
      try {
        const scanner = createScanner(name);
        const version = await scanner.getVersion();
        const available = await scanner.isAvailable();
        console.log(`  ${name}: ${available ? version : 'not installed'}`);
      } catch {
        console.log(`  ${name}: not installed`);
      }
    }
  });

function printTable(envelope: import('./types/index.js').ScanEnvelope): void {
  const { vulnerabilityCounts, riskScore, complianceScore, complianceGrade, totalPackages } =
    envelope.aggregates;

  console.log('');
  console.log(`Image: ${envelope.image.ref}`);
  console.log(`Scan:  ${envelope.scan.id} (${envelope.scan.status})`);
  console.log('');
  console.log('Vulnerabilities:');
  console.log(
    `  CRITICAL: ${vulnerabilityCounts.critical}  HIGH: ${vulnerabilityCounts.high}  MEDIUM: ${vulnerabilityCounts.medium}  LOW: ${vulnerabilityCounts.low}  INFO: ${vulnerabilityCounts.info}`,
  );
  console.log(`  Risk Score: ${riskScore}/100`);
  console.log('');
  console.log(`Packages: ${totalPackages}`);

  if (complianceScore !== undefined) {
    console.log(`Compliance: ${complianceScore}/100 (${complianceGrade})`);
  }

  if (envelope.findings.efficiency.length > 0) {
    console.log(`Efficiency: ${envelope.findings.efficiency.length} findings`);
  }
  console.log('');
}
