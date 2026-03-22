import os from 'node:os';
import type { SensorConfig } from '../config.js';
import type { AgentRegistration, AgentHeartbeat, ImageSource, AgentJob } from '../types/index.js';
import { AgentClient } from './client.js';
import { ScanOrchestrator } from '../scanners/orchestrator.js';
import { S3Storage } from '../storage/s3.js';
import { buildEnvelope } from '../adapters/envelope-builder.js';
import { createScanner } from '../scanners/index.js';

const VERSION = '0.1.0';

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function getScannerVersions(scannerNames: string[]): Promise<Record<string, string>> {
  const entries = await Promise.all(
    scannerNames.map(async (name) => {
      const scanner = createScanner(name);
      return [name, await scanner.getVersion()] as const;
    }),
  );
  return Object.fromEntries(entries);
}

function buildRegistrationPayload(config: SensorConfig, scannerVersions: Record<string, string>): AgentRegistration {
  return {
    name: config.agentName || os.hostname(),
    version: VERSION,
    hostname: os.hostname(),
    os: os.platform(),
    arch: os.arch(),
    scannerVersions,
    capabilities: ['scan'],
    s3Configured: !!config.s3Bucket,
  };
}

function resolveImageSource(scan: NonNullable<AgentJob['scan']>): ImageSource {
  switch (scan.source) {
    case 'tar':
      return { type: 'tar', path: scan.tarPath! };
    case 'registry':
      return { type: 'registry', ref: scan.imageRef };
    case 'docker':
    default:
      return { type: 'docker', ref: scan.imageRef };
  }
}

async function uploadToS3(
  storage: S3Storage,
  scanId: string,
  output: { results: Record<string, { data?: unknown }> },
): Promise<{ rawResults: Record<string, string>; sbom?: string }> {
  const rawResults: Record<string, string> = {};
  let sbom: string | undefined;

  // Upload raw scanner results in parallel
  const uploads = Object.entries(output.results).map(async ([scanner, result]) => {
    if (result.data) {
      const key = await storage.uploadRawResult(scanId, scanner, result.data);
      rawResults[scanner] = key;
    }
  });
  await Promise.all(uploads);

  // Upload SBOM if syft ran
  const syftResult = output.results['syft'];
  if (syftResult?.data) {
    sbom = await storage.uploadSbom(scanId, syftResult.data);
  }

  return { rawResults, sbom };
}

export async function runAgentLoop(config: SensorConfig): Promise<void> {
  if (!config.dashboardUrl || !config.apiKey) {
    throw new Error('Agent mode requires HG_DASHBOARD_URL and HG_API_KEY');
  }

  const client = new AgentClient(config.dashboardUrl, config.apiKey);
  const orchestrator = new ScanOrchestrator(config);
  const storage =
    config.s3Bucket && config.s3AccessKey && config.s3SecretKey
      ? new S3Storage({
          endpoint: config.s3Endpoint,
          bucket: config.s3Bucket,
          accessKey: config.s3AccessKey,
          secretKey: config.s3SecretKey,
          region: config.s3Region,
        })
      : null;

  const scannerVersions = await getScannerVersions(config.enabledScanners);

  // Register with dashboard
  const { agentId } = await client.register(buildRegistrationPayload(config, scannerVersions));
  console.log(`[agent] Registered as ${agentId}`);

  // Heartbeat interval
  const startTime = Date.now();
  let activeScans = 0;

  const heartbeatInterval = setInterval(async () => {
    try {
      const heartbeat: AgentHeartbeat = {
        agentId,
        status: activeScans > 0 ? 'scanning' : 'idle',
        activeScans,
        uptimeSeconds: Math.floor((Date.now() - startTime) / 1000),
      };
      await client.heartbeat(heartbeat);
    } catch (err) {
      console.warn('[agent] Heartbeat failed:', err instanceof Error ? err.message : err);
    }
  }, 30_000);

  // Ensure cleanup on exit
  const cleanup = () => clearInterval(heartbeatInterval);
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  // Poll loop
  console.log('[agent] Polling for jobs...');
  while (true) {
    try {
      const jobs = await client.pollJobs();

      for (const job of jobs) {
        if ((job.type === 'scan' || job.type === 'SCAN') && job.scan) {
          activeScans++;
          try {
            console.log(`[agent] Starting scan: ${job.scan.imageRef}`);
            const source = resolveImageSource(job.scan);
            const output = await orchestrator.execute({
              id: job.id,
              imageRef: job.scan.imageRef,
              source,
              scanners: job.scan.scanners,
            });

            const envelope = buildEnvelope(
              { id: job.id, imageRef: job.scan.imageRef, source },
              output,
            );

            // Upload to S3 if configured
            if (storage) {
              const artifacts = await uploadToS3(storage, job.id, output);
              envelope.artifacts = {
                s3Prefix: `scans/${job.id}/`,
                rawResults: artifacts.rawResults,
                sbom: artifacts.sbom,
              };
              await storage.uploadScanResults(job.id, envelope);
            }

            // Push results to dashboard
            await client.uploadResults(envelope);
            await client.reportJobStatus(job.id, 'completed');
            console.log(`[agent] Scan complete: ${job.scan.imageRef}`);
          } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            console.error(`[agent] Scan failed: ${message}`);
            await client.reportJobStatus(job.id, 'failed', message).catch(() => {});
          } finally {
            activeScans--;
          }
        }
      }
    } catch (err) {
      console.warn('[agent] Poll failed:', err instanceof Error ? err.message : err);
    }

    await sleep(config.pollIntervalMs);
  }
}
