import fs from 'node:fs/promises';
import path from 'node:path';
import type { ImageSource, ScannerResult, IScanner } from '../types/index.js';
import type { SensorConfig } from '../config.js';
import { createScanner, partitionBySourceSupport } from './index.js';

export interface ScanJob {
  id: string;
  imageRef: string;
  source: ImageSource;
  scanners?: string[];
}

export interface ScanOutput {
  jobId: string;
  imageRef: string;
  startedAt: string;
  finishedAt: string;
  results: Record<string, ScannerResult>;
  metadata: {
    scannerVersions: Record<string, string>;
    imageDigest?: string;
    imagePlatform?: string;
    imageSizeBytes?: number;
  };
}

function extractImageMetadata(results: Record<string, ScannerResult>): ScanOutput['metadata'] {
  const versions: Record<string, string> = {};
  let imageDigest: string | undefined;
  let imagePlatform: string | undefined;
  let imageSizeBytes: number | undefined;

  for (const [name, result] of Object.entries(results)) {
    if (result.version) {
      versions[name] = result.version;
    }

    if (!result.data) continue;
    const data = result.data as any;

    // Extract metadata from Trivy output
    if (name === 'trivy' && result.success) {
      if (data.Metadata) {
        imageDigest = data.Metadata.RepoDigests?.[0];
        imagePlatform = data.Metadata.OS ? `${data.Metadata.OS}/${data.Metadata.Architecture}` : undefined;
        imageSizeBytes = data.Metadata.ImageConfig?.size;
      }
    }

    // Extract metadata from Syft output
    if (name === 'syft' && result.success && !imageDigest) {
      if (data.source?.target) {
        imageDigest = data.source.target.digest;
        imageSizeBytes = data.source.target.imageSize;
      }
    }
  }

  return { scannerVersions: versions, imageDigest, imagePlatform, imageSizeBytes };
}

export class ScanOrchestrator {
  constructor(private config: SensorConfig) {}

  async execute(job: ScanJob): Promise<ScanOutput> {
    const startedAt = new Date().toISOString();
    const outputDir = path.join(this.config.workDir, 'reports', job.id);
    await fs.mkdir(outputDir, { recursive: true });

    const scannerNames = job.scanners ?? this.config.enabledScanners;
    const scanners = scannerNames.map((name) => createScanner(name));

    // Get versions concurrently
    const versionEntries = await Promise.all(
      scanners.map(async (s) => [s.name, await s.getVersion()] as const),
    );
    const versionMap = Object.fromEntries(versionEntries);

    const { compatible, incompatible } = partitionBySourceSupport(scanners, job.source);

    const results = await this.runParallel(compatible, job.source, outputDir);

    // Record skipped scanners
    for (const s of incompatible) {
      results[s.name] = {
        scanner: s.name,
        success: false,
        error: `Source type '${job.source.type}' not supported`,
        durationMs: 0,
      };
    }

    // Attach versions to results
    for (const [name, version] of Object.entries(versionMap)) {
      if (results[name]) {
        results[name].version = version;
      }
    }

    const metadata = extractImageMetadata(results);
    // Merge pre-fetched versions
    metadata.scannerVersions = { ...versionMap, ...metadata.scannerVersions };

    const finishedAt = new Date().toISOString();
    return { jobId: job.id, imageRef: job.imageRef, startedAt, finishedAt, results, metadata };
  }

  private async runParallel(
    scanners: IScanner[],
    source: ImageSource,
    outputDir: string,
  ): Promise<Record<string, ScannerResult>> {
    const results: Record<string, ScannerResult> = {};
    const batchSize = this.config.maxConcurrentScanners;

    for (let i = 0; i < scanners.length; i += batchSize) {
      const batch = scanners.slice(i, i + batchSize);
      const batchResults = await Promise.all(
        batch.map(async (scanner) => {
          const outputPath = path.join(outputDir, `${scanner.name}.json`);
          const result = await scanner.scan(source, outputPath);
          return [scanner.name, result] as const;
        }),
      );
      for (const [name, result] of batchResults) {
        results[name] = result;
      }
    }

    return results;
  }
}
