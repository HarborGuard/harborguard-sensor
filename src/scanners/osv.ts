import fs from 'node:fs/promises';
import path from 'node:path';
import type { IScanner, ImageSource, ScannerResult } from '../types/index.js';
import { execWithTimeout, getToolVersion, isToolAvailable, formatSourceRef, parseJsonFile, writeFallbackResult, createTimedResult } from './utils.js';

const TIMEOUT_MS = 300_000;

export class OsvScanner implements IScanner {
  readonly name = 'osv';

  async scan(source: ImageSource, outputPath: string, sbomPath?: string): Promise<ScannerResult> {
    const start = Date.now();
    const reportDir = path.dirname(outputPath);
    const ownSbom = sbomPath ?? path.join(reportDir, 'osv-sbom.cdx.json');
    let cleanupSbom = !sbomPath;

    try {
      // Generate SBOM if not provided (reuse Syft output when available)
      if (!sbomPath) {
        const syftSbom = path.join(reportDir, 'sbom.cdx.json');
        try {
          await fs.access(syftSbom);
          // Reuse existing Syft SBOM
          await fs.copyFile(syftSbom, ownSbom);
          cleanupSbom = true;
        } catch {
          // Generate independent SBOM
          const ref = formatSourceRef(source);
          await execWithTimeout(
            `syft ${ref} -o cyclonedx-json@1.5 > "${ownSbom}"`,
            TIMEOUT_MS,
          );
        }
      }

      // OSV scanner exits code 1 when vulns are found — that is success
      try {
        await execWithTimeout(
          `osv-scanner -L "${ownSbom}" --verbosity error --format json > "${outputPath}"`,
          TIMEOUT_MS,
          { maxBuffer: 100 * 1024 * 1024 },
        );
      } catch (osvError) {
        // Check if output file was written (exit code 1 = vulns found)
        try {
          await fs.access(outputPath);
        } catch {
          throw osvError;
        }
      }

      const data = await parseJsonFile(outputPath);
      return createTimedResult(this.name, true, start, { data });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn('OSV scan failed:', message);
      await writeFallbackResult(outputPath, message, { vulnerabilities: [] });
      return createTimedResult(this.name, false, start, { error: message });
    } finally {
      if (cleanupSbom) {
        try {
          await fs.unlink(ownSbom);
        } catch {
          // Ignore cleanup errors
        }
      }
    }
  }

  async getVersion(): Promise<string> {
    return getToolVersion('osv-scanner --version');
  }

  async isAvailable(): Promise<boolean> {
    return isToolAvailable('osv-scanner');
  }

  supportsSource(_source: ImageSource): boolean {
    return true;
  }
}
