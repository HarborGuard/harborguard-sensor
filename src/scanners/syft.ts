import path from 'node:path';
import type { IScanner, ImageSource, ScannerResult } from '../types/index.js';
import { execWithTimeout, getToolVersion, isToolAvailable, formatSourceRef, parseJsonFile, writeFallbackResult, createTimedResult } from './utils.js';

const TIMEOUT_MS = 300_000;

export class SyftScanner implements IScanner {
  readonly name = 'syft';

  async scan(source: ImageSource, outputPath: string): Promise<ScannerResult> {
    const start = Date.now();
    try {
      const ref = formatSourceRef(source);
      const reportDir = path.dirname(outputPath);
      const sbomPath = path.join(reportDir, 'sbom.cdx.json');

      const env = { ...process.env, SYFT_CACHE_DIR: process.env.SYFT_CACHE_DIR ?? '/workspace/cache/syft' };

      await execWithTimeout(
        `syft ${ref} -o json > "${outputPath}"`,
        TIMEOUT_MS,
        { env },
      );

      await execWithTimeout(
        `syft ${ref} -o cyclonedx-json@1.5 > "${sbomPath}"`,
        TIMEOUT_MS,
        { env },
      );

      const data = await parseJsonFile(outputPath);
      return createTimedResult(this.name, true, start, { data });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn('Syft scan failed:', message);
      await writeFallbackResult(outputPath, message);
      return createTimedResult(this.name, false, start, { error: message });
    }
  }

  async getVersion(): Promise<string> {
    return getToolVersion('syft version');
  }

  async isAvailable(): Promise<boolean> {
    return isToolAvailable('syft');
  }

  supportsSource(_source: ImageSource): boolean {
    return true;
  }
}
