import type { IScanner, ImageSource, ScannerResult } from '../types/index.js';
import { execWithTimeout, getToolVersion, isToolAvailable, parseJsonFile, writeFallbackResult, createTimedResult } from './utils.js';

const TIMEOUT_MS = 300_000;

function buildCommand(source: ImageSource, outputPath: string): string {
  switch (source.type) {
    case 'docker':
      return `grype docker:${source.ref} -o json > "${outputPath}"`;
    case 'registry':
      return `grype registry:${source.ref} -o json > "${outputPath}"`;
    case 'tar':
      return `grype docker-archive:${source.path} -o json > "${outputPath}"`;
  }
}

export class GrypeScanner implements IScanner {
  readonly name = 'grype';

  async scan(source: ImageSource, outputPath: string): Promise<ScannerResult> {
    const start = Date.now();
    try {
      const command = buildCommand(source, outputPath);
      await execWithTimeout(command, TIMEOUT_MS, {
        env: { ...process.env, GRYPE_DB_CACHE_DIR: process.env.GRYPE_DB_CACHE_DIR ?? '/workspace/cache/grype' },
      });

      const data = await parseJsonFile(outputPath);
      return createTimedResult(this.name, true, start, { data });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn('Grype scan failed:', message);
      await writeFallbackResult(outputPath, message);
      return createTimedResult(this.name, false, start, { error: message });
    }
  }

  async getVersion(): Promise<string> {
    return getToolVersion('grype version');
  }

  async isAvailable(): Promise<boolean> {
    return isToolAvailable('grype');
  }

  supportsSource(_source: ImageSource): boolean {
    return true;
  }
}
