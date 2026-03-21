import type { IScanner, ImageSource, ScannerResult } from '../types/index.js';
import { execWithTimeout, getToolVersion, isToolAvailable, parseJsonFile, writeFallbackResult, createTimedResult } from './utils.js';

const TIMEOUT_MS = 240_000;

function buildCommand(source: ImageSource, outputPath: string): string {
  switch (source.type) {
    case 'docker':
      return `dive "${source.ref}" --json "${outputPath}"`;
    case 'tar':
      return `dive --source docker-archive "${source.path}" --json "${outputPath}"`;
    case 'registry':
      throw new Error('Dive does not support direct registry scanning');
  }
}

export class DiveScanner implements IScanner {
  readonly name = 'dive';

  async scan(source: ImageSource, outputPath: string): Promise<ScannerResult> {
    const start = Date.now();
    try {
      const command = buildCommand(source, outputPath);
      await execWithTimeout(command, TIMEOUT_MS);

      const data = await parseJsonFile(outputPath);
      return createTimedResult(this.name, true, start, { data });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn('Dive scan failed:', message);
      await writeFallbackResult(outputPath, message, { layer: [] });
      return createTimedResult(this.name, false, start, { error: message });
    }
  }

  async getVersion(): Promise<string> {
    return getToolVersion('dive --version');
  }

  async isAvailable(): Promise<boolean> {
    return isToolAvailable('dive');
  }

  supportsSource(source: ImageSource): boolean {
    return source.type !== 'registry';
  }
}
