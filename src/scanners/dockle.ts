import type { IScanner, ImageSource, ScannerResult } from '../types/index.js';
import { execWithTimeout, getToolVersion, isToolAvailable, parseJsonFile, writeFallbackResult, createTimedResult } from './utils.js';

const TIMEOUT_MS = 180_000;

function buildCommand(source: ImageSource, outputPath: string): string {
  switch (source.type) {
    case 'docker':
      return `dockle --format json --output "${outputPath}" "${source.ref}"`;
    case 'tar':
      return `dockle --input "${source.path}" --format json --output "${outputPath}"`;
    case 'registry':
      throw new Error('Dockle does not support direct registry scanning');
  }
}

export class DockleScanner implements IScanner {
  readonly name = 'dockle';

  async scan(source: ImageSource, outputPath: string): Promise<ScannerResult> {
    const start = Date.now();
    try {
      const command = buildCommand(source, outputPath);
      await execWithTimeout(command, TIMEOUT_MS);

      const data = await parseJsonFile(outputPath);
      return createTimedResult(this.name, true, start, { data });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn('Dockle scan failed:', message);
      await writeFallbackResult(outputPath, message);
      return createTimedResult(this.name, false, start, { error: message });
    }
  }

  async getVersion(): Promise<string> {
    return getToolVersion('dockle --version');
  }

  async isAvailable(): Promise<boolean> {
    return isToolAvailable('dockle');
  }

  supportsSource(source: ImageSource): boolean {
    return source.type !== 'registry';
  }
}
