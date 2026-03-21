import fs from 'node:fs/promises';
import type { IScanner, ImageSource, ScannerResult } from '../types/index.js';
import { execWithTimeout, getToolVersion, isToolAvailable, parseJsonFile, writeFallbackResult, createTimedResult } from './utils.js';

const TIMEOUT_MS = 300_000;

function buildCommand(source: ImageSource, outputPath: string): string {
  const base = `trivy image -f json -o "${outputPath}"`;
  switch (source.type) {
    case 'docker':
      return `${base} "${source.ref}"`;
    case 'registry':
      return `${base} "${source.ref}"`;
    case 'tar':
      return `${base} --input "${source.path}"`;
  }
}

export class TrivyScanner implements IScanner {
  readonly name = 'trivy';

  async scan(source: ImageSource, outputPath: string): Promise<ScannerResult> {
    const start = Date.now();
    try {
      const command = buildCommand(source, outputPath);
      await execWithTimeout(command, TIMEOUT_MS, {
        env: { ...process.env, TRIVY_CACHE_DIR: process.env.TRIVY_CACHE_DIR ?? '/workspace/cache/trivy' },
      });

      const data = await parseJsonFile(outputPath);
      return createTimedResult(this.name, true, start, { data });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn('Trivy scan failed:', message);
      await writeFallbackResult(outputPath, message);
      return createTimedResult(this.name, false, start, { error: message });
    }
  }

  async getVersion(): Promise<string> {
    return getToolVersion('trivy --version');
  }

  async isAvailable(): Promise<boolean> {
    return isToolAvailable('trivy');
  }

  supportsSource(_source: ImageSource): boolean {
    return true;
  }
}
