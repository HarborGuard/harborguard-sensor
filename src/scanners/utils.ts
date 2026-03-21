import { promisify } from 'node:util';
import { exec } from 'node:child_process';
import fs from 'node:fs/promises';
import type { ImageSource, ScannerResult } from '../types/index.js';

const execAsync = promisify(exec);

export async function execWithTimeout(
  command: string,
  timeoutMs: number,
  options: { shell?: string; env?: NodeJS.ProcessEnv; maxBuffer?: number } = {},
): Promise<{ stdout: string; stderr: string }> {
  return execAsync(command, {
    timeout: timeoutMs,
    shell: options.shell ?? '/bin/sh',
    env: options.env ?? process.env,
    maxBuffer: options.maxBuffer ?? 50 * 1024 * 1024,
  });
}

export async function parseJsonFile<T = unknown>(filePath: string): Promise<T> {
  const content = await fs.readFile(filePath, 'utf-8');
  return JSON.parse(content) as T;
}

export function formatSourceRef(source: ImageSource): string {
  switch (source.type) {
    case 'docker':
      return `docker:${source.ref}`;
    case 'registry':
      return `registry:${source.ref}`;
    case 'tar':
      return `docker-archive:${source.path}`;
  }
}

export async function getToolVersion(command: string): Promise<string> {
  try {
    const { stdout } = await execAsync(command, { timeout: 10000 });
    return stdout.trim().split('\n')[0];
  } catch {
    return 'unknown';
  }
}

export async function isToolAvailable(binary: string): Promise<boolean> {
  try {
    await execAsync(`which ${binary}`, { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

export async function writeFallbackResult(outputPath: string, error: string, extra: Record<string, unknown> = {}): Promise<void> {
  await fs.writeFile(outputPath, JSON.stringify({ error, ...extra }));
}

export function createTimedResult(scanner: string, success: boolean, startTime: number, extra: Partial<ScannerResult> = {}): ScannerResult {
  return {
    scanner,
    success,
    durationMs: Date.now() - startTime,
    ...extra,
  };
}
