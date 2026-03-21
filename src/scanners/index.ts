import type { IScanner, ImageSource } from '../types/index.js';
import { TrivyScanner } from './trivy.js';
import { GrypeScanner } from './grype.js';
import { SyftScanner } from './syft.js';
import { DockleScanner } from './dockle.js';
import { DiveScanner } from './dive.js';
import { OsvScanner } from './osv.js';

const SCANNER_MAP: Record<string, new () => IScanner> = {
  trivy: TrivyScanner,
  grype: GrypeScanner,
  syft: SyftScanner,
  dockle: DockleScanner,
  dive: DiveScanner,
  osv: OsvScanner,
};

export function createScanner(name: string): IScanner {
  const Ctor = SCANNER_MAP[name];
  if (!Ctor) {
    throw new Error(`Unknown scanner: ${name}. Valid scanners: ${Object.keys(SCANNER_MAP).join(', ')}`);
  }
  return new Ctor();
}

export function partitionBySourceSupport(
  scanners: IScanner[],
  source: ImageSource,
): { compatible: IScanner[]; incompatible: IScanner[] } {
  const compatible: IScanner[] = [];
  const incompatible: IScanner[] = [];

  for (const scanner of scanners) {
    if (scanner.supportsSource(source)) {
      compatible.push(scanner);
    } else {
      incompatible.push(scanner);
    }
  }

  return { compatible, incompatible };
}

export { TrivyScanner } from './trivy.js';
export { GrypeScanner } from './grype.js';
export { SyftScanner } from './syft.js';
export { DockleScanner } from './dockle.js';
export { DiveScanner } from './dive.js';
export { OsvScanner } from './osv.js';
