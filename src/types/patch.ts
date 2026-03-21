export interface PatchableVulnerability {
  cveId: string;
  packageName: string;
  installedVersion: string;
  fixedVersion: string;
  severity: string;
}

export interface PatchJob {
  id: string;
  imageRef: string;
  cves: string[];
  strategy: 'apt' | 'yum' | 'apk';
  targetRegistry?: string;
}

export interface PatchResultEntry {
  cveId: string;
  packageName: string;
  previousVersion: string;
  newVersion: string;
  status: 'patched' | 'skipped' | 'failed';
  error?: string;
}

export interface PatchEnvelope {
  version: '1.0';
  job: PatchJob;
  originalImage: string;
  patchedImage?: string;
  patchedDigest?: string;
  results: PatchResultEntry[];
  startedAt: string;
  finishedAt: string;
  status: 'SUCCESS' | 'PARTIAL' | 'FAILED';
}
