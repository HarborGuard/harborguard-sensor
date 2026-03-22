export interface AgentRegistration {
  name: string;
  version: string;
  hostname: string;
  os: string;
  arch: string;
  scannerVersions: Record<string, string>;
  capabilities: string[];
  s3Configured: boolean;
}

export interface AgentHeartbeat {
  agentId: string;
  status: 'idle' | 'scanning';
  activeScans: number;
  uptimeSeconds: number;
}

export interface AgentJob {
  id: string;
  type: 'scan' | 'patch' | 'SCAN' | 'PATCH';
  createdAt: string;

  scan?: {
    imageRef: string;
    source: 'docker' | 'registry' | 'tar';
    tarPath?: string;
    scanners?: string[];
    registryCredentials?: {
      username: string;
      password: string;
    };
  };

  patch?: {
    imageRef: string;
    cves: string[];
    strategy: 'apt' | 'yum' | 'apk';
    targetRegistry?: string;
  };
}
