import type { AgentRegistration, AgentHeartbeat, AgentJob, ScanEnvelope } from '../types/index.js';
import type { PatchEnvelope } from '../types/patch.js';

export class AgentClient {
  private agentId?: string;

  constructor(
    private dashboardUrl: string,
    private apiKey: string,
  ) {}

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = `${this.dashboardUrl}${path}`;
    const response = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(`${method} ${path} failed (${response.status}): ${text}`);
    }

    const contentType = response.headers.get('content-type');
    if (contentType?.includes('application/json')) {
      return (await response.json()) as T;
    }
    return undefined as T;
  }

  async register(info: AgentRegistration): Promise<{ agentId: string }> {
    const result = await this.request<{ agentId: string }>('POST', '/api/agent/register', info);
    this.agentId = result.agentId;
    return result;
  }

  async heartbeat(status: AgentHeartbeat): Promise<void> {
    await this.request<void>('POST', '/api/agent/heartbeat', status);
  }

  async pollJobs(): Promise<AgentJob[]> {
    if (!this.agentId) throw new Error('Agent not registered');
    return this.request<AgentJob[]>('GET', `/api/agent/jobs?agentId=${this.agentId}`);
  }

  async uploadResults(envelope: ScanEnvelope): Promise<{ scanId: string; imageId: string }> {
    return this.request<{ scanId: string; imageId: string }>('POST', '/api/scans/upload', envelope);
  }

  async reportJobStatus(jobId: string, status: 'completed' | 'failed', error?: string): Promise<void> {
    await this.request<void>('POST', `/api/agent/jobs/${jobId}/status`, { status, error });
  }

  async uploadPatchResults(envelope: PatchEnvelope): Promise<void> {
    await this.request<void>('POST', '/api/patches/upload', envelope);
  }

  getAgentId(): string | undefined {
    return this.agentId;
  }
}
