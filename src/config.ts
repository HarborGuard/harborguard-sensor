import { z } from 'zod';

export interface SensorConfig {
  enabledScanners: string[];
  scanTimeoutMinutes: number;
  maxConcurrentScanners: number;

  dashboardUrl?: string;
  apiKey?: string;
  agentName?: string;
  pollIntervalMs: number;

  s3Endpoint?: string;
  s3Bucket?: string;
  s3AccessKey?: string;
  s3SecretKey?: string;
  s3Region: string;

  workDir: string;
  cacheDir: string;

  logLevel: string;
}

const VALID_SCANNERS = ['trivy', 'grype', 'syft', 'dockle', 'osv', 'dive'];

const SensorConfigSchema = z.object({
  enabledScanners: z
    .string()
    .default('trivy,grype,syft,dockle,osv,dive')
    .transform((s) => s.split(',').map((v) => v.trim()))
    .pipe(
      z.array(z.string()).min(1, 'At least one scanner must be enabled').refine(
        (arr) => arr.every((s) => VALID_SCANNERS.includes(s)),
        (arr) => ({
          message: `Invalid scanners: ${arr.filter((s) => !VALID_SCANNERS.includes(s)).join(', ')}. Valid: ${VALID_SCANNERS.join(', ')}`,
        }),
      ),
    ),
  scanTimeoutMinutes: z.coerce.number().min(5).max(180).default(30),
  maxConcurrentScanners: z.coerce.number().min(1).max(10).default(3),

  dashboardUrl: z.string().url().optional(),
  apiKey: z.string().optional(),
  agentName: z.string().optional(),
  pollIntervalMs: z.coerce.number().min(1000).default(10000),

  s3Endpoint: z.string().optional(),
  s3Bucket: z.string().optional(),
  s3AccessKey: z.string().optional(),
  s3SecretKey: z.string().optional(),
  s3Region: z.string().default('us-east-1'),

  workDir: z.string().default('/workspace'),
  cacheDir: z.string().default('/workspace/cache'),

  logLevel: z
    .string()
    .default('info')
    .transform((s) => s.toLowerCase())
    .pipe(z.enum(['debug', 'info', 'warn', 'error'])),
});

export function loadConfig(overrides: Record<string, string> = {}): SensorConfig {
  const env = process.env;

  const raw = {
    enabledScanners: overrides.scanners ?? env.HG_ENABLED_SCANNERS ?? env.ENABLED_SCANNERS,
    scanTimeoutMinutes: overrides.timeout ?? env.HG_SCAN_TIMEOUT_MINUTES ?? env.SCAN_TIMEOUT_MINUTES,
    maxConcurrentScanners: overrides.concurrency ?? env.HG_MAX_CONCURRENT_SCANNERS,
    dashboardUrl: overrides.dashboardUrl ?? env.HG_DASHBOARD_URL,
    apiKey: overrides.apiKey ?? env.HG_API_KEY,
    agentName: overrides.agentName ?? env.HG_AGENT_NAME,
    pollIntervalMs: overrides.pollInterval ?? env.HG_POLL_INTERVAL_MS,
    s3Endpoint: env.HG_S3_ENDPOINT ?? env.S3_ENDPOINT,
    s3Bucket: env.HG_S3_BUCKET ?? env.S3_BUCKET,
    s3AccessKey: env.HG_S3_ACCESS_KEY ?? env.AWS_ACCESS_KEY_ID,
    s3SecretKey: env.HG_S3_SECRET_KEY ?? env.AWS_SECRET_ACCESS_KEY,
    s3Region: env.HG_S3_REGION ?? env.AWS_REGION,
    workDir: env.HG_WORK_DIR ?? env.SCANNER_WORKDIR,
    cacheDir: env.HG_CACHE_DIR,
    logLevel: overrides.logLevel ?? env.HG_LOG_LEVEL ?? env.LOG_LEVEL,
  };

  const result = SensorConfigSchema.safeParse(raw);

  if (!result.success) {
    const errors = result.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`);
    console.error('[config] Validation errors:\n' + errors.join('\n'));
    throw new Error('Invalid sensor configuration');
  }

  return result.data;
}
