export type ImageSource =
  | { type: 'docker'; ref: string }
  | { type: 'registry'; ref: string }
  | { type: 'tar'; path: string };

export interface ScannerResult {
  scanner: string;
  success: boolean;
  data?: unknown;
  error?: string;
  durationMs: number;
  version?: string;
}

export interface IScanner {
  readonly name: string;
  scan(source: ImageSource, outputPath: string): Promise<ScannerResult>;
  getVersion(): Promise<string>;
  isAvailable(): Promise<boolean>;
  supportsSource(source: ImageSource): boolean;
}
