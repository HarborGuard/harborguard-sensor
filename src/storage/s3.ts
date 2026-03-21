import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import fs from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { createWriteStream } from 'node:fs';
import type { Readable } from 'node:stream';
import type { ScanEnvelope } from '../types/index.js';

export interface S3Config {
  endpoint?: string;
  bucket: string;
  accessKey: string;
  secretKey: string;
  region?: string;
}

export class S3Storage {
  private client: S3Client;
  private bucket: string;

  constructor(config: S3Config) {
    this.bucket = config.bucket;
    this.client = new S3Client({
      endpoint: config.endpoint,
      region: config.region ?? 'us-east-1',
      credentials: {
        accessKeyId: config.accessKey,
        secretAccessKey: config.secretKey,
      },
      forcePathStyle: !!config.endpoint, // Required for MinIO
    });
  }

  async uploadScanResults(scanId: string, envelope: ScanEnvelope): Promise<string> {
    const key = `scans/${scanId}/envelope.json`;
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: JSON.stringify(envelope, null, 2),
        ContentType: 'application/json',
      }),
    );
    return key;
  }

  async uploadRawResult(scanId: string, scannerName: string, data: unknown): Promise<string> {
    const key = `scans/${scanId}/raw/${scannerName}.json`;
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: JSON.stringify(data, null, 2),
        ContentType: 'application/json',
      }),
    );
    return key;
  }

  async uploadSbom(scanId: string, data: unknown): Promise<string> {
    const key = `scans/${scanId}/sbom.cdx.json`;
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: JSON.stringify(data, null, 2),
        ContentType: 'application/json',
      }),
    );
    return key;
  }

  async uploadArtifact(key: string, filePath: string): Promise<string> {
    const stream = createReadStream(filePath);
    const stat = await fs.stat(filePath);
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: stream,
        ContentLength: stat.size,
      }),
    );
    return key;
  }

  async getPresignedUrl(key: string, expiresIn = 3600): Promise<string> {
    const command = new GetObjectCommand({
      Bucket: this.bucket,
      Key: key,
    });
    return getSignedUrl(this.client, command, { expiresIn });
  }

  async exists(key: string): Promise<boolean> {
    try {
      await this.client.send(
        new HeadObjectCommand({
          Bucket: this.bucket,
          Key: key,
        }),
      );
      return true;
    } catch {
      return false;
    }
  }

  async downloadToFile(key: string, destPath: string): Promise<void> {
    const response = await this.client.send(
      new GetObjectCommand({
        Bucket: this.bucket,
        Key: key,
      }),
    );
    if (!response.Body) {
      throw new Error(`Empty response for key: ${key}`);
    }
    await pipeline(response.Body as Readable, createWriteStream(destPath));
  }
}
