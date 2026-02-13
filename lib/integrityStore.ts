import crypto from 'crypto';
import path from 'path';

export type AndroidChallengeRecord = {
  platform: 'android';
  nonce: string; // base64url
  createdAt: number;
};

export type IosChallengeRecord = {
  platform: 'ios';
  keyId: string;
  challenge: string; // base64url
  createdAt: number;
};

export type ChallengeRecord = AndroidChallengeRecord | IosChallengeRecord;

export type IosKeyRecord = {
  publicKey: Buffer;
  signCount: number;
};

export type IntegrityStore = {
  challenges: Map<string, ChallengeRecord>;
  iosKeys: Map<string, IosKeyRecord>;
};

declare global {
  var __integrityStore: IntegrityStore | undefined;
}

export function getIntegrityStore(): IntegrityStore {
  if (!globalThis.__integrityStore) {
    globalThis.__integrityStore = {
      challenges: new Map<string, ChallengeRecord>(),
      iosKeys: new Map<string, IosKeyRecord>(),
    };
  }
  return globalThis.__integrityStore;
}

export function now() {
  return Date.now();
}

export function randomBase64Url(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function randomBase64(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64');
}

export function requireEnv(name: string) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

export function getChallengeTtlMs() {
  const raw = process.env.INTEGRITY_CHALLENGE_TTL_MS;
  const parsed = raw ? Number(raw) : NaN;
  if (Number.isFinite(parsed) && parsed > 0) return parsed;
  return 5 * 60 * 1000;
}

export function cleanupExpiredChallenges(store = getIntegrityStore()) {
  const ttlMs = getChallengeTtlMs();
  const cutoff = now() - ttlMs;
  for (const [requestId, rec] of store.challenges.entries()) {
    if (rec.createdAt < cutoff) store.challenges.delete(requestId);
  }
}

/**
 * Google auth libraries read GOOGLE_APPLICATION_CREDENTIALS from disk.
 * This helper makes relative paths (e.g. "./service-account.json") work reliably.
 */
export function resolveGoogleApplicationCredentialsPath() {
  const p = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (!p) return;
  if (path.isAbsolute(p)) return;
  process.env.GOOGLE_APPLICATION_CREDENTIALS = path.resolve(process.cwd(), p);
}

