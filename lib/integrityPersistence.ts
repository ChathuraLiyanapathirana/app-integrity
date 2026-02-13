import { getRedis } from '@/lib/redis';
import type { ChallengeRecord, IosKeyRecord } from '@/lib/integrityStore';
import { getChallengeTtlMs, getIntegrityStore } from '@/lib/integrityStore';

type StoredIosKey = {
  publicKeyB64: string;
  signCount: number;
};

function challengeKey(requestId: string) {
  return `integrity:challenge:${requestId}`;
}

function iosKeyKey(keyId: string) {
  return `integrity:ioskey:${keyId}`;
}

function ttlSeconds() {
  return Math.max(1, Math.ceil(getChallengeTtlMs() / 1000));
}

export async function persistChallenge(requestId: string, rec: ChallengeRecord) {
  const redis = getRedis();
  if (!redis) {
    getIntegrityStore().challenges.set(requestId, rec);
    return;
  }
  await redis.set(challengeKey(requestId), JSON.stringify(rec), { ex: ttlSeconds() });
}

export async function loadChallenge(requestId: string): Promise<ChallengeRecord | null> {
  const redis = getRedis();
  if (!redis) {
    return getIntegrityStore().challenges.get(requestId) ?? null;
  }
  const raw = await redis.get<string>(challengeKey(requestId));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as ChallengeRecord;
  } catch {
    return null;
  }
}

export async function deleteChallenge(requestId: string) {
  const redis = getRedis();
  if (!redis) {
    getIntegrityStore().challenges.delete(requestId);
    return;
  }
  await redis.del(challengeKey(requestId));
}

export async function loadIosKey(keyId: string): Promise<IosKeyRecord | null> {
  const redis = getRedis();
  if (!redis) {
    return getIntegrityStore().iosKeys.get(keyId) ?? null;
  }
  const raw = await redis.get<string>(iosKeyKey(keyId));
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as StoredIosKey;
    return {
      publicKey: Buffer.from(parsed.publicKeyB64, 'base64'),
      signCount: Number(parsed.signCount) || 0,
    };
  } catch {
    return null;
  }
}

export async function saveIosKey(keyId: string, rec: IosKeyRecord) {
  const redis = getRedis();
  if (!redis) {
    getIntegrityStore().iosKeys.set(keyId, rec);
    return;
  }
  const value: StoredIosKey = {
    publicKeyB64: rec.publicKey.toString('base64'),
    signCount: rec.signCount,
  };
  await redis.set(iosKeyKey(keyId), JSON.stringify(value));
}

