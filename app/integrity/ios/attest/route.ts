import { NextResponse } from 'next/server';
import { verifyAttestation } from 'node-app-attest';

import {
  cleanupExpiredChallenges,
  requireEnv,
} from '@/lib/integrityStore';
import { deleteChallenge, loadChallenge, saveIosKey } from '@/lib/integrityPersistence';

export const runtime = 'nodejs';

function json(data: unknown, init?: ResponseInit) {
  return NextResponse.json(data, {
    ...init,
    headers: {
      'Cache-Control': 'no-store',
      ...(init?.headers || {}),
    },
  });
}

// ---------------------------
// iOS: POST /integrity/ios/attest
// ---------------------------
export async function POST(request: Request) {
  try {
    cleanupExpiredChallenges();

    const body = await request.json().catch(() => null);
    const { requestId, keyId, challenge, attestation } = (body || {}) as {
      requestId?: string;
      keyId?: string;
      challenge?: string; // base64url
      attestation?: string; // base64
    };

    if (!requestId || !keyId || !challenge || !attestation) {
      return json({ ok: false, reason: 'missing_fields' }, { status: 400 });
    }

    const record = await loadChallenge(requestId);
    if (!record || record.platform !== 'ios' || record.keyId !== keyId) {
      return json({ ok: false, reason: 'invalid_requestId' }, { status: 401 });
    }
    if (record.challenge !== challenge) {
      return json({ ok: false, reason: 'challenge_mismatch' }, { status: 401 });
    }

    const bundleIdentifier = requireEnv('IOS_BUNDLE_ID');
    const teamIdentifier = requireEnv('IOS_TEAM_ID');

    const result = verifyAttestation({
      attestation: Buffer.from(attestation, 'base64'),
      challenge: Buffer.from(challenge, 'base64url'),
      keyId,
      bundleIdentifier,
      teamIdentifier,
      allowDevelopmentEnvironment:
        String(process.env.IOS_ALLOW_DEVELOPMENT_ENV || 'false').toLowerCase() === 'true',
    });

    await saveIosKey(keyId, { publicKey: result.publicKey, signCount: 0 });
    await deleteChallenge(requestId);
    return json({ ok: true });
  } catch {
    return json({ ok: false, reason: 'unauthorized' }, { status: 401 });
  }
}

