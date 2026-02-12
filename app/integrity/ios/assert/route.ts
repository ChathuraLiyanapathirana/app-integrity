import { NextResponse } from 'next/server';
import { verifyAssertion } from 'node-app-attest';

import {
  cleanupExpiredChallenges,
  getIntegrityStore,
  requireEnv,
} from '@/lib/integrityStore';

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
// iOS: POST /integrity/ios/assert
// ---------------------------
export async function POST(request: Request) {
  try {
    cleanupExpiredChallenges();
    const store = getIntegrityStore();

    const body = await request.json().catch(() => null);
    const { requestId, keyId, challenge, assertion } = (body || {}) as {
      requestId?: string;
      keyId?: string;
      challenge?: string; // base64url
      assertion?: string; // base64
    };

    if (!requestId || !keyId || !challenge || !assertion) {
      return json({ ok: false, reason: 'missing_fields' }, { status: 400 });
    }

    const record = store.challenges.get(requestId);
    if (!record || record.platform !== 'ios' || record.keyId !== keyId) {
      return json({ ok: false, reason: 'invalid_requestId' }, { status: 401 });
    }
    if (record.challenge !== challenge) {
      return json({ ok: false, reason: 'challenge_mismatch' }, { status: 401 });
    }

    const bundleIdentifier = requireEnv('IOS_BUNDLE_ID');
    const teamIdentifier = requireEnv('IOS_TEAM_ID');

    const stored = store.iosKeys.get(keyId);
    if (!stored) {
      return json({ ok: false, reason: 'unknown_keyId' }, { status: 401 });
    }

    const result = verifyAssertion({
      assertion: Buffer.from(assertion, 'base64'),
      payload: Buffer.from(challenge, 'base64url'),
      publicKey: stored.publicKey,
      bundleIdentifier,
      teamIdentifier,
      signCount: stored.signCount,
    });

    store.iosKeys.set(keyId, {
      publicKey: stored.publicKey,
      signCount: result.signCount,
    });
    store.challenges.delete(requestId);
    return json({ ok: true });
  } catch {
    return json({ ok: false, reason: 'unauthorized' }, { status: 401 });
  }
}

