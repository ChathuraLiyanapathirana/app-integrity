import crypto from 'crypto';
import { NextRequest, NextResponse } from 'next/server';

import {
  cleanupExpiredChallenges,
  getIntegrityStore,
  now,
  randomBase64Url,
} from '@/lib/integrityStore';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const revalidate = 0;

function json(data: unknown, init?: ResponseInit) {
  return NextResponse.json(data, {
    ...init,
    headers: {
      'Cache-Control': 'no-store',
      ...(init?.headers || {}),
    },
  });
}

// -------------------------
// GET /integrity/challenge
// -------------------------
export async function GET(req: NextRequest) {
  cleanupExpiredChallenges();
  const store = getIntegrityStore();

  const platform = (req.nextUrl.searchParams.get('platform') || '')
    .toLowerCase()
    .trim();
  const keyId = req.nextUrl.searchParams.get('keyId') || undefined;

  const requestId = crypto.randomUUID();

  if (platform === 'android') {
    // Play Integrity requires "base64 web-safe no-wrap" (base64url without padding/newlines).
    const nonce = randomBase64Url(32);
    store.challenges.set(requestId, { platform: 'android', nonce, createdAt: now() });
    return json({
      ok: true,
      provider: 'android_play_integrity',
      requestId,
      nonce,
    });
  }

  if (platform === 'ios') {
    if (!keyId) return json({ ok: false, reason: 'missing_keyId' }, { status: 400 });

    const challenge = randomBase64Url(32);
    const mode = store.iosKeys.has(keyId) ? 'assert' : 'attest';
    store.challenges.set(requestId, {
      platform: 'ios',
      keyId,
      challenge,
      createdAt: now(),
    });

    return json({
      ok: true,
      provider: 'ios_app_attest',
      requestId,
      mode,
      challenge,
      keyId,
    });
  }

  return json({ ok: false, reason: 'bad_platform' }, { status: 400 });
}

