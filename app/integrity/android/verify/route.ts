import { NextResponse } from 'next/server';
import { google } from 'googleapis';

import {
  cleanupExpiredChallenges,
  getIntegrityStore,
  requireEnv,
  resolveGoogleApplicationCredentialsPath,
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

// --------------------------------
// Android: POST /integrity/android/verify
// --------------------------------
export async function POST(request: Request) {
  try {
    cleanupExpiredChallenges();
    const store = getIntegrityStore();

    const body = await request.json().catch(() => null);
    const { requestId, nonce, token } = (body || {}) as {
      requestId?: string;
      nonce?: string;
      token?: string;
    };

    if (!requestId || !nonce || !token) {
      return json({ ok: false, reason: 'missing_fields' }, { status: 400 });
    }

    const record = store.challenges.get(requestId);
    if (!record || record.platform !== 'android') {
      return json({ ok: false, reason: 'invalid_requestId' }, { status: 401 });
    }
    if (record.nonce !== nonce) {
      return json({ ok: false, reason: 'nonce_mismatch' }, { status: 401 });
    }

    // Required backend credentials:
    // - GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json
    //   OR (recommended for Vercel/serverless) GOOGLE_APPLICATION_CREDENTIALS_JSON / _B64
    // - ANDROID_PACKAGE_NAME=com.fg.patpat (must match your appId)
    // - (Optional) ANDROID_ALLOWED_CERT_SHA256=... (signing cert digest)
    const packageName = requireEnv('ANDROID_PACKAGE_NAME');
    const scopes = ['https://www.googleapis.com/auth/playintegrity'];

    const credsJson =
      process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON ||
      process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
    const credsB64 = process.env.GOOGLE_APPLICATION_CREDENTIALS_B64;

    let auth: InstanceType<typeof google.auth.GoogleAuth>;
    if (credsJson || credsB64) {
      const raw = credsJson
        ? credsJson
        : Buffer.from(credsB64 as string, 'base64').toString('utf8');
      const credentials = JSON.parse(raw) as Record<string, unknown>;
      auth = new google.auth.GoogleAuth({ scopes, credentials });
    } else {
      // Local/dev: allow GOOGLE_APPLICATION_CREDENTIALS to point to a file path
      resolveGoogleApplicationCredentialsPath();
      auth = new google.auth.GoogleAuth({ scopes });
    }
    const playintegrity = google.playintegrity({ version: 'v1', auth });

    const decode = await playintegrity.v1.decodeIntegrityToken({
      packageName,
      requestBody: { integrityToken: token },
    });

    const payload = decode?.data?.tokenPayloadExternal;
    if (!payload) {
      return json({ ok: false, reason: 'no_payload' }, { status: 401 });
    }

    const requestDetails = payload.requestDetails || {};
    const appIntegrity = payload.appIntegrity || {};
    const deviceIntegrity = payload.deviceIntegrity || {};

    if (requestDetails.requestPackageName !== packageName) {
      return json({ ok: false, reason: 'package_mismatch' }, { status: 401 });
    }
    if (requestDetails.nonce !== nonce) {
      return json({ ok: false, reason: 'nonce_mismatch_payload' }, { status: 401 });
    }

    if (appIntegrity.appRecognitionVerdict !== 'PLAY_RECOGNIZED') {
      return json(
        {
          ok: false,
          reason: `app_not_recognized:${appIntegrity.appRecognitionVerdict}`,
        },
        { status: 401 },
      );
    }

    // Optional: enforce signing certificate digests (repackaging protection).
    const allowedCerts = (process.env.ANDROID_ALLOWED_CERT_SHA256 || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const certDigests = (appIntegrity.certificateSha256Digest || []) as string[];
    if (allowedCerts.length > 0 && Array.isArray(certDigests)) {
      const ok = allowedCerts.some((c) => certDigests.includes(c));
      if (!ok) return json({ ok: false, reason: 'signing_cert_mismatch' }, { status: 401 });
    }

    // Optional: require a strong device integrity verdict.
    const verdicts = (deviceIntegrity.deviceRecognitionVerdict || []) as string[];
    const required = (process.env.ANDROID_REQUIRED_DEVICE_VERDICT || 'MEETS_DEVICE_INTEGRITY')
      .trim();
    if (required && Array.isArray(verdicts) && !verdicts.includes(required)) {
      return json(
        { ok: false, reason: `device_integrity_failed:${verdicts.join(',')}` },
        { status: 401 },
      );
    }

    store.challenges.delete(requestId);
    return json({ ok: true });
  } catch {
    // Avoid leaking details in production.
    return json({ ok: false, reason: 'server_error' }, { status: 500 });
  }
}

