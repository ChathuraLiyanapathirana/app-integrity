import { NextResponse } from 'next/server';
import { google } from 'googleapis';
import crypto from 'crypto';

import {
  cleanupExpiredChallenges,
  getIntegrityStore,
  requireEnv,
  resolveGoogleApplicationCredentialsPath,
} from '@/lib/integrityStore';

export const runtime = 'nodejs';

function isDebug() {
  return String(process.env.INTEGRITY_DEBUG || '').toLowerCase() === 'true';
}


function envPresence(name: string) {
  const v = process.env[name];
  if (!v) return { name, set: false as const };
  return { name, set: true as const, length: v.length };
}

function fp(value: string) {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 12);
}

function toBase64Url(s: string) {
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeB64Any(input: string): Buffer | null {
  try {
    // Accept base64url or base64 (with/without padding).
    const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (normalized.length % 4)) % 4;
    const padded = normalized + '='.repeat(padLen);
    const buf = Buffer.from(padded, 'base64');
    if (buf.length === 0) return null;
    return buf;
  } catch {
    return null;
  }
}

function buffersEqual(a: Buffer, b: Buffer) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

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
    const recordNonceBytes = decodeB64Any(record.nonce);
    const bodyNonceBytes = decodeB64Any(nonce);
    if (!recordNonceBytes || !bodyNonceBytes || !buffersEqual(recordNonceBytes, bodyNonceBytes)) {
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

    if (isDebug()) {
      // Safe diagnostics: never log token or private keys.
      const credentialSource = credsJson ? 'json' : credsB64 ? 'b64' : 'file_or_default';
      console.log('[integrity/android/verify] debug env', {
        packageName,
        credentialSource,
        env: {
          ANDROID_PACKAGE_NAME: envPresence('ANDROID_PACKAGE_NAME'),
          GOOGLE_APPLICATION_CREDENTIALS_JSON: envPresence('GOOGLE_APPLICATION_CREDENTIALS_JSON'),
          GOOGLE_SERVICE_ACCOUNT_JSON: envPresence('GOOGLE_SERVICE_ACCOUNT_JSON'),
          GOOGLE_APPLICATION_CREDENTIALS_B64: envPresence('GOOGLE_APPLICATION_CREDENTIALS_B64'),
          GOOGLE_APPLICATION_CREDENTIALS: envPresence('GOOGLE_APPLICATION_CREDENTIALS'),
        },
        request: {
          requestIdFp: fp(requestId),
          nonceFp: fp(toBase64Url(nonce)),
          nonceLen: nonce.length,
        },
      });
    }

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
    if (typeof requestDetails.nonce !== 'string') {
      return json({ ok: false, reason: 'nonce_missing_payload' }, { status: 401 });
    }

    const payloadNonceBytes = decodeB64Any(requestDetails.nonce);
    if (!payloadNonceBytes || !buffersEqual(recordNonceBytes, payloadNonceBytes)) {
      if (isDebug()) {
        console.warn('[integrity/android/verify] nonce mismatch detail', {
          requestIdFp: fp(requestId),
          expected: { fp: fp(toBase64Url(record.nonce)), len: record.nonce.length },
          body: { fp: fp(toBase64Url(nonce)), len: nonce.length },
          payload: { fp: fp(toBase64Url(requestDetails.nonce)), len: requestDetails.nonce.length },
        });
      }
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
      .split(/[\s,]+/g) // allow comma / newline / spaces
      .map((s) => s.trim())
      .filter(Boolean);
    const certDigests = (appIntegrity.certificateSha256Digest || []) as string[];
    if (allowedCerts.length > 0 && Array.isArray(certDigests)) {
      const ok = allowedCerts.some((c) => certDigests.includes(c));
      if (!ok) {
        if (isDebug()) {
          console.warn('[integrity/android/verify] signing cert mismatch', {
            requestIdFp: fp(requestId),
            allowedCertsCount: allowedCerts.length,
            allowedCertsPreview: allowedCerts.map((c) => c.slice(0, 8) + '…'),
            payloadCertDigests: certDigests,
          });
          return json(
            {
              ok: false,
              reason: 'signing_cert_mismatch',
              debug: {
                payloadCertificateSha256Digest: certDigests,
                allowed: allowedCerts,
                hint:
                  'Set ANDROID_ALLOWED_CERT_SHA256 to one of payloadCertificateSha256Digest values, or unset it to disable pinning.',
              },
            },
            { status: 401 },
          );
        }
        return json({ ok: false, reason: 'signing_cert_mismatch' }, { status: 401 });
      }
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
  } catch (e) {
    const errorId = crypto.randomUUID();
    console.error('[integrity/android/verify] error', {
      errorId,
      message: e instanceof Error ? e.message : String(e),
      name: e instanceof Error ? e.name : undefined,
      stack: isDebug() && e instanceof Error ? e.stack : undefined,
    });
    // Avoid leaking details in production.
    return json({ ok: false, reason: 'server_error', errorId }, { status: 500 });
  }
}

