import { Redis } from '@upstash/redis';

declare global {
  var __upstashRedis: Redis | undefined;
}

function getRedisEnv() {
  // Preferred Upstash REST env vars
  const url = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

  if (!url || !token) return null;
  return { url, token };
}

export function getRedis(): Redis | null {
  const env = getRedisEnv();
  if (!env) return null;

  if (!globalThis.__upstashRedis) {
    globalThis.__upstashRedis = new Redis({ url: env.url, token: env.token });
  }
  return globalThis.__upstashRedis;
}

