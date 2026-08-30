type Bucket = {
  count: number;
  resetAt: number;
};

const buckets = new Map<string, Bucket>();

export function consumeRateLimit(
  key: string,
  limit = 3,
  windowMs = 60_000
) {
  const now = Date.now();

  let bucket = buckets.get(key);

  // Create/reset bucket
  if (!bucket || now >= bucket.resetAt) {
    bucket = {
      count: 0,
      resetAt: now + windowMs,
    };

    buckets.set(key, bucket);
  }

  // Limit exceeded
  if (bucket.count >= limit) {
    return {
      allowed: false,
      remaining: 0,
      retryAfterMs: bucket.resetAt - now,
    };
  }

  bucket.count++;

  return {
    allowed: true,
    remaining: limit - bucket.count,
    retryAfterMs: bucket.resetAt - now,
  };
}

export function clearRateLimits() {
  buckets.clear();
}
