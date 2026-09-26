import { createHmac } from "node:crypto"
import { isIP } from "node:net"
import { Ratelimit } from "@upstash/ratelimit"
import { Redis } from "@upstash/redis"
import ipaddr from "ipaddr.js"
import { ArchiveError } from "./archive"
import { AI_REVIEW_RATE_LIMIT, RATE_LIMIT_WINDOW_SECONDS, SCAN_RATE_LIMIT, type RateLimitScope, type ScanQuota } from "./types"

type ThrottleCode = "rate-limited" | "busy" | "rate-limit-unavailable"
type QuotaLimiter = Pick<Ratelimit, "limit">

export function quotaHeaders(quota: ScanQuota, prefix = "X-RateLimit"): Record<string, string> {
  return {
    [`${prefix}-Limit`]: String(quota.limit),
    [`${prefix}-Remaining`]: String(Math.max(0, quota.remaining)),
    [`${prefix}-Reset`]: String(Math.ceil(quota.reset / 1000)),
    [`${prefix}-Scope`]: quota.scope,
  }
}

export class ScanThrottleError extends ArchiveError {
  readonly code: ThrottleCode
  readonly scope: RateLimitScope
  readonly retryAfterSeconds: number
  readonly quota?: ScanQuota

  constructor(message: string, options: { code: ThrottleCode; scope: RateLimitScope; retryAfterSeconds: number; quota?: ScanQuota }) {
    super(message, options.code === "rate-limited" ? 429 : 503)
    this.name = "ScanThrottleError"
    this.code = options.code
    this.scope = options.scope
    this.retryAfterSeconds = Math.max(1, Math.ceil(options.retryAfterSeconds))
    this.quota = options.quota
  }

  get headers(): Record<string, string> {
    return {
      ...(this.quota ? quotaHeaders(this.quota) : {}),
      "Retry-After": String(this.retryAfterSeconds),
    }
  }
}

function unavailable() {
  return new ScanThrottleError("Scan protection is temporarily unavailable. Please try again shortly.", {
    code: "rate-limit-unavailable", scope: "scan", retryAfterSeconds: 15,
  })
}

export function clientRateLimitKey(request: Request, secret: string) {
  // Only Vercel's overwritten header is trusted. Other hosts share a conservative bucket.
  const raw = process.env.VERCEL === "1" ? request.headers.get("x-vercel-forwarded-for")?.split(",")[0]?.trim() : undefined
  let network = "shared"
  if (raw && isIP(raw)) {
    const address = ipaddr.process(raw)
    // Group IPv6 privacy addresses by /64 so rotating the interface ID cannot reset the quota.
    network = address.kind() === "ipv6"
      ? `ipv6:${Buffer.from(address.toByteArray().slice(0, 8)).toString("hex")}/64`
      : `ipv4:${address.toString()}`
  }
  return createHmac("sha256", secret).update(`skill-guard:rate-limit:v1:${network}`).digest("hex")
}

export function createSharedRateLimits(limiters: Record<RateLimitScope, QuotaLimiter>, secret: string) {
  return {
    async consume(request: Request, scope: RateLimitScope): Promise<ScanQuota> {
      let result: Awaited<ReturnType<QuotaLimiter["limit"]>>
      try {
        result = await limiters[scope].limit(clientRateLimitKey(request, secret))
        // The SDK permits requests on timeout by default; expensive scans must fail closed instead.
        if (result.reason === "timeout") throw new Error("rate-limit-timeout")
        await result.pending
      } catch {
        console.warn("[skill-guard] Rate-limit storage check failed", { scope })
        throw unavailable()
      }
      const quota: ScanQuota = { scope, limit: result.limit, remaining: Math.max(0, result.remaining), reset: result.reset }
      if (!result.success) {
        throw new ScanThrottleError(scope === "ai"
          ? "The AI review limit was reached. Wait to retry, or turn off AI-assisted review for a static scan."
          : "The scan limit for this network was reached. Please wait before trying again.", {
          code: "rate-limited", scope, quota,
          retryAfterSeconds: Math.max(1, Math.ceil((result.reset - Date.now()) / 1000)),
        })
      }
      return quota
    },
  }
}

let shared: ReturnType<typeof createSharedRateLimits> | undefined

function configuredRateLimits() {
  if (shared) return shared
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL
  const token = process.env.KV_REST_API_URL ? process.env.KV_REST_API_TOKEN : process.env.UPSTASH_REDIS_REST_TOKEN
  if (!url || !token) throw unavailable()

  const redis = new Redis({ url, token, retry: { retries: 0 }, signal: () => AbortSignal.timeout(2500), enableTelemetry: false })
  const environment = process.env.VERCEL_ENV || (process.env.NODE_ENV === "production" ? "production" : "development")
  const prefix = `skill-guard:${process.env.VERCEL_PROJECT_ID || "default"}:${environment}:rate-limit:v1`
  const makeLimiter = (scope: RateLimitScope, limit: number) => new Ratelimit({
    redis,
    prefix: `${prefix}:${scope}`,
    // Fixed windows preserve the existing quota policy and provide an exact retry deadline.
    limiter: Ratelimit.fixedWindow(limit, `${RATE_LIMIT_WINDOW_SECONDS} s`),
    ephemeralCache: false,
    analytics: false,
    timeout: 3000,
  })
  shared = createSharedRateLimits({ scan: makeLimiter("scan", SCAN_RATE_LIMIT), ai: makeLimiter("ai", AI_REVIEW_RATE_LIMIT) }, token)
  return shared
}

export const sharedScanLimits = {
  async consume(request: Request, scope: RateLimitScope) {
    try {
      return await configuredRateLimits().consume(request, scope)
    } catch (cause) {
      if (cause instanceof ScanThrottleError) throw cause
      console.warn("[skill-guard] Rate-limit configuration check failed")
      throw unavailable()
    }
  },
}
