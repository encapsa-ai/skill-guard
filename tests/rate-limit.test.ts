import assert from "node:assert/strict"
import test, { type TestContext } from "node:test"
import type { Ratelimit } from "@upstash/ratelimit"
import { ArchiveError } from "../lib/skill-guard/archive"
import { clientRateLimitKey, createSharedRateLimits, quotaHeaders, ScanThrottleError, sharedScanLimits } from "../lib/skill-guard/rate-limit"
import { reserveScan } from "../lib/skill-guard/request-guard"
import { AI_REVIEW_RATE_LIMIT, RATE_LIMIT_WINDOW_SECONDS, SCAN_RATE_LIMIT, type RateLimitScope, type ScanQuota } from "../lib/skill-guard/types"

type LimitResult = Awaited<ReturnType<Ratelimit["limit"]>>
const request = (headers: HeadersInit = {}) => new Request("https://skills.example.com/api/analyze", { headers })
const result = (overrides: Partial<LimitResult> = {}): LimitResult => ({
  success: true, limit: SCAN_RATE_LIMIT, remaining: SCAN_RATE_LIMIT - 1,
  reset: Date.now() + RATE_LIMIT_WINDOW_SECONDS * 1000, pending: Promise.resolve(), ...overrides,
})
const quota = (scope: RateLimitScope): ScanQuota => ({
  scope, limit: scope === "scan" ? SCAN_RATE_LIMIT : AI_REVIEW_RATE_LIMIT, remaining: 1, reset: Date.now() + 600_000,
})

function vercel(context: TestContext, enabled = true) {
  const previous = process.env.VERCEL
  if (enabled) process.env.VERCEL = "1"
  else delete process.env.VERCEL
  context.after(() => { if (previous === undefined) delete process.env.VERCEL; else process.env.VERCEL = previous })
}

function allowQuotas(context: TestContext) {
  return context.mock.method(sharedScanLimits, "consume", async (_request: Request, scope: RateLimitScope) => quota(scope))
}

function throttle(scope: RateLimitScope = "scan") {
  return new ScanThrottleError("Quota reached.", { code: "rate-limited", scope, retryAfterSeconds: 30, quota: { ...quota(scope), remaining: 0 } })
}

function isThrottle(status: number, scope: RateLimitScope = "scan") {
  return (error: unknown) => error instanceof ScanThrottleError && error.status === status && error.scope === scope
}

test("quota identities are stable keyed hashes, not stored IP addresses", (context) => {
  vercel(context)
  const input = request({ "x-vercel-forwarded-for": "203.0.113.10" })
  const key = clientRateLimitKey(input, "test-secret")
  assert.match(key, /^[a-f0-9]{64}$/)
  assert.equal(key, clientRateLimitKey(input, "test-secret"))
  assert.notEqual(key, clientRateLimitKey(input, "different-secret"))
  assert.notEqual(key, clientRateLimitKey(request({ "x-vercel-forwarded-for": "203.0.113.11" }), "test-secret"))
})

test("client-controlled forwarding headers cannot reset the trusted quota", (context) => {
  vercel(context)
  const trusted = { "x-vercel-forwarded-for": "203.0.113.10" }
  const key = clientRateLimitKey(request(trusted), "secret")
  assert.equal(key, clientRateLimitKey(request({ ...trusted, "x-forwarded-for": "198.51.100.2", "x-real-ip": "198.51.100.3" }), "secret"))
  assert.equal(key, clientRateLimitKey(request({ "x-vercel-forwarded-for": "203.0.113.10, 198.51.100.2" }), "secret"))
  assert.equal(clientRateLimitKey(request(), "secret"), clientRateLimitKey(request({ "x-forwarded-for": "198.51.100.2" }), "secret"))
  assert.equal(clientRateLimitKey(request(), "secret"), clientRateLimitKey(request({ "x-vercel-forwarded-for": "not-an-ip" }), "secret"))
})

test("non-Vercel hosts do not trust user-supplied proxy headers", (context) => {
  vercel(context, false)
  assert.equal(clientRateLimitKey(request(), "secret"), clientRateLimitKey(request({ "x-vercel-forwarded-for": "203.0.113.10" }), "secret"))
})

test("IPv6 privacy addresses share a /64 and mapped IPv4 has one identity", (context) => {
  vercel(context)
  const key = (ip: string) => clientRateLimitKey(request({ "x-vercel-forwarded-for": ip }), "secret")
  assert.equal(key("203.0.113.10"), key("::ffff:203.0.113.10"))
  assert.equal(key("2001:db8:abcd:1234::1"), key("2001:0DB8:ABCD:1234:ffff:ffff:ffff:ffff"))
  assert.notEqual(key("2001:db8:abcd:1234::1"), key("2001:db8:abcd:1235::1"))
})

test("shared limiter services use the same identity and separate scan and AI counters", async (context) => {
  vercel(context)
  const counts = new Map<string, number>()
  const makeLimiter = (scope: RateLimitScope, limit: number) => ({
    async limit(identifier: string) {
      const key = `${scope}:${identifier}`
      const count = (counts.get(key) ?? 0) + 1
      counts.set(key, count)
      return result({ success: count <= limit, limit, remaining: Math.max(0, limit - count) })
    },
  })
  const first = createSharedRateLimits({ scan: makeLimiter("scan", 25), ai: makeLimiter("ai", 8) }, "secret")
  const second = createSharedRateLimits({ scan: makeLimiter("scan", 25), ai: makeLimiter("ai", 8) }, "secret")
  const input = request({ "x-vercel-forwarded-for": "203.0.113.10" })
  const attempts = await Promise.allSettled(Array.from({ length: 26 }, (_, i) => (i % 2 ? first : second).consume(input, "scan")))
  assert.equal(attempts.filter((attempt) => attempt.status === "fulfilled").length, 25)
  assert.equal(attempts.filter((attempt) => attempt.status === "rejected" && isThrottle(429)(attempt.reason)).length, 1)
  for (let i = 0; i < 8; i++) await first.consume(input, "ai")
  await assert.rejects(second.consume(input, "ai"), isThrottle(429, "ai"))
  assert.equal((await second.consume(request({ "x-vercel-forwarded-for": "203.0.113.11" }), "scan")).remaining, 24)
})

test("retry delays use the remaining window, with rounded reset headers", async (context) => {
  const now = 1_800_000_000_000
  context.mock.method(Date, "now", () => now)
  const limiter = { limit: async () => result({ success: false, remaining: -1, reset: now + 12_250 }) }
  const service = createSharedRateLimits({ scan: limiter, ai: limiter }, "secret")
  await assert.rejects(service.consume(request(), "scan"), (error: unknown) => {
    assert.ok(error instanceof ScanThrottleError)
    assert.equal(error.retryAfterSeconds, 13)
    assert.equal(error.headers["Retry-After"], "13")
    assert.equal(error.headers["X-RateLimit-Reset"], String(Math.ceil((now + 12_250) / 1000)))
    assert.equal(error.headers["X-RateLimit-Remaining"], "0")
    return true
  })
  assert.equal(quotaHeaders(quota("ai"), "X-AI-RateLimit")["X-AI-RateLimit-Limit"], "8")
})

test("a passed reset deadline never emits a zero Retry-After", async () => {
  const limiter = { limit: async () => result({ success: false, remaining: 0, reset: Date.now() - 1000 }) }
  const service = createSharedRateLimits({ scan: limiter, ai: limiter }, "secret")
  await assert.rejects(service.consume(request(), "scan"), (error: unknown) => error instanceof ScanThrottleError && error.retryAfterSeconds === 1)
})

test("SDK fail-open timeouts and Redis failures are converted into safe 503s", async (context) => {
  const warnings = context.mock.method(console, "warn", () => undefined)
  for (const limit of [
    async () => result({ success: true, reason: "timeout", reset: 0 }),
    async () => { throw new Error("private-token-at-redis.example.invalid") },
    async () => result({ pending: Promise.reject(new Error("private-background-error")) }),
  ]) {
    const service = createSharedRateLimits({ scan: { limit }, ai: { limit } }, "secret")
    for (const scope of ["scan", "ai"] as const) {
      await assert.rejects(service.consume(request(), scope), (error: unknown) => {
        assert.ok(error instanceof ScanThrottleError)
        assert.equal(error.status, 503)
        assert.equal(error.code, "rate-limit-unavailable")
        assert.equal(error.scope, "scan")
        assert.equal(error.retryAfterSeconds, 15)
        assert.ok(!error.message.includes("private"))
        return true
      })
    }
  }
  assert.ok(!JSON.stringify(warnings.mock.calls).includes("private"))
})

test("missing Redis credentials cannot silently fall back to local quotas", async (context) => {
  const names = ["KV_REST_API_URL", "KV_REST_API_TOKEN", "UPSTASH_REDIS_REST_URL", "UPSTASH_REDIS_REST_TOKEN"] as const
  const previous = names.map((name) => process.env[name])
  for (const name of names) delete process.env[name]
  context.after(() => names.forEach((name, index) => { if (previous[index] === undefined) delete process.env[name]; else process.env[name] = previous[index] }))
  await assert.rejects(sharedScanLimits.consume(request(), "scan"), isThrottle(503))
})

test("scan reservations hold local capacity while Redis checks are pending", async (context) => {
  const releases: Array<(value: ScanQuota) => void> = []
  context.mock.method(sharedScanLimits, "consume", () => new Promise<ScanQuota>((resolve) => { releases.push(resolve) }))
  const pending = Array.from({ length: 4 }, () => reserveScan(request()))
  await assert.rejects(reserveScan(request()), isThrottle(503))
  assert.equal(releases.length, 4)
  for (const resolve of releases) resolve(quota("scan"))
  const reservations = await Promise.all(pending)
  for (const reservation of reservations) { reservation.release(); reservation.release() }
  allowQuotas(context)
  const next = await reserveScan(request())
  next.release()
})

test("rejected shared checks do not leak local scan capacity", async (context) => {
  context.mock.method(sharedScanLimits, "consume", async () => { throw throttle() })
  for (let i = 0; i < 8; i++) await assert.rejects(reserveScan(request()), isThrottle(429))
  allowQuotas(context)
  const reservation = await reserveScan(request())
  reservation.release()
})

test("AI admission is idempotent and capacity is released exactly once", async (context) => {
  const consume = allowQuotas(context)
  const reservations = await Promise.all(Array.from({ length: 3 }, () => reserveScan(request())))
  context.after(() => reservations.forEach((reservation) => reservation.release()))
  await Promise.all([reservations[0].enableAI(), reservations[0].enableAI()])
  assert.equal(consume.mock.calls.filter((call) => call.arguments[1] === "ai").length, 1)
  assert.equal(reservations[0].headers["X-AI-RateLimit-Limit"], "8")
  await reservations[1].enableAI()
  await assert.rejects(reservations[2].enableAI(), isThrottle(503, "ai"))
  reservations[0].release()
  reservations[0].release()
  await reservations[2].enableAI()
  await assert.rejects(reservations[0].enableAI(), (error: unknown) => error instanceof ArchiveError && error.status === 499)
})

test("AI quota rejections do not leak AI slots or turn static scans into AI requests", async (context) => {
  context.mock.method(sharedScanLimits, "consume", async (_request: Request, scope: RateLimitScope) => {
    if (scope === "ai") throw throttle("ai")
    return quota(scope)
  })
  for (let i = 0; i < 4; i++) {
    const reservation = await reserveScan(request())
    await assert.rejects(reservation.enableAI(), isThrottle(429, "ai"))
    reservation.release()
  }
  const consume = allowQuotas(context)
  const reservation = await reserveScan(request())
  assert.deepEqual(consume.mock.calls.map((call) => call.arguments[1]), ["scan"])
  await reservation.enableAI()
  reservation.release()
})

test("cancelling while Redis admits a scan releases the reserved slot", async (context) => {
  const controller = new AbortController()
  let resolve!: (value: ScanQuota) => void
  context.mock.method(sharedScanLimits, "consume", () => new Promise<ScanQuota>((done) => { resolve = done }))
  const pending = reserveScan(new Request("https://skills.example.com/api/analyze", { signal: controller.signal }))
  controller.abort()
  resolve(quota("scan"))
  await assert.rejects(pending, (error: unknown) => error instanceof ArchiveError && error.status === 499)
  allowQuotas(context)
  const reservations = await Promise.all(Array.from({ length: 4 }, () => reserveScan(request())))
  for (const reservation of reservations) reservation.release()
})

test("releasing a reservation during an AI quota check cannot leak or double-release slots", async (context) => {
  allowQuotas(context)
  const reservation = await reserveScan(request())
  let resolve!: (value: ScanQuota) => void
  context.mock.method(sharedScanLimits, "consume", () => new Promise<ScanQuota>((done) => { resolve = done }))
  const pending = reservation.enableAI()
  reservation.release()
  resolve(quota("ai"))
  await assert.rejects(pending, (error: unknown) => error instanceof ArchiveError && error.status === 499)
  allowQuotas(context)
  const next = await Promise.all(Array.from({ length: 3 }, () => reserveScan(request())))
  context.after(() => next.forEach((entry) => entry.release()))
  await next[0].enableAI()
  await next[1].enableAI()
  await assert.rejects(next[2].enableAI(), isThrottle(503, "ai"))
})
