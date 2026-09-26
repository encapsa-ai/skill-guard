import assert from "node:assert/strict"
import test, { beforeEach } from "node:test"
import { POST } from "../app/api/analyze/route"
import { ScanThrottleError, sharedScanLimits } from "../lib/skill-guard/rate-limit"
import { createSampleArchive } from "../lib/skill-guard/sample"
import { AI_REVIEW_RATE_LIMIT, MAX_ZIP_BYTES, SCAN_RATE_LIMIT, type RateLimitScope, type ScanQuota } from "../lib/skill-guard/types"

function quota(scope: RateLimitScope): ScanQuota {
  const limit = scope === "scan" ? SCAN_RATE_LIMIT : AI_REVIEW_RATE_LIMIT
  return { scope, limit, remaining: limit - 1, reset: Date.now() + 600_000 }
}

beforeEach((context) => {
  assert.ok("mock" in context)
  context.mock.method(sharedScanLimits, "consume", async (_request: Request, scope: RateLimitScope) => quota(scope))
})

function upload(options: { ai?: string; filename?: string; duplicate?: boolean; origin?: string; url?: string; headers?: HeadersInit } = {}) {
  const form = new FormData()
  form.append("file", new File([new Uint8Array(createSampleArchive())], options.filename ?? "sample.zip", { type: "application/zip" }))
  form.append("aiReview", options.ai ?? "false")
  if (options.duplicate) form.append("file", new File(["not a zip"], "second.zip"))
  const headers = new Headers(options.headers)
  if (options.origin) headers.set("origin", options.origin)
  return new Request(options.url ?? "http://localhost:3000/api/analyze", { method: "POST", body: form, headers })
}

test("scan endpoint returns a real, uncached static report", async () => {
  const response = await POST(upload())
  assert.equal(response.status, 200)
  assert.match(response.headers.get("cache-control") ?? "", /no-store/)
  assert.equal(response.headers.get("x-ratelimit-limit"), "25")
  assert.equal(response.headers.get("x-ratelimit-remaining"), "24")
  assert.equal(response.headers.get("x-ratelimit-scope"), "scan")
  assert.ok(Number(response.headers.get("x-ratelimit-reset")) > Date.now() / 1000)
  const { report } = await response.json()
  assert.equal(report.coverage.totalFiles, 4)
  assert.equal(report.skillNameSource, "frontmatter")
  assert.ok(report.skillName && report.skillName !== "sample")
  assert.equal(report.archiveName, "sample.zip")
  assert.ok(report.findings.length > 0)
  assert.equal(report.aiReview.status, "not-requested")
})

test("scan endpoint rejects multiple files in one request", async () => {
  const response = await POST(upload({ duplicate: true }))
  assert.equal(response.status, 400)
})

test("scan endpoint requires an explicit boolean AI option", async () => {
  const response = await POST(upload({ ai: "yes" }))
  assert.equal(response.status, 400)
})

test("scan endpoint rejects cross-origin form submissions", async () => {
  const response = await POST(upload({ origin: "https://untrusted.example.invalid" }))
  assert.equal(response.status, 403)
})

test("scan endpoint accepts browser-verified same-origin uploads behind a rewritten host", async () => {
  const response = await POST(upload({
    url: "http://internal-proxy:3000/api/analyze",
    origin: "https://skill-guard-preview.vercel.app",
    headers: { host: "internal-proxy:3000", "sec-fetch-site": "same-origin" },
  }))
  assert.equal(response.status, 200, JSON.stringify(await response.json()))
})

test("scan endpoint accepts forwarded public hosts without fetch metadata", async () => {
  for (const host of ["skill-guard-preview.vercel.app", "skills.example.com"]) {
    const response = await POST(upload({
      url: "http://internal-proxy:3000/api/analyze",
      origin: `https://${host}`,
      headers: { host: "internal-proxy:3000", "x-forwarded-host": host },
    }))
    assert.equal(response.status, 200, JSON.stringify(await response.json()))
  }
})

test("scan endpoint uses the first host in a forwarded proxy chain", async () => {
  const response = await POST(upload({
    origin: "https://skills.example.com",
    headers: { "x-forwarded-host": "skills.example.com, internal-proxy:3000" },
  }))
  assert.equal(response.status, 200)
})

test("scan endpoint accepts direct same-origin uploads without fetch metadata", async () => {
  const response = await POST(upload({ origin: "http://localhost:3000" }))
  assert.equal(response.status, 200)
})

test("scan endpoint rejects cross-site metadata even with a matching origin", async () => {
  const response = await POST(upload({
    origin: "http://localhost:3000",
    headers: { "sec-fetch-site": "cross-site", "x-forwarded-host": "localhost:3000" },
  }))
  assert.equal(response.status, 403)
})

test("scan endpoint rejects untrusted and sibling origins behind a proxy", async () => {
  for (const origin of ["https://untrusted.example.invalid", "https://other.skills.example.com", "https://skills.example.com.evil.invalid", "http://localhost:3000"]) {
    const response = await POST(upload({
      origin,
      headers: { "sec-fetch-site": "same-site", "x-forwarded-host": "skills.example.com" },
    }))
    assert.equal(response.status, 403, origin)
  }
})

test("scan endpoint does not trust later hosts in a forwarded chain", async () => {
  const response = await POST(upload({
    origin: "https://untrusted.example.invalid",
    headers: { "x-forwarded-host": "skills.example.com, untrusted.example.invalid" },
  }))
  assert.equal(response.status, 403)
})

test("scan endpoint rejects opaque or malformed origins even with same-origin metadata", async () => {
  for (const origin of ["null", "not-a-url", "file://localhost:3000", "https://skills.example.com/unexpected-path"]) {
    const response = await POST(upload({ origin, headers: { "sec-fetch-site": "same-origin" } }))
    assert.equal(response.status, 403, origin)
  }
})

test("scan endpoint rejects the wrong content type", async () => {
  const response = await POST(new Request("http://localhost:3000/api/analyze", { method: "POST", body: "{}", headers: { "content-type": "application/json" } }))
  assert.equal(response.status, 415)
})

test("scan endpoint rejects non-ZIP extensions", async () => {
  const response = await POST(upload({ filename: "sample.py" }))
  assert.equal(response.status, 400)
})

test("scan endpoint bounds actual request bytes, not just Content-Length", async () => {
  const response = await POST(new Request("http://localhost:3000/api/analyze", { method: "POST", body: new Uint8Array(MAX_ZIP_BYTES + 128 * 1024 + 1), headers: { "content-type": "multipart/form-data; boundary=test" } }))
  assert.equal(response.status, 413)
})

test("scan quota is enforced before reading uploads with the actual retry delay", async (context) => {
  context.mock.method(sharedScanLimits, "consume", async () => {
    throw new ScanThrottleError("Scan quota reached.", {
      code: "rate-limited", scope: "scan", retryAfterSeconds: 37,
      quota: { ...quota("scan"), remaining: 0 },
    })
  })
  const request = upload()
  const response = await POST(request)
  assert.equal(request.bodyUsed, false)
  assert.equal(response.status, 429)
  assert.equal(response.headers.get("retry-after"), "37")
  assert.equal(response.headers.get("x-ratelimit-remaining"), "0")
  assert.match(response.headers.get("cache-control") ?? "", /no-store/)
  assert.deepEqual(await response.json(), { error: "Scan quota reached.", code: "rate-limited", scope: "scan", retryAfterSeconds: 37 })
})

test("AI quota is separate and static scans remain available", async (context) => {
  const calls: RateLimitScope[] = []
  context.mock.method(sharedScanLimits, "consume", async (_request: Request, scope: RateLimitScope) => {
    calls.push(scope)
    if (scope === "ai") throw new ScanThrottleError("AI quota reached.", {
      code: "rate-limited", scope, retryAfterSeconds: 21, quota: { ...quota(scope), remaining: 0 },
    })
    return quota(scope)
  })
  const response = await POST(upload({ ai: "true" }))
  assert.equal(response.status, 429)
  assert.equal(response.headers.get("x-ratelimit-limit"), "8")
  assert.equal(response.headers.get("x-ratelimit-scope"), "ai")
  assert.equal(response.headers.get("retry-after"), "21")
  assert.equal((await response.json()).scope, "ai")
  assert.equal((await POST(upload())).status, 200)
  assert.deepEqual(calls, ["scan", "ai", "scan"])
})

test("Redis outages stop scans safely without returning infrastructure details", async (context) => {
  context.mock.method(sharedScanLimits, "consume", async () => {
    throw new ScanThrottleError("Scan protection is temporarily unavailable.", {
      code: "rate-limit-unavailable", scope: "scan", retryAfterSeconds: 15,
    })
  })
  const request = upload()
  const response = await POST(request)
  assert.equal(request.bodyUsed, false)
  assert.equal(response.status, 503)
  assert.equal(response.headers.get("retry-after"), "15")
  assert.deepEqual(await response.json(), {
    error: "Scan protection is temporarily unavailable.", code: "rate-limit-unavailable", scope: "scan", retryAfterSeconds: 15,
  })
})

test("invalid request headers do not consume Redis quota", async (context) => {
  const consume = context.mock.method(sharedScanLimits, "consume", async (_request: Request, scope: RateLimitScope) => quota(scope))
  assert.equal((await POST(upload({ origin: "https://untrusted.example.invalid" }))).status, 403)
  assert.equal((await POST(new Request("http://localhost:3000/api/analyze", { method: "POST", body: "{}", headers: { "content-type": "application/json" } }))).status, 415)
  assert.equal(consume.mock.callCount(), 0)
})

test("the endpoint releases local slots after malformed uploads", async () => {
  for (let i = 0; i < 8; i++) assert.equal((await POST(upload({ duplicate: true }))).status, 400)
  assert.equal((await POST(upload())).status, 200)
})

test("the endpoint awaits quota admission before consuming a request body", async (context) => {
  let allow!: (value: ScanQuota) => void
  context.mock.method(sharedScanLimits, "consume", () => new Promise<ScanQuota>((resolve) => { allow = resolve }))
  const request = upload()
  const response = POST(request)
  assert.equal(request.bodyUsed, false)
  allow(quota("scan"))
  assert.equal((await response).status, 200)
})
