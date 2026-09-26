import assert from "node:assert/strict"
import test from "node:test"
import { POST } from "../app/api/analyze/route"
import { createSampleArchive } from "../lib/skill-guard/sample"
import { MAX_ZIP_BYTES } from "../lib/skill-guard/types"

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
