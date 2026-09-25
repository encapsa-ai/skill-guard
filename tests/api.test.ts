import assert from "node:assert/strict"
import test from "node:test"
import { POST } from "../app/api/analyze/route"
import { createSampleArchive } from "../lib/skill-guard/sample"
import { MAX_ZIP_BYTES } from "../lib/skill-guard/types"

function upload(options: { ai?: string; filename?: string; duplicate?: boolean; origin?: string } = {}) {
  const form = new FormData()
  form.append("file", new File([new Uint8Array(createSampleArchive())], options.filename ?? "sample.zip", { type: "application/zip" }))
  form.append("aiReview", options.ai ?? "false")
  if (options.duplicate) form.append("file", new File(["not a zip"], "second.zip"))
  return new Request("http://localhost:3000/api/analyze", { method: "POST", body: form, headers: options.origin ? { origin: options.origin } : {} })
}

test("scan endpoint returns a real, uncached static report", async () => {
  const response = await POST(upload())
  assert.equal(response.status, 200)
  assert.match(response.headers.get("cache-control") ?? "", /no-store/)
  const { report } = await response.json()
  assert.equal(report.coverage.totalFiles, 4)
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
