import { createHash } from "node:crypto"
import { ArchiveError } from "./archive"
import { MAX_ZIP_BYTES } from "./types"

const buckets = new Map<string, { expires: number; scans: number; ai: number }>()
let activeScans = 0
let activeAIReviews = 0

// Instance-local backpressure is not a distributed quota; use Vercel Firewall for deployment-wide abuse controls.
export function reserveScan(request: Request) {
  const now = Date.now()
  for (const [key, bucket] of buckets) if (bucket.expires <= now) buckets.delete(key)
  const address = process.env.VERCEL ? request.headers.get("x-vercel-forwarded-for") ?? "shared" : "development"
  const key = createHash("sha256").update(address).digest("hex")
  const bucket = buckets.get(key) ?? { expires: now + 10 * 60_000, scans: 0, ai: 0 }
  if (bucket.scans >= 25) throw new ArchiveError("The scan limit was reached. Please try again in 10 minutes.", 429)
  if (activeScans >= 4 || (!buckets.has(key) && buckets.size >= 2000)) throw new ArchiveError("The analyzer is busy. Please try again shortly.", 503)
  bucket.scans++
  buckets.set(key, bucket)
  activeScans++
  let ai = false
  let released = false
  return {
    enableAI() {
      if (ai) return
      if (bucket.ai >= 8) throw new ArchiveError("The AI review limit was reached. Retry later or turn off AI-assisted review for a static scan.", 429)
      if (activeAIReviews >= 2) throw new ArchiveError("AI review is busy. Retry shortly or use static analysis.", 503)
      bucket.ai++
      activeAIReviews++
      ai = true
    },
    release() {
      if (released) return
      released = true
      activeScans--
      if (ai) activeAIReviews--
    },
  }
}

export function validateScanRequest(request: Request) {
  const origin = request.headers.get("origin")
  const fetchSite = request.headers.get("sec-fetch-site")
  if (fetchSite === "cross-site") throw new ArchiveError("Cross-site uploads are not accepted.", 403)
  if (origin) {
    let source: URL
    try { source = new URL(origin) } catch { throw new ArchiveError("Invalid request origin.", 403) }
    if (!["http:", "https:"].includes(source.protocol) || source.origin !== origin) throw new ArchiveError("Invalid request origin.", 403)
    const forwardedHost = request.headers.get("x-forwarded-host")?.split(",")[0]?.trim()
    const publicHost = forwardedHost || request.headers.get("host") || new URL(request.url).host
    // Browser-set Fetch Metadata preserves the public origin when a preview or deployment proxy rewrites Host.
    if (fetchSite !== "same-origin" && source.host !== publicHost.toLowerCase()) throw new ArchiveError("Upload files from the Skill Guard page.", 403)
  }
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("multipart/form-data;")) throw new ArchiveError("Upload a ZIP file using multipart form data.", 415)
  const declared = Number(request.headers.get("content-length"))
  if (declared > MAX_ZIP_BYTES + 128 * 1024) throw new ArchiveError("This upload exceeds the 4 MB archive limit.", 413)
}

export async function readBoundedFormData(request: Request) {
  if (!request.body) throw new ArchiveError("No upload was provided.")
  const reader = request.body.getReader()
  const signal = AbortSignal.any([request.signal, AbortSignal.timeout(12_000)])
  const abort = () => { void reader.cancel().catch(() => undefined) }
  signal.addEventListener("abort", abort, { once: true })
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    while (true) {
      if (signal.aborted) throw new ArchiveError("The upload was interrupted or timed out.", 408)
      const { done, value } = await reader.read()
      if (signal.aborted) throw new ArchiveError("The upload was interrupted or timed out.", 408)
      if (done) break
      length += value.byteLength
      if (length > MAX_ZIP_BYTES + 128 * 1024) {
        await reader.cancel()
        throw new ArchiveError("This upload exceeds the 4 MB archive limit.", 413)
      }
      chunks.push(value)
    }
    const bytes = new Uint8Array(length)
    let offset = 0
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
    try {
      return await new Response(bytes, { headers: { "content-type": request.headers.get("content-type")! } }).formData()
    } catch {
      throw new ArchiveError("The upload form is malformed. Select your ZIP again and retry.")
    }
  } finally {
    signal.removeEventListener("abort", abort)
    reader.releaseLock()
  }
}
