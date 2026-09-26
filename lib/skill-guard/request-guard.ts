import { ArchiveError } from "./archive"
import { quotaHeaders, ScanThrottleError, sharedScanLimits } from "./rate-limit"
import { MAX_ZIP_BYTES } from "./types"

let activeScans = 0
let activeAIReviews = 0

// Instance-local backpressure is not a distributed quota; use Vercel Firewall for deployment-wide abuse controls.
export async function reserveScan(request: Request) {
  if (request.signal.aborted) throw new ArchiveError("The scan was cancelled.", 499)
  if (activeScans >= 4) throw new ScanThrottleError("The analyzer is busy. Please try again shortly.", {
    code: "busy", scope: "scan", retryAfterSeconds: 5,
  })
  activeScans++
  try {
    const quota = await sharedScanLimits.consume(request, "scan")
    if (request.signal.aborted) throw new ArchiveError("The scan was cancelled.", 499)
    const headers = quotaHeaders(quota)
    let holdsAI = false
    let aiReservation: Promise<void> | undefined
    let released = false
    return {
      headers,
      async enableAI() {
        if (released || request.signal.aborted) throw new ArchiveError("The scan was cancelled.", 499)
        if (aiReservation) return aiReservation
        if (activeAIReviews >= 2) throw new ScanThrottleError("AI review is busy. Retry shortly or use static analysis.", {
          code: "busy", scope: "ai", retryAfterSeconds: 15,
        })
        activeAIReviews++
        holdsAI = true
        aiReservation = (async () => {
          try {
            const aiQuota = await sharedScanLimits.consume(request, "ai")
            if (released || request.signal.aborted) throw new ArchiveError("The scan was cancelled.", 499)
            Object.assign(headers, quotaHeaders(aiQuota, "X-AI-RateLimit"))
          } catch (cause) {
            if (holdsAI) { activeAIReviews--; holdsAI = false }
            aiReservation = undefined
            throw cause
          }
        })()
        return aiReservation
      },
      release() {
        if (released) return
        released = true
        activeScans--
        if (holdsAI) { activeAIReviews--; holdsAI = false }
      },
    }
  } catch (cause) {
    activeScans--
    throw cause
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
