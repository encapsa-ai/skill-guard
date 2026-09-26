import { ArchiveError, inspectArchive } from "@/lib/skill-guard/archive"
import { analyzeArchive } from "@/lib/skill-guard/analyzer"
import { addAIReview } from "@/lib/skill-guard/ai-review"
import { readBoundedFormData, reserveScan, validateScanRequest } from "@/lib/skill-guard/request-guard"
import { MAX_ZIP_BYTES } from "@/lib/skill-guard/types"

export const runtime = "nodejs"
export const maxDuration = 180

const responseHeaders = { "Cache-Control": "no-store, max-age=0" }

export async function POST(request: Request) {
  const started = Date.now()
  let reservation: ReturnType<typeof reserveScan> | undefined
  try {
    validateScanRequest(request)
    reservation = reserveScan(request)
    const form = await readBoundedFormData(request)
    if (form.getAll("file").length !== 1 || form.getAll("aiReview").length > 1 || [...form.keys()].some((key) => key !== "file" && key !== "aiReview")) {
      throw new ArchiveError("Send exactly one ZIP archive per request. The app queues multiple archives separately.")
    }
    const upload = form.get("file")
    const ai = form.get("aiReview")
    if (ai !== null && ai !== "true" && ai !== "false") throw new ArchiveError("Invalid AI review option.")
    if (!(upload instanceof File)) throw new ArchiveError("Select a ZIP archive to inspect.")
    if (!upload.name.toLowerCase().endsWith(".zip") || upload.name.length > 160 || /[\x00-\x1f\x7f]/.test(upload.name)) {
      throw new ArchiveError("Provide a .zip archive with a valid filename of 160 characters or fewer.")
    }
    if (!upload.size || upload.size > MAX_ZIP_BYTES) throw new ArchiveError("ZIP archives must be nonempty and no larger than 4 MB.", 413)
    if (ai === "true") reservation.enableAI()
    const archive = await inspectArchive(Buffer.from(await upload.arrayBuffer()), request.signal)
    let report = analyzeArchive(archive, upload.name, started)
    if (ai === "true" && !request.signal.aborted) {
      report = await addAIReview(report, archive.files, request.signal, { timeoutMs: Math.max(0, 165_000 - (Date.now() - started)) })
    }
    if (request.signal.aborted) throw new ArchiveError("The scan was cancelled.", 499)
    report.durationMs = Date.now() - started
    return Response.json({ report }, { headers: responseHeaders })
  } catch (cause) {
    const error = cause instanceof ArchiveError ? cause : new ArchiveError("The archive could not be analyzed. Please try a smaller, standard ZIP or retry shortly.", 500)
    return Response.json({ error: error.message }, {
      status: error.status,
      headers: { ...responseHeaders, ...(error.status === 429 ? { "Retry-After": "600" } : {}) },
    })
  } finally {
    reservation?.release()
  }
}
