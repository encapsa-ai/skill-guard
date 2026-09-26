"use client"

import { useEffect, useRef, useState } from "react"
import useSWRMutation from "swr/mutation"
import { MAX_ARCHIVES, MAX_ZIP_BYTES, RATE_LIMIT_WINDOW_SECONDS, type RateLimitScope, type ScanReport } from "@/lib/skill-guard/types"

class ScanRequestError extends Error {
  constructor(message: string, readonly status: number, readonly scope: RateLimitScope, readonly retryAfterSeconds: number) {
    super(message)
    this.name = "ScanRequestError"
  }
}

export interface QueuedSkill {
  id: string
  file: File
  skillName?: string
  sample?: boolean
  status: "queued" | "scanning" | "complete" | "error"
  error?: string
}

async function analyzeArchive(url: string, { arg }: { arg: { file: File; aiReview: boolean; signal: AbortSignal } }) {
  const data = new FormData()
  data.append("file", arg.file)
  data.append("aiReview", String(arg.aiReview))
  const response = await fetch(url, { method: "POST", body: data, signal: arg.signal })
  if (!response.ok) {
    const error = await response.json().catch(() => null)
    const retry = Number(response.headers.get("Retry-After"))
    const fallback = response.status === 429 ? RATE_LIMIT_WINDOW_SECONDS : 15
    throw new ScanRequestError(
      typeof error?.error === "string" ? error.error : response.status === 413 ? "This archive exceeds the upload limit." : "The scan could not finish. Please try again.",
      response.status,
      error?.scope === "ai" ? "ai" : "scan",
      Number.isFinite(retry) && retry > 0 ? Math.min(3600, Math.ceil(retry)) : fallback,
    )
  }
  const payload = await response.json() as { report: ScanReport }
  return payload.report
}

async function loadSample(url: string) {
  const response = await fetch(url)
  if (!response.ok) throw new Error("The sample could not be loaded. You can still upload your own ZIP.")
  return new File([await response.blob()], "calendar-helper-demo.zip", { type: "application/zip" })
}

export function useSkillScan() {
  const [queue, setQueue] = useState<QueuedSkill[]>([])
  const [reports, setReports] = useState<ScanReport[]>([])
  const [aiReview, setAiReview] = useState(false)
  const [isScanning, setIsScanning] = useState(false)
  const [isSample, setIsSample] = useState(false)
  const [error, setError] = useState("")
  const [ready, setReady] = useState(false)
  const [cooldowns, setCooldowns] = useState({ scan: 0, ai: 0 })
  const [now, setNow] = useState(0)
  const cooldownScope: RateLimitScope = aiReview && cooldowns.ai > cooldowns.scan ? "ai" : "scan"
  const retryAfterSeconds = Math.max(0, Math.ceil((cooldowns[cooldownScope] - now) / 1000))
  const abortController = useRef<AbortController | null>(null)
  const busy = useRef(false)
  const { trigger } = useSWRMutation("/api/analyze", analyzeArchive)
  const { trigger: sampleTrigger, isMutating: loadingSample } = useSWRMutation("/api/sample", loadSample)

  useEffect(() => {
    setReady(true)
    return () => abortController.current?.abort()
  }, [])

  useEffect(() => {
    const expires = Math.max(cooldowns.scan, cooldowns.ai)
    if (!expires) return
    const tick = () => {
      const time = Date.now()
      setNow(time)
      if (time >= expires) clearInterval(timer)
    }
    const timer = setInterval(tick, 1000)
    tick()
    return () => clearInterval(timer)
  }, [cooldowns])

  useEffect(() => {
    if (!isScanning && reports.length > 0 && queue.every((item) => item.status === "complete")) {
      document.getElementById("scan-report")?.scrollIntoView({
        behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "instant" : "smooth",
        block: "start",
      })
    }
  }, [isScanning, reports.length, queue])

  function addFiles(files: File[]) {
    if (busy.current) return
    const errors: string[] = []
    const accepted: QueuedSkill[] = []
    const uploads = queue.filter((item) => !item.sample)
    for (const file of files) {
      if (!file.name.toLowerCase().endsWith(".zip")) {
        errors.push(`${file.name}: please choose a .zip archive.`)
      } else if (file.size > MAX_ZIP_BYTES) {
        errors.push(`${file.name}: the maximum size is 4 MB.`)
      } else if (!file.size) {
        errors.push(`${file.name}: this file is empty.`)
      } else if (file.name.length > 160) {
        errors.push("Please shorten filenames to 160 characters or fewer.")
      } else if (uploads.some((item) => item.file.name === file.name && item.file.size === file.size && item.file.lastModified === file.lastModified) || accepted.some((item) => item.file.name === file.name && item.file.size === file.size)) {
        errors.push(`${file.name}: already in your queue.`)
      } else if (uploads.length + accepted.length >= MAX_ARCHIVES) {
        errors.push("You can scan up to 5 ZIP archives per batch.")
        break
      } else {
        accepted.push({ id: crypto.randomUUID(), file, status: "queued" })
      }
    }
    if (accepted.length) setQueue((previous) => [...previous.filter((item) => !item.sample), ...accepted])
    setError(errors.join(" "))
  }

  async function scan(items: QueuedSkill[] = queue) {
    if (busy.current || items.length === 0 || cooldowns[cooldownScope] > Date.now()) return
    const pending = items.filter((item) => item.status !== "complete")
    const resuming = pending.length > 0 && pending.length < items.length
    const toScan = resuming ? pending : items
    busy.current = true
    setIsScanning(true)
    setIsSample(items.every((item) => item.sample))
    if (!resuming) setReports([])
    setError("")
    setQueue(items.map((item) => resuming && item.status === "complete" ? item : { ...item, status: "queued", error: undefined }))
    const controller = new AbortController()
    abortController.current = controller
    try {
      for (const item of toScan) {
        if (controller.signal.aborted) break
        setQueue((previous) => previous.map((entry) => entry.id === item.id ? { ...entry, status: "scanning" } : entry))
        try {
          const report = await trigger({ file: item.file, aiReview, signal: controller.signal })
          if (controller.signal.aborted) break
          setReports((previous) => [...previous, report])
          setQueue((previous) => previous.map((entry) => entry.id === item.id ? { ...entry, status: "complete", skillName: report.skillName } : entry))
        } catch (cause) {
          if (controller.signal.aborted) break
          const message = cause instanceof Error ? cause.message : "This archive could not be scanned."
          setQueue((previous) => previous.map((entry) => entry.id === item.id ? { ...entry, status: "error", error: message } : entry))
          if (cause instanceof ScanRequestError && (cause.status === 429 || cause.status === 503)) {
            const time = Date.now()
            setNow(time)
            setCooldowns((previous) => ({ ...previous, [cause.scope]: Math.max(previous[cause.scope], time + cause.retryAfterSeconds * 1000) }))
            break
          }
        }
      }
    } finally {
      if (controller.signal.aborted) {
        setError("Scan cancelled. Completed reports are still available below.")
        setQueue((previous) => previous.map((entry) => entry.status === "scanning" ? { ...entry, status: "queued" } : entry))
      }
      abortController.current = null
      busy.current = false
      setIsScanning(false)
    }
  }

  async function trySample() {
    if (busy.current || loadingSample || cooldowns[cooldownScope] > Date.now()) return
    setError("")
    try {
      const file = await sampleTrigger()
      await scan([{ id: crypto.randomUUID(), file, sample: true, status: "queued" }])
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The sample could not be loaded.")
    }
  }

  function removeFile(id: string) {
    if (!busy.current) setQueue((previous) => previous.filter((entry) => entry.id !== id))
  }

  function clearFiles() {
    if (busy.current) return
    setQueue([])
    setReports([])
    setError("")
    setIsSample(false)
  }

  return {
    queue, reports, aiReview, setAiReview, isScanning, isSample, error, ready, loadingSample,
    retryAfterSeconds, cooldownScope,
    addFiles, scan, trySample, removeFile, clearFiles,
    cancel: () => abortController.current?.abort(),
  }
}
