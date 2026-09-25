"use client"

import { useEffect, useRef, useState } from "react"
import useSWRMutation from "swr/mutation"
import { MAX_ARCHIVES, MAX_ZIP_BYTES, type ScanReport } from "@/lib/skill-guard/types"

export interface QueuedSkill {
  id: string
  file: File
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
    throw new Error(error?.error ?? (response.status === 413 ? "This archive exceeds the upload limit." : "The scan could not finish. Please try again."))
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
  const abortController = useRef<AbortController | null>(null)
  const busy = useRef(false)
  const { trigger } = useSWRMutation("/api/analyze", analyzeArchive)
  const { trigger: sampleTrigger, isMutating: loadingSample } = useSWRMutation("/api/sample", loadSample)

  useEffect(() => {
    setReady(true)
    return () => abortController.current?.abort()
  }, [])

  useEffect(() => {
    if (!isScanning && reports.length > 0) {
      document.getElementById("scan-report")?.scrollIntoView({
        behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "instant" : "smooth",
        block: "start",
      })
    }
  }, [isScanning, reports.length])

  function addFiles(files: File[]) {
    if (busy.current) return
    const errors: string[] = []
    const accepted: QueuedSkill[] = []
    for (const file of files) {
      if (!file.name.toLowerCase().endsWith(".zip")) {
        errors.push(`${file.name}: please choose a .zip archive.`)
      } else if (file.size > MAX_ZIP_BYTES) {
        errors.push(`${file.name}: the maximum size is 4 MB.`)
      } else if (!file.size) {
        errors.push(`${file.name}: this file is empty.`)
      } else if (file.name.length > 160) {
        errors.push("Please shorten filenames to 160 characters or fewer.")
      } else if (queue.some((item) => item.file.name === file.name && item.file.size === file.size && item.file.lastModified === file.lastModified) || accepted.some((item) => item.file.name === file.name && item.file.size === file.size)) {
        errors.push(`${file.name}: already in your queue.`)
      } else if (queue.length + accepted.length >= MAX_ARCHIVES) {
        errors.push("You can scan up to 5 ZIP archives per batch.")
        break
      } else {
        accepted.push({ id: crypto.randomUUID(), file, status: "queued" })
      }
    }
    setQueue((previous) => [...previous, ...accepted])
    setError(errors.join(" "))
  }

  async function scan(items: QueuedSkill[] = queue, sample = false) {
    if (busy.current || items.length === 0) return
    busy.current = true
    setIsScanning(true)
    setIsSample(sample)
    setReports([])
    setError("")
    setQueue(items.map((item) => ({ ...item, status: "queued", error: undefined })))
    const controller = new AbortController()
    abortController.current = controller
    try {
      for (const item of items) {
        if (controller.signal.aborted) break
        setQueue((previous) => previous.map((entry) => entry.id === item.id ? { ...entry, status: "scanning" } : entry))
        try {
          const report = await trigger({ file: item.file, aiReview, signal: controller.signal })
          if (controller.signal.aborted) break
          setReports((previous) => [...previous, report])
          setQueue((previous) => previous.map((entry) => entry.id === item.id ? { ...entry, status: "complete" } : entry))
        } catch (cause) {
          if (controller.signal.aborted) break
          const message = cause instanceof Error ? cause.message : "This archive could not be scanned."
          setQueue((previous) => previous.map((entry) => entry.id === item.id ? { ...entry, status: "error", error: message } : entry))
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
    if (busy.current || loadingSample) return
    setError("")
    try {
      const file = await sampleTrigger()
      await scan([{ id: crypto.randomUUID(), file, status: "queued" }], true)
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
    addFiles, scan, trySample, removeFile, clearFiles,
    cancel: () => abortController.current?.abort(),
  }
}
