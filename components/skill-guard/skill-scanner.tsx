"use client"

import Image from "next/image"
import { useRef, useState, type DragEvent } from "react"
import { ArrowRight, ArrowUpRight, Check, CircleAlert, CodeXml, FileArchive, Fingerprint, FolderUp, Info, KeyRound, LoaderCircle, LockKeyhole, ScanLine, ShieldCheck, Sparkles, Terminal, Upload, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Field, FieldContent, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Progress, ProgressLabel, ProgressValue } from "@/components/ui/progress"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { AI_REVIEW_RATE_LIMIT, RATE_LIMIT_WINDOW_SECONDS, SCAN_RATE_LIMIT, formatBytes } from "@/lib/skill-guard/types"
import { cn } from "@/lib/utils"
import { useSkillScan, type QueuedSkill } from "./use-skill-scan"
import { ScanResults } from "./scan-results"

const checks = [
  { icon: CodeXml, label: "Prompt injection" },
  { icon: KeyRound, label: "Credential theft" },
  { icon: ArrowUpRight, label: "Data exfiltration" },
  { icon: Terminal, label: "Unsafe scripts" },
  { icon: Fingerprint, label: "Hidden payloads" },
  { icon: ShieldCheck, label: "Risky permissions" },
]

function ProtectionPanel() {
  return (
    <aside className="guard-panel" aria-label="Scan coverage overview">
      <div className="flex flex-col gap-1">
        <div className="flex items-center justify-between">
          <span className="flex items-center gap-2 font-mono text-sm text-panel-foreground/75"><ShieldCheck className="size-4 text-gold" aria-hidden="true" /> THE TRUST LAYER</span>
          <span className="size-1.5 rounded-full bg-gold" aria-hidden="true" />
        </div>
        <Image src="/images/skill-guard-art.png" alt="A folder of skill files protected by a golden shield" width={1024} height={1024} className="guard-illustration" priority />
        <div className="flex flex-col gap-3">
          <h2 className="text-2xl leading-tight font-semibold tracking-tight">A small file.<br className="hidden md:block" /> A big responsibility.</h2>
          <p className="text-sm leading-relaxed text-panel-foreground/70">Skills inherit your agent&apos;s access. We help you spot what shouldn&apos;t come with it.</p>
        </div>
      </div>
      <div className="mt-6 border-t border-panel-foreground/15 pt-5">
        <div className="grid grid-cols-2 gap-x-3 gap-y-4">
          {checks.map(({ icon: Icon, label }) => (
            <div key={label} className="flex items-center gap-2 text-sm text-panel-foreground/85">
              <Icon className="size-4 shrink-0 text-gold" strokeWidth={1.6} aria-hidden="true" />
              <span>{label}</span>
            </div>
          ))}
        </div>
      </div>
      <a className="mt-6 inline-flex items-center gap-1.5 text-sm text-panel-foreground/70 transition-colors hover:text-panel-foreground" href="#threat-intelligence">Explore our detection coverage <ArrowRight className="size-4" aria-hidden="true" /></a>
    </aside>
  )
}

function QueueItem({ item, disabled, onRemove }: { item: QueuedSkill; disabled: boolean; onRemove: () => void }) {
  return (
    <li className="queue-item">
      <div className="flex items-center gap-3">
        <FileArchive className="size-5 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div className="flex min-w-0 flex-1 flex-col gap-0.5">
          <span className="truncate text-sm font-medium" title={item.skillName ?? item.file.name}>{item.skillName ?? item.file.name}</span>
          {item.skillName && <span className="truncate font-mono text-sm text-muted-foreground" title={item.file.name}>{item.file.name}</span>}
          <span className="text-sm text-muted-foreground">{formatBytes(item.file.size)} · {item.status === "queued" ? "Ready to scan" : item.status === "scanning" ? "Inspecting…" : item.status === "complete" ? "Report ready" : "Not scanned"}</span>
        </div>
        {item.status === "scanning" && <LoaderCircle className="size-4 animate-spin" aria-label="Scanning" />}
        {item.status === "complete" && <Check className="size-4" aria-label="Scan complete" />}
        {item.status === "error" && <CircleAlert className="size-4 text-destructive" aria-label="Scan error" />}
        <Button variant="ghost" size="icon-sm" disabled={disabled} onClick={onRemove} aria-label={`Remove ${item.file.name}`}><X /></Button>
      </div>
      {item.error && <p role="alert" className="mt-2 text-sm text-destructive">{item.error}</p>}
    </li>
  )
}

export function SkillScanner() {
  const scan = useSkillScan()
  const fileInput = useRef<HTMLInputElement>(null)
  const dragDepth = useRef(0)
  const [dragging, setDragging] = useState(false)
  const busy = scan.isScanning || scan.loadingSample
  const coolingDown = scan.retryAfterSeconds > 0
  const retryLabel = `${Math.floor(scan.retryAfterSeconds / 60)}:${String(scan.retryAfterSeconds % 60).padStart(2, "0")}`
  const pendingCount = scan.queue.filter((item) => item.status !== "complete").length || scan.queue.length
  const completed = scan.queue.filter((item) => item.status === "complete" || item.status === "error").length
  const activeStep = scan.isScanning ? 1 : scan.reports.length > 0 ? 2 : 0

  function onDrop(event: DragEvent<HTMLButtonElement>) {
    event.preventDefault()
    setDragging(false)
    dragDepth.current = 0
    if (!busy && scan.ready) scan.addFiles(Array.from(event.dataTransfer.files))
  }

  return (
    <TooltipProvider delay={200}>
      <section id="analyzer" className="content-shell reveal reveal-delayed" aria-label="Skill security analyzer" data-ready={scan.ready}>
        <div className="scanner-shell">
          <div className="scanner-topbar flex items-center justify-between">
            <ol aria-label="Scan steps" className="flex items-center gap-3">
              {["Upload", "Analyze", "Review"].map((label, index) => (
                <li key={label} className="flex items-center gap-3" aria-current={activeStep === index ? "step" : undefined}>
                  {index > 0 && <span className="step-line hidden sm:block" aria-hidden="true" />}
                  <span className="flex items-center gap-2">
                    <span className="step-dot" data-active={activeStep === index} data-complete={activeStep > index}>{activeStep > index ? <Check className="size-3.5" /> : index + 1}</span>
                    <span className={cn("text-sm", activeStep === index ? "font-semibold text-foreground" : "text-muted-foreground")}>{label}</span>
                  </span>
                </li>
              ))}
            </ol>
            <Badge variant="secondary" className="hidden sm:inline-flex">Free to use</Badge>
          </div>
          <div className="scanner-main">
            <div className="scanner-input">
              <div className="flex flex-col gap-5">
                <div className="flex flex-col gap-1.5">
                  <h2 className="text-xl font-semibold tracking-tight">Let&apos;s look inside.</h2>
                  <p className="text-sm text-muted-foreground">Upload your skills. Know what you&apos;re giving access to.</p>
                </div>
                <FieldGroup>
                  <Field>
                    <FieldLabel htmlFor="skill-upload" className="sr-only">Upload AI skill ZIP archives</FieldLabel>
                    <input
                      ref={fileInput}
                      id="skill-upload"
                      type="file"
                      multiple
                      accept=".zip,application/zip,application/x-zip-compressed"
                      className="sr-only"
                      tabIndex={-1}
                      disabled={busy || !scan.ready}
                      aria-describedby="upload-limits"
                      onChange={(event) => {
                        scan.addFiles(Array.from(event.target.files ?? []))
                        event.target.value = ""
                      }}
                    />
                    <Button
                      type="button"
                      variant="outline"
                      className="dropzone h-auto w-full whitespace-normal"
                      aria-label="Browse skill ZIP archives"
                      aria-controls="skill-upload"
                      aria-describedby="upload-limits"
                      disabled={busy || !scan.ready}
                      data-dragging={dragging}
                      data-busy={busy}
                      onClick={() => fileInput.current?.click()}
                      onDragOver={(event) => event.preventDefault()}
                      onDragEnter={(event) => { event.preventDefault(); dragDepth.current += 1; setDragging(true) }}
                      onDragLeave={(event) => { event.preventDefault(); dragDepth.current -= 1; if (dragDepth.current <= 0) setDragging(false) }}
                      onDrop={onDrop}
                    >
                      <span className="flex flex-col items-center gap-3 text-center">
                        <span className="flex size-12 items-center justify-center rounded-xl bg-secondary text-gold-foreground"><FolderUp strokeWidth={1.6} aria-hidden="true" /></span>
                        <span className="flex flex-col gap-1">
                          <span className="text-base font-semibold">{dragging ? "Drop them here. We’ll take a look." : "Drop your skill ZIPs here"}</span>
                          <span className="text-sm font-normal text-muted-foreground">or <span className="font-semibold text-foreground underline decoration-border underline-offset-4">browse files</span> to get started</span>
                        </span>
                        <span id="upload-limits" className="font-mono text-sm font-normal text-muted-foreground"><span className="whitespace-nowrap">.ZIP files</span> · <span className="whitespace-nowrap">Up to 5 skills</span> · <span className="whitespace-nowrap">4 MB each</span></span>
                      </span>
                    </Button>
                  </Field>
                  {scan.queue.length > 0 && (
                    <div className="flex flex-col gap-2">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium">{scan.queue.length} {scan.queue.length === 1 ? "skill" : "skills"} selected</span>
                        <Button variant="ghost" size="xs" disabled={busy} onClick={scan.clearFiles}>Clear all</Button>
                      </div>
                      <ul className="flex flex-col gap-2">{scan.queue.map((item) => <QueueItem key={item.id} item={item} disabled={busy} onRemove={() => scan.removeFile(item.id)} />)}</ul>
                    </div>
                  )}
                  <Field orientation="horizontal" data-disabled={busy}>
                    <Sparkles className="mt-0.5 size-4 shrink-0 text-gold-foreground" aria-hidden="true" />
                    <FieldContent>
                      <div className="flex items-center gap-2">
                        <FieldLabel htmlFor="ai-review">AI-assisted deep review</FieldLabel>
                        <Tooltip>
                          <TooltipTrigger aria-label="About AI-assisted review" className="text-muted-foreground"><Info className="size-3.5" /></TooltipTrigger>
                          <TooltipContent>Six contextual security lenses with source-backed notes. When enabled, redacted source text is sent to Anthropic via AI Gateway. Remove secrets first; provider retention policies apply. AI cannot remove static findings.</TooltipContent>
                        </Tooltip>
                      </div>
                      <span id="ai-disclosure" className="sr-only">Optional. Sends redacted source text to Anthropic via AI Gateway. Remove secrets first; provider retention policies apply.</span>
                    </FieldContent>
                    <Switch id="ai-review" checked={scan.aiReview} onCheckedChange={scan.setAiReview} disabled={busy || !scan.ready} aria-describedby="ai-disclosure" />
                  </Field>
                </FieldGroup>
                {scan.error && <Alert variant="destructive"><CircleAlert /><AlertTitle>One quick check</AlertTitle><AlertDescription>{scan.error}</AlertDescription></Alert>}
                {coolingDown && (
                  <Alert id="scan-cooldown" role="status">
                    <Info />
                    <AlertTitle>{scan.cooldownScope === "ai" ? "AI review paused" : "Scans paused"}</AlertTitle>
                    <AlertDescription>
                      <p>Try again in <span aria-live="off" className="font-mono tabular-nums">{retryLabel}</span>. Your unscanned files stay in the queue.</p>
                      {scan.cooldownScope === "ai" && <p>Turn off AI-assisted review to continue with static analysis.</p>}
                    </AlertDescription>
                  </Alert>
                )}
                <div className="flex flex-col gap-3">
                  {scan.isScanning ? (
                    <div className="flex flex-col gap-3" role="status" aria-live="polite">
                      <Progress value={scan.queue.length ? completed / scan.queue.length * 100 : 0}>
                        <ProgressLabel>{scan.aiReview ? "Inspecting files & reviewing instructions…" : "Inspecting your skill files…"}</ProgressLabel>
                        <ProgressValue>{() => `${completed}/${scan.queue.length}`}</ProgressValue>
                      </Progress>
                      <Button variant="outline" size="lg" onClick={scan.cancel}><LoaderCircle className="animate-spin" data-icon="inline-start" />Cancel scan</Button>
                    </div>
                  ) : (
                    <Button size="lg" className="w-full" disabled={busy || !scan.ready || coolingDown} aria-describedby={coolingDown ? "scan-cooldown" : undefined} onClick={() => scan.queue.length ? scan.scan() : fileInput.current?.click()}>
                      <ScanLine data-icon="inline-start" />{coolingDown ? `Retry in ${retryLabel}` : scan.queue.length ? `Analyze ${pendingCount > 1 ? `${pendingCount} skills` : "skill"}` : "Choose skills to analyze"}<ArrowRight data-icon="inline-end" />
                    </Button>
                  )}
                  <div className="flex items-center justify-center gap-1 text-sm">
                    <span className="text-muted-foreground">Just exploring?</span>
                    <Button variant="link" size="xs" disabled={busy || !scan.ready || coolingDown} onClick={scan.trySample}>
                      {scan.loadingSample ? <LoaderCircle className="animate-spin" data-icon="inline-start" /> : null}
                      Try a sample scan <ArrowUpRight data-icon="inline-end" />
                    </Button>
                  </div>
                  <p className="text-center text-sm text-muted-foreground">Per network: {SCAN_RATE_LIMIT} scans, including up to {AI_REVIEW_RATE_LIMIT} AI reviews, per {RATE_LIMIT_WINDOW_SECONDS / 60} minutes.</p>
                </div>
              </div>
            </div>
            <ProtectionPanel />
          </div>
          <div className="privacy-strip">
            <div className="flex flex-wrap items-center justify-center gap-x-7 gap-y-2 text-sm text-muted-foreground">
              <span className="flex items-center gap-2"><ShieldCheck className="size-4" aria-hidden="true" />Your code is never executed</span>
              <span className="flex items-center gap-2"><LockKeyhole className="size-4" aria-hidden="true" />Uploads aren&apos;t saved</span>
              <span className="flex items-center gap-2"><Upload className="size-4" aria-hidden="true" />No account needed</span>
            </div>
          </div>
        </div>
        {scan.reports.length > 0 && <ScanResults reports={scan.reports} isSample={scan.isSample} scanning={scan.isScanning} />}
      </section>
    </TooltipProvider>
  )
}
