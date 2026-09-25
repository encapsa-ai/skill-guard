"use client"

import Image from "next/image"
import { useRef, useState, type DragEvent } from "react"
import { ArrowRight, ArrowUpRight, Check, CircleAlert, CodeXml, FileArchive, Fingerprint, FolderUp, Info, KeyRound, LoaderCircle, LockKeyhole, ScanLine, ShieldCheck, Sparkles, Terminal, Upload, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Field, FieldContent, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Progress, ProgressLabel, ProgressValue } from "@/components/ui/progress"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { formatBytes } from "@/lib/skill-guard/types"
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
          <span className="truncate text-sm font-medium" title={item.file.name}>{item.file.name}</span>
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
  const completed = scan.queue.filter((item) => item.status === "complete" || item.status === "error").length
  const activeStep = scan.isScanning ? 1 : scan.reports.length > 0 ? 2 : 0

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault()
    setDragging(false)
    dragDepth.current = 0
    scan.addFiles(Array.from(event.dataTransfer.files))
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
                    <div
                      className="dropzone"
                      data-dragging={dragging}
                      data-busy={busy}
                      onDragOver={(event) => event.preventDefault()}
                      onDragEnter={(event) => { event.preventDefault(); dragDepth.current += 1; setDragging(true) }}
                      onDragLeave={(event) => { event.preventDefault(); dragDepth.current -= 1; if (dragDepth.current <= 0) setDragging(false) }}
                      onDrop={onDrop}
                    >
                      <div className="flex flex-col items-center gap-3 text-center">
                        <span className="flex size-12 items-center justify-center rounded-xl bg-secondary text-gold-foreground"><FolderUp className="size-6" strokeWidth={1.6} aria-hidden="true" /></span>
                        <div className="flex flex-col gap-1">
                          <p className="text-base font-semibold">{dragging ? "Drop them here. We’ll take a look." : "Drop your skill ZIPs here"}</p>
                          <p className="text-sm text-muted-foreground">or <button type="button" className="font-semibold text-foreground underline decoration-border underline-offset-4 hover:decoration-gold" disabled={busy || !scan.ready} onClick={() => fileInput.current?.click()}>browse files</button> to get started</p>
                        </div>
                        <p id="upload-limits" className="font-mono text-sm text-muted-foreground">.ZIP files · Up to 5 skills · 4 MB each</p>
                      </div>
                    </div>
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
                          <TooltipContent>Optional contextual review of supported text. Static findings cannot be removed by the AI. Provider retention policies apply.</TooltipContent>
                        </Tooltip>
                      </div>
                      <FieldDescription id="ai-disclosure">{scan.aiReview ? "Enabled: redacted source text goes to Anthropic via AI Gateway. Remove secrets first; provider retention policies apply." : "Add a second perspective. Off by default for privacy."}</FieldDescription>
                    </FieldContent>
                    <Switch id="ai-review" checked={scan.aiReview} onCheckedChange={scan.setAiReview} disabled={busy || !scan.ready} aria-describedby="ai-disclosure" />
                  </Field>
                </FieldGroup>
                {scan.error && <Alert variant="destructive"><CircleAlert /><AlertTitle>One quick check</AlertTitle><AlertDescription>{scan.error}</AlertDescription></Alert>}
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
                    <Button size="lg" className="w-full" disabled={busy || !scan.ready} onClick={() => scan.queue.length ? scan.scan() : fileInput.current?.click()}>
                      <ScanLine data-icon="inline-start" />{scan.queue.length ? `Analyze ${scan.queue.length > 1 ? `${scan.queue.length} skills` : "skill"}` : "Choose skills to analyze"}<ArrowRight data-icon="inline-end" />
                    </Button>
                  )}
                  <div className="flex items-center justify-center gap-1 text-sm">
                    <span className="text-muted-foreground">Just exploring?</span>
                    <Button variant="link" size="xs" disabled={busy || !scan.ready} onClick={scan.trySample}>
                      {scan.loadingSample ? <LoaderCircle className="animate-spin" data-icon="inline-start" /> : null}
                      Try a sample scan <ArrowUpRight data-icon="inline-end" />
                    </Button>
                  </div>
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
