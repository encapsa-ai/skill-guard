"use client"

import { CircleAlert, FileSearch, Fingerprint, Info, KeyRound, Layers, ShieldCheck, Sparkles, Terminal } from "lucide-react"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Progress, ProgressLabel, ProgressValue } from "@/components/ui/progress"
import { AI_REVIEW_METHODS, type ScanReport } from "@/lib/skill-guard/types"

const methodIcons = [FileSearch, KeyRound, Terminal, ShieldCheck, Layers, Fingerprint]
const number = (value: number) => value.toLocaleString("en-US")
const percent = (reviewed: number, total: number) => total ? Math.floor(reviewed / total * 100) : 0

export function AIReviewSummary({ report }: { report: ScanReport }) {
  const review = report.aiReview
  const coverage = review.coverage
  const supportedMethods = review.methods?.filter((method) => method.notes.length > 0).length ?? 0
  const added = report.findings.filter((finding) => finding.source === "ai").length
  const unavailable = review.status === "unavailable"

  return (
    <section className="ai-review-summary" aria-label="AI deep review overview">
      <div className="flex flex-col gap-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <span className="inline-flex items-center gap-2 font-mono text-sm"><Sparkles className="size-4 text-gold" aria-hidden="true" />AI DEEP REVIEW</span>
          <Badge variant="secondary">{unavailable ? "Not completed" : review.status === "partial" ? "Partial review" : "Review completed"}</Badge>
        </div>
        <div className="flex flex-col gap-2">
          <h4 className="text-2xl font-semibold tracking-tight text-balance">{unavailable ? "Static results are ready. AI review is not." : "Beyond the pattern match."}</h4>
          <p className="max-w-3xl text-sm leading-relaxed text-panel-foreground/80">{unavailable ? review.message : "A contextual second look at instructions, code, and trust boundaries. Every note below is linked to source evidence—not just a model verdict."}</p>
        </div>
        {!unavailable && (
          <dl className="ai-review-metrics">
            <div className="flex flex-col gap-1"><dt className="text-sm text-panel-foreground/75">Lenses with evidence</dt><dd className="text-3xl font-semibold tracking-tight tabular-nums">{supportedMethods}<span className="text-lg font-normal text-panel-foreground/65"> / {AI_REVIEW_METHODS.length}</span></dd><dd className="text-sm text-panel-foreground/75">Source-backed assessments</dd></div>
            <div className="flex flex-col gap-1"><dt className="text-sm text-panel-foreground/75">AI text coverage</dt><dd className="text-3xl font-semibold tracking-tight tabular-nums">{coverage ? `${percent(coverage.reviewedCharacters, coverage.totalCharacters)}%` : `${review.reviewedFiles}/${review.totalTextFiles}`}</dd><dd className="text-sm text-panel-foreground/75">{coverage?.fullyReviewedFiles ?? review.reviewedFiles} of {review.totalTextFiles} text files fully reviewed</dd></div>
            <div className="flex flex-col gap-1"><dt className="text-sm text-panel-foreground/75">Additional AI findings</dt><dd className="text-3xl font-semibold tracking-tight tabular-nums">{added}</dd><dd className="text-sm text-panel-foreground/75">{added ? "Evidence matched to source" : "No additional grounded findings"}</dd></div>
          </dl>
        )}
        <p className="text-sm text-panel-foreground/75">Static findings remain unchanged. Evidence matching verifies citations, not the model&apos;s interpretation or the skill&apos;s safety.</p>
      </div>
    </section>
  )
}

export function AIReviewDetails({ report, onViewFindings }: { report: ScanReport; onViewFindings: () => void }) {
  const review = report.aiReview
  const coverage = review.coverage
  const validation = review.validation
  const recommendations = report.findings.slice(0, 3)

  return (
    <div className="flex min-w-0 flex-col gap-6">
      {review.status === "partial" && <Alert><CircleAlert /><AlertTitle>The deep review has limits</AlertTitle><AlertDescription>{review.message}</AlertDescription></Alert>}
      {review.status === "unavailable" ? <Alert><Info /><AlertTitle>No AI conclusions were issued</AlertTitle><AlertDescription>The findings tab still contains the completed static inspection. Retry with AI review enabled when the provider is available.</AlertDescription></Alert> : (
        <section className="flex flex-col gap-4" aria-labelledby={`ai-lenses-${report.id}`}>
          <div className="flex flex-col gap-1"><h4 id={`ai-lenses-${report.id}`} className="text-lg font-semibold">How the AI reviewed this skill</h4><p className="text-sm leading-relaxed text-muted-foreground">Six focused lenses within the model review, not six independent scanners. Indicator counts include static and AI findings. Open a lens to see its assessment and matched source excerpts.</p></div>
          <Accordion multiple className="ai-methods">
            {AI_REVIEW_METHODS.map((definition, index) => {
              const method = review.methods?.find((item) => item.id === definition.id)
              const Icon = methodIcons[index]
              return (
                <AccordionItem value={definition.id} key={definition.id} className="ai-method-item">
                  <AccordionTrigger className="py-4">
                    <span className="flex min-w-0 flex-col gap-2">
                      <span className="flex items-center gap-2"><Icon className="size-4 shrink-0 text-gold-foreground" aria-hidden="true" /><span className="font-semibold">{definition.title}</span></span>
                      <span className="flex flex-wrap items-center gap-2"><Badge variant={method?.status === "reviewed" ? "outline" : "secondary"}>{method?.status === "reviewed" ? "Evidence-backed" : method?.notes.length ? "Limited context" : "No supported assessment"}</Badge>{Boolean(method?.findingCount) && <span className="text-sm text-muted-foreground">{method!.findingCount} related {method!.findingCount === 1 ? "indicator" : "indicators"}</span>}</span>
                      <span className="text-sm leading-relaxed font-normal text-muted-foreground">{method?.notes[0]?.summary ?? definition.description}</span>
                    </span>
                  </AccordionTrigger>
                  <AccordionContent>
                    <div className="flex min-w-0 flex-col gap-4 pb-2">
                      <p className="text-sm leading-relaxed text-muted-foreground">{definition.description}</p>
                      {method?.notes.length ? method.notes.map((note, noteIndex) => (
                        <div key={`${note.batch}-${noteIndex}`} className="flex min-w-0 flex-col gap-3">
                          {noteIndex > 0 && <p className="text-sm leading-relaxed">{note.summary}</p>}
                          {note.citations.map((citation, citationIndex) => <div key={citationIndex} className="flex min-w-0 flex-col gap-1"><p className="break-all font-mono text-sm text-muted-foreground">{citation.file}:{citation.line}</p><pre className="evidence-block font-mono"><code>{citation.evidence}</code></pre></div>)}
                          {(coverage?.completedBatches ?? 0) > 1 && <p className="text-sm text-muted-foreground">From analysis batch {note.batch}; conclusions are limited to its supplied file sections.</p>}
                        </div>
                      )) : <p className="text-sm leading-relaxed">The model did not return a usable, source-backed assessment for this lens. This is not a passed check or a safety verdict.</p>}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              )
            })}
          </Accordion>
        </section>
      )}
      {coverage && (
        <section className="flex min-w-0 flex-col gap-4" aria-labelledby={`ai-coverage-${report.id}`}>
          <div className="flex flex-col gap-1"><h4 id={`ai-coverage-${report.id}`} className="text-lg font-semibold">Exactly what was reviewed</h4><p className="text-sm leading-relaxed text-muted-foreground">{coverage.completedBatches} of {coverage.plannedBatches} planned batches returned usable responses. Coverage measures redacted source characters, not a confidence score. Binary files are excluded.</p></div>
          <Progress value={percent(coverage.reviewedCharacters, coverage.totalCharacters)}><ProgressLabel>AI source coverage</ProgressLabel><ProgressValue>{() => `${number(coverage.reviewedCharacters)} / ${number(coverage.totalCharacters)} characters`}</ProgressValue></Progress>
          <Accordion multiple>
            <AccordionItem value="source-coverage"><AccordionTrigger>File-by-file AI coverage ({coverage.files.length})</AccordionTrigger><AccordionContent><ul className="max-h-96 overflow-y-auto rounded-xl border">
              {coverage.files.map((file) => <li key={file.file} className="inventory-row"><div className="flex min-w-0 flex-col gap-2"><div className="flex flex-wrap items-center justify-between gap-2"><span className="break-all font-mono text-sm">{file.file}</span><Badge variant={file.status === "complete" ? "outline" : "secondary"}>{file.status === "complete" ? "Fully reviewed" : file.status === "partial" ? "Partly reviewed" : "Not reviewed"}</Badge></div><p className="text-sm text-muted-foreground">{number(file.reviewedCharacters)} / {number(file.totalCharacters)} characters{file.reviewedRanges.length ? ` · Source lines ${file.reviewedRanges.map((range) => range.startLine === range.endLine ? range.startLine : `${range.startLine}–${range.endLine}`).join(", ")}` : ""}</p>{file.status === "partial" && <p className="text-sm text-muted-foreground">Only supplied sections were reviewed; long source lines may also be split.</p>}</div></li>)}
            </ul></AccordionContent></AccordionItem>
            <AccordionItem value="review-validation"><AccordionTrigger>Evidence validation & review details</AccordionTrigger><AccordionContent><div className="flex flex-col gap-3 text-sm leading-relaxed text-muted-foreground">
              <p>{review.message}</p>
              {validation && <dl className="grid grid-cols-2 gap-x-4 gap-y-2"><dt>Additional findings accepted</dt><dd>{validation.acceptedObservations}</dd><dt>Unsupported observations withheld</dt><dd>{validation.discardedObservations}</dd><dt>Unsupported assessments withheld</dt><dd>{validation.discardedAssessments}</dd><dt>Exact-quote line corrections</dt><dd>{validation.relocatedCitations}</dd></dl>}
              <p>Incorrect line numbers are corrected only when a verbatim quote identifies one unique source line in the supplied sections. Unsupported claims are excluded, never promoted to findings.</p>
              <p className="break-all font-mono">Model: {review.model ?? "Not used"} · {review.attempts ?? 0} provider attempts</p>
              <p>Review is bounded to four source batches and a shared time limit. The manifest excerpt accompanies later batches when available; cross-file analysis cannot establish behavior in unseen code or at runtime.</p>
            </div></AccordionContent></AccordionItem>
          </Accordion>
        </section>
      )}
      <section className="rounded-xl bg-muted p-5 text-foreground" aria-labelledby={`ai-next-${report.id}`}>
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3"><h4 id={`ai-next-${report.id}`} className="text-base font-semibold">Before you install</h4><Button variant="outline" size="sm" onClick={onViewFindings}>Review all findings</Button></div>
          {recommendations.length ? <ul className="flex flex-col gap-3">{recommendations.map((finding) => <li key={finding.id} className="flex flex-col gap-1"><span className="text-sm font-semibold">{finding.title}</span><p className="text-sm leading-relaxed text-muted-foreground">{finding.recommendation}</p></li>)}</ul> : <p className="text-sm leading-relaxed text-muted-foreground">Verify the publisher, permissions, and external dependencies. Inspect any unreviewed content separately. No additional AI findings does not mean the skill is safe.</p>}
        </div>
      </section>
    </div>
  )
}
