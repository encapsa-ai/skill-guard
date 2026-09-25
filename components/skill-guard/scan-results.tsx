"use client"

import { useState } from "react"
import { ArrowUpRight, Check, CircleAlert, CodeXml, Download, FileCode2, FileSearch, Info, Layers, ShieldAlert, ShieldCheck, Sparkles } from "lucide-react"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Field, FieldLabel } from "@/components/ui/field"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { CATEGORIES, SEVERITY_ORDER, formatBytes, riskLabel, type Finding, type ScanReport, type Severity } from "@/lib/skill-guard/types"
import { RESEARCH_SOURCES } from "@/lib/skill-guard/research"
import { downloadReports } from "@/lib/skill-guard/export-report"

function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge variant={severity === "critical" || severity === "high" ? "destructive" : severity === "medium" ? "secondary" : "outline"}>{severity.charAt(0).toUpperCase() + severity.slice(1)}</Badge>
}

function FindingItem({ finding }: { finding: Finding }) {
  return (
    <AccordionItem value={finding.id}>
      <AccordionTrigger className="py-5">
        <span className="flex min-w-0 flex-col gap-2">
          <span className="flex flex-wrap items-center gap-2"><SeverityBadge severity={finding.severity} /><span className="font-semibold">{finding.title}</span>{finding.source === "ai" && <Badge variant="outline"><Sparkles data-icon="inline-start" />AI advisory</Badge>}</span>
          <span className="break-all font-mono text-sm text-muted-foreground">{finding.file}{finding.line ? `:${finding.line}` : " · file metadata"}</span>
        </span>
      </AccordionTrigger>
      <AccordionContent>
        <div className="flex flex-col gap-4 pb-4">
          <p className="text-sm leading-relaxed text-muted-foreground">{finding.description}</p>
          <pre className="evidence-block font-mono"><code>{finding.evidence}</code></pre>
          <div className="flex items-start gap-3"><ShieldCheck className="mt-0.5 size-4 shrink-0" aria-hidden="true" /><p className="text-sm leading-relaxed"><strong className="font-semibold">What to do. </strong>{finding.recommendation}</p></div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-muted-foreground">
            <span>{CATEGORIES[finding.category]}</span><span>{finding.confidence === "high" ? "High" : "Moderate"} confidence</span><span className="font-mono">{finding.ruleId}</span>
            {RESEARCH_SOURCES.filter((source) => finding.referenceIds.includes(source.id)).map((source) => <a key={source.id} href={source.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 hover:text-foreground">{source.publisher}<ArrowUpRight className="size-3.5" /></a>)}
          </div>
        </div>
      </AccordionContent>
    </AccordionItem>
  )
}

function ReportDetails({ report }: { report: ScanReport }) {
  const [severity, setSeverity] = useState("all")
  const findings = report.findings.filter((finding) => severity === "all" || finding.severity === severity)
  return (
    <div className="flex flex-col gap-6">
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="report-metric"><div className="flex flex-col gap-2"><span className="text-sm text-muted-foreground">Highest detected risk</span><span className="text-xl font-semibold tracking-tight">{riskLabel(report.riskLevel)}</span><span className="text-sm text-muted-foreground">{report.riskLevel === "none" ? "Not a guarantee of safety" : "Review before installing"}</span></div></div>
        <div className="report-metric"><div className="flex flex-col gap-2"><span className="text-sm text-muted-foreground">Content inspected</span><span className="text-xl font-semibold tracking-tight">{report.coverage.inspectedFiles} <span className="font-normal text-muted-foreground">/ {report.coverage.totalFiles} files</span></span><span className="text-sm text-muted-foreground">{report.coverage.uninspectedFiles ? `${report.coverage.uninspectedFiles} need separate review` : `${formatBytes(report.coverage.expandedBytes)} expanded`}</span></div></div>
        <div className="report-metric"><div className="flex flex-col gap-2"><span className="text-sm text-muted-foreground">Flagged indicators</span><span className="text-xl font-semibold tracking-tight">{report.findings.length} <span className="font-normal text-muted-foreground">findings</span></span><span className="text-sm text-muted-foreground">{report.rulesChecked} static checks + archive checks</span></div></div>
      </div>
      <p className="text-sm leading-relaxed text-muted-foreground">{report.summary}</p>
      {!report.coverage.complete && <Alert><CircleAlert /><AlertTitle>Some content could not be inspected</AlertTitle><AlertDescription>Opaque files, nested archives, or missing skill metadata limit coverage. See the file inventory and scope before making a trust decision.</AlertDescription></Alert>}
      {report.aiReview.status === "unavailable" && <Alert><Info /><AlertTitle>AI review unavailable; static analysis completed</AlertTitle><AlertDescription>{report.aiReview.message}</AlertDescription></Alert>}
      <Tabs defaultValue="findings" className="gap-5">
        <TabsList variant="line" className="max-w-full flex-wrap justify-start gap-3">
          <TabsTrigger value="findings"><ShieldAlert data-icon="inline-start" />Findings ({report.findings.length})</TabsTrigger>
          <TabsTrigger value="files"><Layers data-icon="inline-start" />File inventory</TabsTrigger>
          <TabsTrigger value="scope"><FileSearch data-icon="inline-start" />Coverage & scope</TabsTrigger>
        </TabsList>
        <TabsContent value="findings">
          <div className="flex flex-col gap-3">
            <Field orientation="horizontal" className="w-auto self-end">
              <FieldLabel htmlFor={`severity-${report.id}`} className="sr-only">Filter findings by severity</FieldLabel>
              <select id={`severity-${report.id}`} value={severity} onChange={(event) => setSeverity(event.target.value)} className="h-9 rounded-lg border bg-card px-3 text-sm text-card-foreground">
                <option value="all">All severities</option>
                {SEVERITY_ORDER.map((level) => <option key={level} value={level}>{level.charAt(0).toUpperCase() + level.slice(1)} ({report.findings.filter((finding) => finding.severity === level).length})</option>)}
              </select>
            </Field>
            {findings.length ? <Accordion multiple defaultValue={[findings[0].id]}>{findings.map((finding) => <FindingItem key={finding.id} finding={finding} />)}</Accordion> : <Alert><ShieldCheck /><AlertTitle>{report.findings.length ? "No findings at this severity" : "No configured indicators detected"}</AlertTitle><AlertDescription>{report.findings.length ? "Choose another severity to see the other findings." : "This does not certify the skill as safe. Review its purpose, permissions, dependencies, and any uninspected files."}</AlertDescription></Alert>}
          </div>
        </TabsContent>
        <TabsContent value="files">
          <div className="overflow-hidden rounded-xl border">
            {report.files.map((file) => (
              <div key={file.path} className="inventory-row">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex min-w-0 items-start gap-3"><FileCode2 className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" /><div className="flex min-w-0 flex-col gap-1"><span className="break-all font-mono text-sm">{file.path}</span><span className="text-sm text-muted-foreground">{formatBytes(file.bytes)} · {file.kind} · {file.findings} {file.findings === 1 ? "finding" : "findings"}</span></div></div>
                  <Badge variant={file.status === "inspected" ? "outline" : "secondary"}>{file.status === "inspected" ? <><Check data-icon="inline-start" />Inspected</> : "Not inspected"}</Badge>
                </div>
              </div>
            ))}
          </div>
        </TabsContent>
        <TabsContent value="scope">
          <div className="flex flex-col gap-5">
            <Alert><Sparkles /><AlertTitle>AI review: {report.aiReview.status.replaceAll("-", " ")}</AlertTitle><AlertDescription>{report.aiReview.message}{report.aiReview.model ? ` Model: ${report.aiReview.model}.` : ""}</AlertDescription></Alert>
            <ul className="flex list-disc flex-col gap-2 pl-5 text-sm leading-relaxed text-muted-foreground">{report.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul>
            <div className="flex flex-col gap-2 rounded-xl bg-muted p-4 text-sm text-muted-foreground"><p>Ruleset {report.rulesetVersion} · {report.coverage.manifestCount} SKILL.md {report.coverage.manifestCount === 1 ? "manifest" : "manifests"}</p><p>Scanned {new Date(report.scannedAt).toLocaleString()} · {(report.durationMs / 1000).toFixed(1)} seconds</p><p className="break-all font-mono">SHA-256: {report.archiveSha256}</p></div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}

export function ScanResults({ reports, isSample, scanning }: { reports: ScanReport[]; isSample: boolean; scanning: boolean }) {
  return (
    <section id="scan-report" className="report-shell" aria-labelledby="report-title">
      <div className="flex flex-col gap-6">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
          <div className="flex flex-col gap-2"><div className="flex items-center gap-2"><ShieldCheck className="size-5 text-gold-foreground" aria-hidden="true" /><h2 id="report-title" className="text-2xl font-semibold tracking-tight">Your security report</h2></div><p className="text-sm text-muted-foreground" role="status">{scanning ? "Reports appear as each archive finishes." : `${reports.length} ${reports.length === 1 ? "archive" : "archives"} analyzed. Here’s what we found.`}</p></div>
          <div className="flex items-center gap-2"><Button variant="outline" size="sm" onClick={() => downloadReports(reports, "json", isSample)} aria-label="Download JSON report"><CodeXml data-icon="inline-start" />JSON</Button><Button size="sm" onClick={() => downloadReports(reports, "html", isSample)}><Download data-icon="inline-start" />Download report</Button></div>
        </div>
        {isSample && <Alert><Info /><AlertTitle>Sample scan · real engine, synthetic indicators</AlertTitle><AlertDescription>This demonstration uses inert test files and reserved example domains, not real malware. Your own uploads are scanned by the same analysis engine.</AlertDescription></Alert>}
        {reports.length === 1 ? <ReportDetails key={reports[0].id} report={reports[0]} /> : <Tabs defaultValue={reports[0].id} className="gap-5"><TabsList className="max-w-full flex-wrap justify-start">{reports.map((report) => <TabsTrigger key={report.id} value={report.id} className="max-w-52 truncate">{report.archiveName}</TabsTrigger>)}</TabsList>{reports.map((report) => <TabsContent key={report.id} value={report.id}><ReportDetails report={report} /></TabsContent>)}</Tabs>}
        <div className="border-t pt-4 text-sm text-muted-foreground">Indicators are not proof of malicious intent. No findings is not proof of safety. Always review context before installing.</div>
      </div>
    </section>
  )
}
