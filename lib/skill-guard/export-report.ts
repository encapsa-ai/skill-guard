import { AI_REVIEW_METHODS, CATEGORIES, formatBytes, riskLabel, type ScanReport } from "./types"
import { RESEARCH_SOURCES } from "./research"

export function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]!)
}

function buildHtmlAIReview(report: ScanReport) {
  const review = report.aiReview
  if (review.status === "not-requested") return ""
  const e = escapeHtml
  const coverage = review.coverage
  const validation = review.validation
  return `
    <h3>AI-assisted deep review</h3>
    <p>${e(review.message)}</p>
    <p>Six analytical lenses within the model review, not six independent scanners. Citations are matched to source text; this does not verify the model's interpretation or certify safety. Static findings remain unchanged.</p>
    <dl><dt>Lenses with evidence</dt><dd>${review.methods?.filter((method) => method.notes.length > 0).length ?? 0} / ${AI_REVIEW_METHODS.length}</dd><dt>Additional AI findings</dt><dd>${report.findings.filter((finding) => finding.source === "ai").length}</dd>${coverage ? `<dt>AI source coverage</dt><dd>${coverage.reviewedCharacters} / ${coverage.totalCharacters} redacted source characters; ${coverage.fullyReviewedFiles} / ${review.totalTextFiles} text files fully reviewed</dd><dt>Analysis batches</dt><dd>${coverage.completedBatches} / ${coverage.plannedBatches} returned usable responses</dd>` : ""}</dl>
    ${AI_REVIEW_METHODS.map((definition) => {
      const method = review.methods?.find((item) => item.id === definition.id)
      return `<article><h4>${e(definition.title)} · ${method?.status === "reviewed" ? "Evidence-backed" : method?.notes.length ? "Limited context" : "No supported assessment"}</h4><p>${e(definition.description)}</p>${method?.findingCount ? `<p>${method.findingCount} related static or AI indicators</p>` : ""}${method?.notes.length ? method.notes.map((note) => `<p>${e(note.summary)}</p>${note.citations.map((citation) => `<p class="hash">${e(citation.file)}:${citation.line}</p><pre>${e(citation.evidence)}</pre>`).join("")}<p>Analysis batch ${note.batch}; limited to its supplied source sections.</p>`).join("") : "<p>No usable, source-backed assessment was returned for this lens. This is not a passed check.</p>"}</article>`
    }).join("")}
    ${coverage ? `<h4>File-by-file AI coverage</h4><p>Binary files are excluded. Large files are split into sections within a four-batch input budget and shared time limit. Partial source lines may be included; character coverage is authoritative.</p><table><thead><tr><th>File</th><th>AI coverage</th><th>Characters reviewed / total</th><th>Source lines</th></tr></thead><tbody>${coverage.files.map((file) => `<tr><td>${e(file.file)}</td><td>${e(file.status)}</td><td>${file.reviewedCharacters} / ${file.totalCharacters}</td><td>${file.reviewedRanges.map((range) => `${range.startLine}–${range.endLine}`).join(", ") || "None"}</td></tr>`).join("")}</tbody></table>` : ""}
    ${validation ? `<h4>Evidence validation</h4><dl><dt>Accepted findings</dt><dd>${validation.acceptedObservations}</dd><dt>Withheld observations</dt><dd>${validation.discardedObservations}</dd><dt>Withheld assessments</dt><dd>${validation.discardedAssessments}</dd><dt>Exact-quote line corrections</dt><dd>${validation.relocatedCitations}</dd></dl><p>Incorrect line numbers are corrected only when a verbatim quote identifies one unique source line in the supplied sections. Unsupported claims are excluded.</p>` : ""}
  `
}

export function buildHtmlReport(reports: ScanReport[], sample = false) {
  const e = escapeHtml
  const sections = reports.map((report) => `
    <section>
      <h2>${e(report.skillName)}</h2>
      <p class="hash">Archive: ${e(report.archiveName)}</p>${report.skillNameSource === "filename" ? "<p>No skill name was found in SKILL.md; using the archive name.</p>" : ""}
      <p class="verdict">${e(riskLabel(report.riskLevel))}${!report.coverage.complete ? " · Incomplete content coverage" : ""}</p>
      <p>${e(report.summary)}</p>
      <dl><dt>Scan time (UTC)</dt><dd>${e(report.scannedAt)}</dd><dt>Ruleset</dt><dd>${e(report.rulesetVersion)} · ${report.rulesChecked} checks</dd><dt>SHA-256</dt><dd class="hash">${e(report.archiveSha256)}</dd><dt>Coverage</dt><dd>${report.coverage.inspectedFiles} / ${report.coverage.totalFiles} file contents inspected · ${e(formatBytes(report.coverage.expandedBytes))} expanded</dd><dt>AI review</dt><dd>${e(report.aiReview.status)}${report.aiReview.model ? ` · ${e(report.aiReview.model)}` : ""}. ${e(report.aiReview.message)}</dd></dl>
      ${buildHtmlAIReview(report)}
      <h3>Findings (${report.findings.length})</h3>
      ${report.findings.length ? report.findings.map((finding) => `<article><h4>${e(finding.severity.toUpperCase())} — ${e(finding.title)}</h4><p>${e(CATEGORIES[finding.category])} · ${e(finding.ruleId)} · ${e(finding.source)} · ${e(finding.confidence)} confidence</p><p class="hash">${e(finding.file)}${finding.line ? `:${finding.line}` : " (file metadata)"}</p><pre>${e(finding.evidence)}</pre><p>${e(finding.description)}</p><p><strong>Recommended action:</strong> ${e(finding.recommendation)}</p></article>`).join("") : "<p>No configured threat indicators were detected. This is not a guarantee of safety.</p>"}
      <h3>File inventory</h3>
      <table><thead><tr><th>File</th><th>Type</th><th>Bytes</th><th>Content coverage</th><th>SHA-256</th></tr></thead><tbody>${report.files.map((file) => `<tr><td>${e(file.path)}</td><td>${e(file.kind)}</td><td>${file.bytes}</td><td>${e(file.status)}</td><td class="hash">${e(file.sha256)}</td></tr>`).join("")}</tbody></table>
      <h3>Scope and limitations</h3><ul>${report.limitations.map((limitation) => `<li>${e(limitation)}</li>`).join("")}</ul>
    </section>
  `).join("")
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Skill Guard security report</title><style>:root{--ink:#192f4d;--paper:#fff;--slate:#67778b;--gold:#efa51f;--risk:#bf493f}*{box-sizing:border-box}body{max-width:1040px;margin:0 auto;padding:40px 24px;color:var(--ink);background:var(--paper);font:15px/1.6 sans-serif}h1,h2,h3,h4{line-height:1.3}h1{font-size:36px;letter-spacing:-1px}h2{overflow-wrap:anywhere}header{border-bottom:3px solid var(--gold);padding-bottom:20px}section{padding:28px 0;border-bottom:1px solid var(--slate)}article{border:1px solid var(--slate);border-radius:8px;padding:18px;margin:18px 0;break-inside:avoid}pre{white-space:pre-wrap;overflow-wrap:anywhere;unicode-bidi:plaintext;background:var(--ink);color:var(--paper);padding:15px;border-radius:6px;font:14px/1.6 monospace}.hash{font-family:monospace;overflow-wrap:anywhere;word-break:break-all}dl{display:grid;grid-template-columns:140px 1fr;gap:8px}dd{margin:0}dt{font-weight:bold}.verdict{font-size:20px;font-weight:bold}table{border-collapse:collapse;width:100%;font-size:14px;table-layout:fixed}th,td{text-align:left;padding:8px;border:1px solid var(--slate);overflow-wrap:anywhere}a{color:var(--ink)}@media print{body{padding:0}article{box-shadow:none}a{word-break:break-all}}</style></head><body><header><p>ENCAPSA / SKILL GUARD${sample ? " / SYNTHETIC DEMONSTRATION" : ""}</p><h1>AI skill security report</h1><p>Evidence before execution. This report is advisory, not a security certification. Save or print this document to PDF using your browser.</p>${sample ? "<p><strong>Sample:</strong> findings come from inert synthetic indicators, not real malware.</p>" : ""}</header>${sections}<footer><h3>Research sources</h3><ul>${RESEARCH_SOURCES.map((source) => `<li><a href="${e(source.url)}" target="_blank" rel="noopener noreferrer">${e(source.publisher)}: ${e(source.title)}</a></li>`).join("")}</ul><p>Skill Guard does not retain uploaded archives or reports. Optional AI review is subject to provider data policies. Use human review and least privilege before installing any skill.</p></footer></body></html>`
}

export function downloadReports(reports: ScanReport[], format: "html" | "json", sample = false) {
  const content = format === "json" ? JSON.stringify({ tool: "Skill Guard by Encapsa", sample, reports }, null, 2) : buildHtmlReport(reports, sample)
  const blob = new Blob([content], { type: format === "json" ? "application/json" : "text/html;charset=utf-8" })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = `skill-guard-report${sample ? "-sample" : ""}.${format}`
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
