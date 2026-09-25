import { randomUUID } from "node:crypto"
import type { ArchiveFile, InspectedArchive } from "./archive"
import { evidenceLine, redactSecrets, visibleText } from "./redaction"
import { SECURITY_RULES } from "./rules"
import { RULESET_VERSION, SEVERITY_ORDER, type Finding, type ScanReport } from "./types"

const MAX_REPORTED_FINDINGS = 200
export const STATIC_CHECK_COUNT = SECURITY_RULES.length + 4

function priority(finding: Finding) {
  return SEVERITY_ORDER.indexOf(finding.severity)
}

function inspectEncodedLiterals(file: ArchiveFile): Finding[] {
  if (file.content === null) return []
  const findings: Finding[] = []
  const literals = /["'`]([A-Za-z0-9+/]{40,}={0,2}|(?:\\x[0-9a-fA-F]{2}){12,})["'`]/g
  let count = 0
  for (const match of file.content.matchAll(literals)) {
    if (++count > 20) break
    const literal = match[1]
    if (literal.length > 16_000) continue
    const isHex = literal.startsWith("\\x")
    let decoded: string
    try {
      const data = Buffer.from(isHex ? literal.replaceAll("\\x", "") : literal, isHex ? "hex" : "base64")
      decoded = new TextDecoder("utf-8", { fatal: true }).decode(data)
      if (decoded.includes("\0")) continue
    } catch { continue }
    const matched = SECURITY_RULES
      .filter((rule) => rule.severity === "critical" || rule.severity === "high" || rule.id === "SG-008" || rule.id === "SG-014")
      .map((rule) => ({ rule, match: rule.pattern.exec(decoded) }))
      .filter((item) => item.match)
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.rule.severity) - SEVERITY_ORDER.indexOf(b.rule.severity))[0]
    if (!matched?.match) continue
    const location = evidenceLine(file.content, match.index!)
    const decodedEvidence = evidenceLine(decoded, matched.match.index).evidence
    findings.push({
      id: randomUUID(), ruleId: "SG-033", title: `Encoded payload: ${matched.rule.title.toLowerCase()}`,
      severity: matched.rule.severity === "critical" ? "critical" : "high", category: "obfuscation",
      file: file.path, line: location.line,
      evidence: `${isHex ? "Hex-escaped" : "Base64"} literal (${literal.length} characters). Decoded without execution:\n${decodedEvidence}`,
      description: `A bounded, single-pass decode revealed an indicator matching ${matched.rule.id}. Encoding alone is not malicious; the decoded behavior and source context require review.`,
      recommendation: "Replace the encoded payload with readable, reviewed source. Do not decode it into an interpreter or execute it.",
      confidence: "moderate", source: "static", referenceIds: ["snyk", "cisco"],
    })
  }
  return findings
}

function inspectNodeDependencies(file: ArchiveFile): Finding | null {
  if (!/(?:^|\/)package\.json$/i.test(file.path) || file.content === null) return null
  try {
    const manifest: unknown = JSON.parse(file.content)
    if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) return null
    for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
      const dependencies = (manifest as Record<string, unknown>)[field]
      if (!dependencies || typeof dependencies !== "object" || Array.isArray(dependencies)) continue
      for (const [name, value] of Object.entries(dependencies)) {
        if (typeof value !== "string" || !/^(?:\*|latest$|next$|[~^><]|https?:|git\+|github:)|(?:^|\.)x(?:\.|$)/i.test(value)) continue
        const location = evidenceLine(file.content, Math.max(0, file.content.indexOf(JSON.stringify(name))))
        return {
          id: randomUUID(), ruleId: "SG-034", title: "Floating or remote Node dependency", severity: "low", category: "supply-chain",
          file: file.path, ...location,
          description: "A Node dependency uses a floating range or remote reference. A reviewed lockfile may mitigate this, but lockfile consistency and dependency reputation are not verified by this scanner.",
          recommendation: "Review the dependency and lockfile, use immutable artifacts, and perform a separate transitive-dependency vulnerability and provenance scan.",
          confidence: "moderate", source: "static", referenceIds: ["cisco", "snyk"],
        }
      }
    }
  } catch { /* Invalid manifests remain covered by text rules; nothing is imported or executed. */ }
  return null
}

function metadataFinding(file: ArchiveFile): Finding | null {
  if (file.content !== null) return null
  const descriptions = {
    archive: "A nested archive or container was inventoried but not recursively opened. Its contents can hide additional instructions, scripts, or malware.",
    executable: "An executable or compiled artifact was found. Its bytes were hashed, but the scanner does not decompile, emulate, or execute it.",
    binary: "This asset is not supported text. The scanner does not perform OCR, document extraction, or binary malware analysis on it.",
  }
  const kind = file.kind === "text" ? "binary" : file.kind
  return {
    id: randomUUID(), ruleId: "SG-040", title: kind === "archive" ? "Nested content was not inspected" : kind === "executable" ? "Executable or bytecode needs separate analysis" : "Opaque asset was not inspected",
    severity: kind === "binary" ? "low" : "medium", category: "integrity", file: file.path, line: null,
    evidence: `${visibleText(file.path)} · ${file.bytes} bytes · SHA-256 ${file.sha256}`,
    description: descriptions[kind],
    recommendation: "Obtain readable source or inspect the exact artifact in a dedicated, isolated analysis environment. Do not interpret incomplete coverage as approval.",
    confidence: "high", source: "static", referenceIds: ["cisco", "spec"],
  }
}

export function finalizeReport(report: ScanReport): ScanReport {
  const findings = [...report.findings].sort((a, b) => priority(a) - priority(b) || a.file.localeCompare(b.file) || (a.line ?? 0) - (b.line ?? 0))
  const riskLevel = findings[0]?.severity ?? "none"
  const highRisk = findings.some((finding) => finding.severity === "critical" || finding.severity === "high")
  let summary = !findings.length
    ? "No configured threat indicators were detected in the inspected text. This result does not certify the skill as safe; review its permissions, provenance, and external dependencies."
    : highRisk
      ? "High-priority indicators were found. Do not install or run this skill until the evidence and its surrounding context have been reviewed. Findings can include benign examples as well as actual threats."
      : "This skill contains capabilities or coverage gaps that warrant review. These indicators are not proof of malicious intent; verify that each behavior is necessary and authorized."
  if (!report.coverage.complete) summary += " Content coverage is incomplete."
  return {
    ...report, riskLevel, summary, findings,
    files: report.files.map((file) => ({ ...file, findings: findings.filter((finding) => finding.file === file.path).length })),
  }
}

export function analyzeArchive(archive: InspectedArchive, archiveName: string, startedAt = Date.now()): ScanReport {
  const findings: Finding[] = []
  let omitted = 0
  function add(finding: Finding) {
    if (findings.length < MAX_REPORTED_FINDINGS) {
      findings.push(finding)
      return
    }
    omitted++
    const lowest = findings.reduce((index, item, current) => priority(item) > priority(findings[index]) ? current : index, 0)
    if (priority(finding) < priority(findings[lowest])) findings[lowest] = finding
  }

  for (const file of archive.files) {
    const opaque = metadataFinding(file)
    if (opaque) add(opaque)
    if (file.content === null) continue
    const matches: Finding[] = []
    for (const rule of SECURITY_RULES) {
      if (rule.files && !rule.files.test(file.path)) continue
      const match = rule.pattern.exec(file.content)
      if (!match) continue
      const finding: Finding = {
        id: randomUUID(), ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category,
        file: file.path, ...evidenceLine(file.content, match.index), description: rule.description,
        recommendation: rule.recommendation, confidence: ["SG-005", "SG-006", "SG-004"].includes(rule.id) ? "high" : "moderate",
        source: "static", referenceIds: rule.referenceIds,
      }
      matches.push(finding)
      add(finding)
    }
    const sensitive = matches.find((finding) => ["SG-008", "SG-009", "SG-010"].includes(finding.ruleId))
    const outbound = matches.find((finding) => ["SG-012", "SG-014", "SG-015"].includes(finding.ruleId))
    if (sensitive && outbound) add({
      id: randomUUID(), ruleId: "SG-035", title: "Sensitive access alongside outbound transfer", severity: "high", category: "exfiltration",
      file: file.path, line: outbound.line, evidence: `Sensitive-source indicator (line ${sensitive.line}):\n${sensitive.evidence}\nOutbound indicator (line ${outbound.line}):\n${outbound.evidence}`,
      description: "Sensitive-source access and outbound network behavior occur in the same file. Their co-occurrence warrants investigation, but this heuristic does not prove that sensitive data reaches the network.",
      recommendation: "Trace the data manually from the sensitive source to the request body, headers, and URL. Remove unauthorized transfers and restrict egress.",
      confidence: "moderate", source: "static", referenceIds: ["snyk", "cisco"],
    })
    for (const finding of inspectEncodedLiterals(file)) add(finding)
    const dependency = inspectNodeDependencies(file)
    if (dependency) add(dependency)
  }

  const manifests = archive.files.filter((file) => /(?:^|\/)SKILL\.md$/i.test(file.path) && file.content !== null)
  const manifest = manifests[0]
  if (!manifest || !/^---\r?\n[\s\S]*?\r?\n---(?:\r?\n|$)/.test(manifest.content!)) {
    add({
      id: randomUUID(), ruleId: "SG-036", title: manifest ? "Missing skill frontmatter" : "No readable SKILL.md manifest", severity: "low", category: "integrity",
      file: manifest?.path ?? "(archive)", line: manifest ? 1 : null,
      evidence: manifest ? "SKILL.md does not begin with a YAML frontmatter block." : "No readable SKILL.md was found in this archive.",
      description: "The archive does not expose the expected entry-point metadata. Supporting text was still scanned, but the scanner cannot validate the skill’s declared purpose.",
      recommendation: "Package a readable SKILL.md with name and description frontmatter. Confirm that the archive is a complete skill and review its dependencies.",
      confidence: "high", source: "static", referenceIds: ["spec"],
    })
  }

  const inspectedFiles = archive.files.filter((file) => file.content !== null).length
  const limitations = [
    "Best-effort heuristic analysis, not a safety certification. False positives and false negatives are possible. Findings in comments or documentation may be inert examples.",
    "No uploaded code is run, installed, imported, emulated, or written to a filesystem. URLs and remote dependencies are never contacted.",
    "No full AST/dataflow analysis, decompilation, OCR, reputation checks, CVE lookup, signature validation, or transitive dependency resolution. Assets and nested archives may conceal additional threats.",
    "Text rules inspect the complete decoded file and report the first match per rule per file. Encoded inspection is limited to 20 literal candidates per text file, 16,000 characters each, and one decoding layer.",
    "Evidence and optional AI input receive best-effort secret redaction. Custom, encoded, or unrecognized secrets may remain; remove secrets before uploading or sharing a report.",
    "Risk labels summarize observed indicators, not a probability of compromise. Review permissions, provenance, runtime behavior, and business context before installing.",
  ]
  if (inspectedFiles < archive.files.length) limitations.unshift(`${archive.files.length - inspectedFiles} file(s) were inventoried and hashed but their contents were not inspected. Review the file inventory.`)
  if (omitted) limitations.unshift(`The report retains the ${MAX_REPORTED_FINDINGS} highest-priority findings; ${omitted} additional indicators are omitted. Every accepted text file was still checked.`)
  const name = manifest?.content?.match(/^name:\s*["']?([^\r\n"']+)/m)?.[1]?.trim().slice(0, 80)
  return finalizeReport({
    id: randomUUID(), archiveName: redactSecrets(archiveName), archiveSha256: archive.sha256,
    skillName: name ? redactSecrets(name) : archiveName.replace(/\.zip$/i, ""),
    scannedAt: new Date().toISOString(), durationMs: Date.now() - startedAt,
    rulesetVersion: RULESET_VERSION, rulesChecked: STATIC_CHECK_COUNT,
    riskLevel: "none", summary: "", findings,
    files: archive.files.map(({ content: _content, ...file }) => ({ ...file, findings: 0 })),
    coverage: {
      totalFiles: archive.files.length, inspectedFiles, uninspectedFiles: archive.files.length - inspectedFiles,
      expandedBytes: archive.expandedBytes, manifestCount: manifests.length,
      complete: inspectedFiles === archive.files.length && manifests.length > 0,
    },
    limitations,
    aiReview: {
      status: "not-requested", model: null, reviewedFiles: 0, totalTextFiles: inspectedFiles,
      message: "AI review was not requested. No source text was sent to a model provider; all findings are from static inspection.",
    },
  })
}
