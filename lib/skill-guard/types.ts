export const MAX_ARCHIVES = 5
export const MAX_ZIP_BYTES = 4 * 1024 * 1024
export const MAX_EXPANDED_BYTES = 20 * 1024 * 1024
export const MAX_FILE_BYTES = 2 * 1024 * 1024
export const MAX_ENTRIES = 500
export const RULESET_VERSION = "2026.09.1"

export const CATEGORIES = {
  "prompt-injection": "Prompt injection",
  credentials: "Credential exposure",
  exfiltration: "Data exfiltration",
  execution: "Unsafe execution",
  persistence: "Persistence & privilege",
  obfuscation: "Obfuscated payloads",
  "supply-chain": "Supply-chain risk",
  integrity: "Archive integrity",
} as const

export type Category = keyof typeof CATEGORIES
export type Severity = "critical" | "high" | "medium" | "low"
export type RiskLevel = Severity | "none"
export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"]

export interface Finding {
  id: string
  ruleId: string
  title: string
  severity: Severity
  category: Category
  file: string
  line: number | null
  evidence: string
  description: string
  recommendation: string
  confidence: "high" | "moderate"
  source: "static" | "ai"
  referenceIds: string[]
}

export interface FileInventory {
  path: string
  bytes: number
  sha256: string
  kind: "text" | "binary" | "executable" | "archive"
  status: "inspected" | "not-inspected"
  findings: number
}

export type AIReviewFailureCode = "timeout" | "cancelled" | "rate-limited" | "configuration" | "credits" | "provider-error" | "invalid-response" | "output-limit" | "content-filter" | "input-limit" | "unknown"

export interface AIReview {
  status: "not-requested" | "complete" | "partial" | "unavailable"
  model: string | null
  reviewedFiles: number
  totalTextFiles: number
  message: string
  attempts?: number
  failureCode?: AIReviewFailureCode
}

export interface ScanReport {
  id: string
  archiveName: string
  archiveSha256: string
  skillName: string
  skillNameSource: "frontmatter" | "heading" | "filename"
  scannedAt: string
  durationMs: number
  rulesetVersion: string
  rulesChecked: number
  riskLevel: RiskLevel
  summary: string
  findings: Finding[]
  files: FileInventory[]
  coverage: {
    totalFiles: number
    inspectedFiles: number
    uninspectedFiles: number
    expandedBytes: number
    manifestCount: number
    complete: boolean
  }
  limitations: string[]
  aiReview: AIReview
}

export function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function riskLabel(level: RiskLevel) {
  return {
    critical: "Critical risk",
    high: "High risk",
    medium: "Review recommended",
    low: "Low-severity indicators",
    none: "No indicators detected",
  }[level]
}
