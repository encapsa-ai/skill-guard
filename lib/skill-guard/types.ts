export const MAX_ARCHIVES = 5
export const SCAN_RATE_LIMIT = 25
export const AI_REVIEW_RATE_LIMIT = 8
export const RATE_LIMIT_WINDOW_SECONDS = 10 * 60
export type RateLimitScope = "scan" | "ai"
export interface ScanQuota {
  scope: RateLimitScope
  limit: number
  remaining: number
  reset: number
}
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

export const AI_REVIEW_METHODS = [
  { id: "intent", title: "Instruction intent", description: "Looks beyond keywords for role overrides, misleading instructions, and behavior outside the declared purpose.", categories: ["prompt-injection"] },
  { id: "data-flow", title: "Sensitive data flow", description: "Examines how secrets and private data are accessed, handled, and potentially sent elsewhere.", categories: ["credentials", "exfiltration"] },
  { id: "execution", title: "Execution & dependencies", description: "Reviews setup commands, script behavior, remote code, and dependency trust boundaries.", categories: ["execution", "supply-chain"] },
  { id: "privileges", title: "Privilege & persistence", description: "Checks requested access, lasting changes, and agent-memory or configuration manipulation.", categories: ["persistence"] },
  { id: "consistency", title: "Cross-file consistency", description: "Compares the supplied manifest context with supporting files in each review batch; unseen files cannot be compared.", categories: ["integrity"] },
  { id: "concealment", title: "Hidden behavior", description: "Looks for disguised instructions, encoded content, and a mismatch between presentation and behavior.", categories: ["obfuscation"] },
] as const satisfies readonly { id: string; title: string; description: string; categories: readonly Category[] }[]

export type AIReviewMethodId = typeof AI_REVIEW_METHODS[number]["id"]

export interface AICitation {
  file: string
  line: number
  evidence: string
}

export interface AIMethodNote {
  summary: string
  citations: AICitation[]
  batch: number
}

export interface AIMethodReview {
  id: AIReviewMethodId
  status: "reviewed" | "limited" | "not-reviewed"
  notes: AIMethodNote[]
  findingCount: number
}

export interface AIFileCoverage {
  file: string
  totalCharacters: number
  reviewedCharacters: number
  reviewedRanges: { startLine: number; endLine: number }[]
  status: "complete" | "partial" | "not-reviewed"
}

export interface AIReview {
  status: "not-requested" | "complete" | "partial" | "unavailable"
  model: string | null
  reviewedFiles: number
  totalTextFiles: number
  message: string
  attempts?: number
  failureCode?: AIReviewFailureCode
  methods?: AIMethodReview[]
  coverage?: {
    reviewedCharacters: number
    totalCharacters: number
    reviewedChunks: number
    plannedChunks: number
    completedBatches: number
    plannedBatches: number
    fullyReviewedFiles: number
    partiallyReviewedFiles: number
    files: AIFileCoverage[]
  }
  validation?: {
    acceptedObservations: number
    discardedObservations: number
    discardedAssessments: number
    relocatedCitations: number
  }
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
