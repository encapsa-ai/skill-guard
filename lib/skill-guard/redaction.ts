const tokenPatterns = [
  /\b(?:sk-(?:ant-|proj-)?)[A-Za-z0-9_-]{20,}\b/g,
  /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{25,})\b/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{15,}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
]

export function redactSecrets(input: string): string {
  let output = input.replace(/-----BEGIN [^\r\n]*PRIVATE KEY-----[\s\S]*?-----END [^\r\n]*PRIVATE KEY-----/g, (value) => value.replace(/[^\r\n]+/g, "[PRIVATE KEY REDACTED]"))
  for (const pattern of tokenPatterns) output = output.replace(pattern, "[TOKEN REDACTED]")
  output = output.replace(/\b([\w-]{0,64}(?:secret|password|token|api[_-]?key|access[_-]?key)[\w-]{0,64}["']?\s{0,16}[:=]\s{0,16}["'])([^"'\r\n]{8,4096})(["'])/gi, "$1[SECRET REDACTED]$3")
  output = output.replace(/^([\w-]{0,64}(?:secret|password|token|api[_-]?key|access[_-]?key)[\w-]{0,64}\s{0,16}=\s{0,16})([^\s"'\r\n]{8,4096})/gim, "$1[SECRET REDACTED]")
  output = output.replace(/([?&](?:api[_-]?key|token|secret|password|key)=)[^&\s"'<>]+/gi, "$1[SECRET REDACTED]")
  output = output.replace(/(\bBearer\s+)[A-Za-z0-9_.~+\/-]{16,}/gi, "$1[TOKEN REDACTED]")
  output = output.replace(/(https?:\/\/)[^\s/@:]{1,100}:[^\s/@]{1,200}@/gi, "$1[CREDENTIALS REDACTED]@")
  return output
}

export function visibleText(input: string): string {
  return input.replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2069\u{e0000}-\u{e007f}]/gu, (character) => `[U+${character.codePointAt(0)!.toString(16).toUpperCase()}]`)
}

export function evidenceLine(content: string, offset: number) {
  const bounded = Math.max(0, Math.min(offset, content.length))
  const start = content.lastIndexOf("\n", bounded - 1) + 1
  const end = content.indexOf("\n", bounded)
  const lineText = redactSecrets(content.slice(start, end === -1 ? undefined : end))
  const relative = redactSecrets(content.slice(start, bounded)).length
  const excerptStart = Math.max(0, relative - 100)
  return {
    line: content.slice(0, bounded).split("\n").length,
    evidence: `${excerptStart ? "…" : ""}${visibleText(lineText.slice(excerptStart, excerptStart + 480))}${lineText.length > excerptStart + 480 ? "…" : ""}`,
  }
}
