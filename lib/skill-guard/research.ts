import type { Category } from "./types"

export const RESEARCH_REVIEWED_ON = "September 25, 2026"

export const RESEARCH_SOURCES = [
  {
    id: "snyk",
    publisher: "Snyk",
    title: "ToxicSkills: agent skills supply-chain compromise",
    url: "https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/",
    detail: "A February 2026 audit of 3,984 skills identified 76 human-confirmed malicious payloads. The study distinguishes vulnerable skills from intentionally malicious ones; its percentages are not a current ecosystem-wide prevalence estimate.",
  },
  {
    id: "koi",
    publisher: "Koi Security",
    title: "ClawHavoc: malicious skills, infostealers, and hidden backdoors",
    url: "https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting",
    detail: "The February 2026 investigation traces fake prerequisites to Windows keylogging trojans and macOS Atomic Stealer. Separate cases hid a reverse shell in otherwise useful Python and sent an agent’s .env file to a webhook. Its dated marketplace counts are historical, not current prevalence estimates.",
  },
  {
    id: "cisco-research",
    publisher: "Cisco Threat Research",
    title: "A malicious skill case study: silent transfers and agent manipulation",
    url: "https://blogs.cisco.com/security/personal-ai-agents-like-openclaw-are-a-security-nightmare",
    detail: "A January 2026 adversarial-skill experiment demonstrates prompt injection combined with silent data transfer and embedded shell commands. It also highlights manipulated marketplace popularity: a high ranking is not evidence of safety.",
  },
  {
    id: "cisco",
    publisher: "Cisco AI Defense",
    title: "Skill Scanner: threat taxonomy and detection limits",
    url: "https://cisco-ai-defense.github.io/docs/skill-scanner",
    detail: "Documents prompt injection, exfiltration, encoded payloads, Python bytecode, command pipelines, suspicious configuration URLs, dependency risk, and why clean scans cannot certify security.",
  },
  {
    id: "owasp-injection",
    publisher: "OWASP",
    title: "LLM01: Prompt Injection",
    url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    detail: "Covers indirect, multilingual, encoded, split-payload, and multimodal injection. Recommends untrusted-content separation, deterministic output validation, least privilege, and human approval.",
  },
  {
    id: "owasp-agentic",
    publisher: "OWASP",
    title: "Top 10 for Agentic Applications 2026",
    url: "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    detail: "A peer-reviewed framework for the risks introduced when agents can plan, invoke tools, maintain state, and act across systems.",
  },
  {
    id: "spec",
    publisher: "Agent Skills",
    title: "The open Agent Skills specification",
    url: "https://agentskills.io/specification",
    detail: "Defines SKILL.md, metadata, optional scripts, references, and assets. Progressive disclosure makes inspection of the entire archive important—not just the entry-point instructions.",
  },
] as const

export interface ThreatResearch {
  category: Category
  title: string
  summary: string
  files: string
  techniques: string
  coverage: string
  defense: string
  sourceIds: string[]
}

export const THREAT_RESEARCH: ThreatResearch[] = [
  {
    category: "prompt-injection",
    title: "The instruction is the attack",
    summary: "A skill can redirect an agent without shipping executable malware.",
    files: "SKILL.md, README.md, references/*.md, agent instructions, HTML comments, YAML descriptions, and retrieved content.",
    techniques: "System-role impersonation; instructions to ignore prior rules, hide actions, suppress warnings, or trust remote instructions; tool-output laundering; split, multilingual, and invisible-Unicode payloads. A benign-looking description can load a malicious reference later.",
    coverage: "Static rules flag explicit overrides, concealed behavior, fake system delimiters, and invisible characters. Optional AI review considers instruction context. Subtle, multilingual, split, or image-borne instructions may be missed.",
    defense: "Treat skill content as untrusted data. Require approval for consequential actions, isolate tool permissions, and review every referenced file.",
    sourceIds: ["snyk", "owasp-injection", "spec"],
  },
  {
    category: "credentials",
    title: "Credentials become the payload",
    summary: "Useful-looking setup steps can reach far beyond the skill directory.",
    files: "Python, shell, JavaScript, PowerShell, .env files, cloud configuration, browser stores, and bundled secrets.",
    techniques: "Reading environment variables, ~/.aws/credentials, SSH keys, kubeconfig, .npmrc, browser cookies, keychains, wallet seeds, or API tokens. ClawHavoc distributed Windows keylogging trojans and macOS Atomic Stealer through fake prerequisites; another skill targeted the agent’s own .env file.",
    coverage: "Sensitive-path, environment-access, hardcoded-token, private-key, keylogging-API, and secret-disclosure rules. These are indicators, not proof of theft. Best-effort redaction protects common secret formats in evidence and AI input; custom formats may not be recognized.",
    defense: "Remove embedded secrets, rotate exposed credentials, use narrowly scoped credentials, and deny unrelated home-directory access.",
    sourceIds: ["snyk", "koi", "cisco"],
  },
  {
    category: "exfiltration",
    title: "A backdoor disguised as an API call",
    summary: "Network access can turn a local capability into a data leak.",
    files: "requests/httpx code, fetch/axios calls, curl commands, webhooks, configuration URLs, and Markdown images.",
    techniques: "POSTing files or environment data, sending secrets in URL parameters, messaging-bot APIs, paste services, tunneling endpoints, and beacon images. Legitimate network access is not itself evidence of malicious intent.",
    coverage: "Flags sensitive-source and outbound-transfer co-occurrence, uploads, suspicious endpoint patterns, and secret-bearing URLs. This is heuristic correlation, not full program dataflow or live network analysis. Embedded destinations are never contacted.",
    defense: "Allowlist necessary destinations, block arbitrary outbound traffic, and check what data each request sends before approving a skill.",
    sourceIds: ["snyk", "cisco", "owasp-injection"],
  },
  {
    category: "execution",
    title: "The prerequisite that runs everything",
    summary: "Installation and troubleshooting are common covers for remote execution.",
    files: "scripts/*.py, *.sh, *.js, *.ps1, *.bat, setup.py, and instructions inside Markdown.",
    techniques: "Download-and-execute pipelines; eval/exec or shell=True; PowerShell Invoke-Expression; reverse-shell indicators; destructive file operations; and unsafe deserialization. The remote payload may change after a review.",
    coverage: "Language-agnostic pattern matching across all decodable text, including documentation and extensionless scripts. No code is executed, emulated, imported, installed, or detonated. Dynamic behavior and novel encodings remain blind spots.",
    defense: "Inspect installers, pin and verify artifacts, run only in a low-privilege isolated environment, and never automatically approve a remote setup command.",
    sourceIds: ["snyk", "cisco"],
  },
  {
    category: "persistence",
    title: "An install that outlives the session",
    summary: "Attackers can alter the machine—or the agent’s future behavior.",
    files: "Shell profiles, cron jobs, systemd units, LaunchAgents, Windows Run keys, authorized_keys, MEMORY.md, SOUL.md, and agent settings.",
    techniques: "Startup hooks, scheduled tasks, additional SSH access, disabling security controls, broad tool permissions, elevation requests, and writes to persistent agent memory. Memory poisoning can silently affect later tasks.",
    coverage: "Rules flag persistence locations, agent-memory writes, privilege elevation, and disabled safeguards. Mere references can be benign; the report preserves context for manual review.",
    defense: "Keep agent memory and configuration read-only where possible. Audit startup changes and grant only the tools needed for the declared task.",
    sourceIds: ["snyk", "owasp-agentic"],
  },
  {
    category: "obfuscation",
    title: "What you cannot read can still run",
    summary: "Encoding and compiled payloads make superficial reviews unreliable.",
    files: "Base64 strings, escaped text, minified scripts, marshal/pickle data, .pyc files, native binaries, and hidden Unicode.",
    techniques: "Decode-then-execute chains, layered encoding, runtime string reconstruction, bidirectional text, Unicode tags, bytecode-only payloads, and misleading file extensions. Some encoding is legitimate and requires context.",
    coverage: "Detects common encoding/execution combinations and Unicode concealment. Up to 20 bounded Base64/hex literals per text file receive one decoding pass. Binaries and bytecode are inventoried and explicitly marked uninspected; they are not decompiled.",
    defense: "Require readable source corresponding to distributed artifacts, verify hashes out of band, and inspect opaque content with a dedicated isolated malware-analysis tool.",
    sourceIds: ["snyk", "cisco", "owasp-injection"],
  },
  {
    category: "supply-chain",
    title: "The threat outside the ZIP",
    summary: "A harmless archive can delegate its behavior to an unsafe dependency.",
    files: "package.json, requirements.txt, pyproject.toml, lockfiles, setup instructions, hooks, and remote skill references.",
    techniques: "Install hooks, floating versions, git/URL dependencies, dependency confusion, typosquatting, compromised maintainers, remote instructions, and unverifiable release downloads. Financial-account and wallet integrations amplify the impact.",
    coverage: "Flags package lifecycle hooks, remote installations, floating Python requirements, unrestricted tools, and financial-secret access. No registry reputation, CVE/OSV lookup, signature verification, transitive dependency resolution, or remote artifact retrieval is performed.",
    defense: "Verify authors and package names, pin exact versions and hashes, review transitive dependencies, and use separate vulnerability and provenance checks.",
    sourceIds: ["snyk", "cisco", "owasp-agentic"],
  },
  {
    category: "integrity",
    title: "The archive itself is untrusted",
    summary: "A security scanner must not become the next attack surface.",
    files: "ZIP directory records, nested archives, symlinks, duplicate paths, executable attachments, and encrypted entries.",
    techniques: "Path traversal, absolute paths, symlink escapes, duplicate-name confusion, decompression bombs, corrupted entries, encrypted archives, and nested payloads that hide from shallow inspection.",
    coverage: "Rejects unsafe paths, special file entries, duplicate paths, encrypted entries, invalid checksums, and excessive expansion. Limits: 4 MB compressed, 20 MB expanded, 2 MB per extracted file, and 500 entries. Nested archives are flagged, not recursively expanded.",
    defense: "Never extract unknown packages onto a live filesystem. Obtain inspectable source for opaque files and treat incomplete coverage as a reason for further review.",
    sourceIds: ["cisco", "spec"],
  },
]
