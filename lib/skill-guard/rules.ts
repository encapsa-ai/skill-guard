import type { Category, Severity } from "./types"

export interface SecurityRule {
  id: string
  title: string
  severity: Severity
  category: Category
  pattern: RegExp
  files?: RegExp
  description: string
  recommendation: string
  referenceIds: string[]
}

export const SECURITY_RULES: SecurityRule[] = [
  {
    id: "SG-001", title: "Agent instruction override", severity: "high", category: "prompt-injection",
    pattern: /(?:ignore|disregard|override|bypass)[^\n]{0,70}(?:previous|prior|system|safety|security)[^\n]{0,50}(?:instructions?|rules?|restrictions?|polic(?:y|ies)|checks?)/i,
    description: "The content asks an agent to override higher-priority instructions or safety constraints. Quoted examples and security documentation can also match this pattern; review the surrounding intent.",
    recommendation: "Remove behavior-changing instructions unrelated to the skill’s declared purpose. Do not let skill instructions override system policies or user approval.", referenceIds: ["snyk", "owasp-injection"],
  },
  {
    id: "SG-002", title: "Concealed actions or suppressed warnings", severity: "high", category: "prompt-injection",
    pattern: /(?:do not|don't|never|without)[^\n]{0,45}(?:tell|inform|notify|alert|ask|warn|show)[^\n]{0,45}(?:user|human|operator)|(?:hide|conceal|suppress)[^\n]{0,45}(?:actions?|warnings?|activity|execution|security)/i,
    description: "Instructions appear to hide activity from the user or suppress warnings. This can support social engineering and unapproved tool use.",
    recommendation: "Require transparent reporting and explicit human approval for sensitive actions. Check whether this is an inert example or a live instruction.", referenceIds: ["snyk", "owasp-injection"],
  },
  {
    id: "SG-003", title: "System-role impersonation marker", severity: "medium", category: "prompt-injection",
    pattern: /<\|(?:im_start|start_header_id)\|>\s*system|\[SYSTEM\]|<system(?:_prompt)?>/i,
    description: "The file contains system-message-like delimiters. They may be an attempt to elevate untrusted content, though prompt templates can contain them legitimately.",
    recommendation: "Keep external content in an explicit data boundary and do not interpret embedded role markers as authority.", referenceIds: ["owasp-injection"],
  },
  {
    id: "SG-004", title: "Invisible or directional Unicode", severity: "medium", category: "obfuscation",
    pattern: /[\u200b-\u200f\u202a-\u202e\u2060-\u2069\u{e0000}-\u{e007f}]/u,
    description: "Invisible, bidirectional, or Unicode tag characters can hide instructions or make code appear different from its interpreted form. Legitimate multilingual text can also use some of these characters.",
    recommendation: "Inspect the revealed Unicode code points, compare the rendered and source text, and remove unexplained control characters.", referenceIds: ["snyk", "cisco", "owasp-injection"],
  },
  {
    id: "SG-005", title: "Embedded private key", severity: "critical", category: "credentials",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/,
    description: "A private-key marker was found. If this is a real key, distributing this skill exposes it. The report redacts recognized key material.",
    recommendation: "Remove the key from the archive and its publication history. Revoke or rotate it if it has ever been shared.", referenceIds: ["snyk"],
  },
  {
    id: "SG-006", title: "Hardcoded API token", severity: "high", category: "credentials",
    pattern: /\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{25,}|(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{15,})\b/,
    description: "A string matches a recognized credential format. It could be a synthetic token, but a real credential must be considered exposed.",
    recommendation: "Replace embedded credentials with secure runtime references and rotate any real secret before distributing the skill.", referenceIds: ["snyk", "cisco"],
  },
  {
    id: "SG-007", title: "Possible hardcoded credential", severity: "medium", category: "credentials",
    pattern: /(?:api[_-]?key|client[_-]?secret|auth[_-]?token|password|secret_access_key)["']?\s*[:=]\s*["'][^"'\n]{12,}["']/i,
    description: "A credential-like field is assigned a literal value. This heuristic can also match placeholders and configuration documentation.",
    recommendation: "Verify that the value is not a real secret. Use secret injection rather than packaging credentials with a skill.", referenceIds: ["snyk"],
  },
  {
    id: "SG-008", title: "Sensitive credential-file access", severity: "medium", category: "credentials",
    pattern: /\.aws[\/\\]credentials|\.ssh[\/\\]id_(?:rsa|ed25519|ecdsa)|\.kube[\/\\]config|\.npmrc\b|\.netrc\b|(?:~\/|["'\/])\.env(?![\w.-])|wallet\.dat\b/i,
    description: "The file references a sensitive credential location. A reference alone does not prove a read or theft; verify the operation and whether access is required.",
    recommendation: "Deny unrelated home-directory and secret-file access. Provide only narrowly scoped credentials needed by the skill.", referenceIds: ["snyk", "cisco"],
  },
  {
    id: "SG-009", title: "Environment credential surface", severity: "low", category: "credentials",
    pattern: /\bos\.environ\b|\bos\.getenv\s*\(|\bprocess\.env\b|\bgetenv\s*\(|\bGet-ChildItem\s+Env:/i,
    description: "The skill can read environment variables, which often include tokens. Many legitimate integrations require this; verify the specific variables and destinations.",
    recommendation: "Use a minimal environment and avoid passing organization-wide or unrelated credentials into the agent runtime.", referenceIds: ["snyk"],
  },
  {
    id: "SG-010", title: "Browser or keychain credential access", severity: "high", category: "credentials",
    pattern: /(?:Chrome|Chromium|Firefox|Brave)[^\n]{0,100}(?:Cookies|Login Data|logins\.json|key4\.db)|security\s+find-(?:generic|internet)-password|Login\s+Keychain|CryptUnprotectData/i,
    description: "The content references browser credential stores or operating-system secret retrieval. This is unusual for a general-purpose skill.",
    recommendation: "Do not grant browser-profile or keychain access without an explicitly authorized use case and a manual security review.", referenceIds: ["snyk", "cisco"],
  },
  {
    id: "SG-011", title: "Potential secret disclosure in output", severity: "medium", category: "credentials",
    pattern: /(?:\bprint\s*\(|\becho\s+|console\.log\s*\()[^\n]{0,140}(?:api[_-]?key|secret|password|auth[_-]?token|process\.env|os\.environ)/i,
    description: "A logging or output operation appears near credential-related content. Secrets printed by an agent may be copied into logs, transcripts, or third-party systems.",
    recommendation: "Remove secret-bearing logs and return only a non-sensitive success status. Verify that documentation examples do not become live commands.", referenceIds: ["snyk"],
  },
  {
    id: "SG-012", title: "Outbound file-upload behavior", severity: "medium", category: "exfiltration",
    pattern: /\bcurl\b[^\n]{0,250}(?:--data-binary\s+@|--upload-file\s+|(?:-F|--form)\s+[^\n]{0,60}@)|(?:requests|httpx)\.post\s*\([^\n]{0,250}\bfiles\s*=/i,
    description: "The content includes file-transfer behavior. Uploading can be legitimate, but the destination, files, and consent boundary must be checked.",
    recommendation: "Allowlist the destination and confirm that no secrets, unrelated files, or agent context are included in the upload.", referenceIds: ["snyk", "cisco"],
  },
  {
    id: "SG-013", title: "Credential-bearing URL", severity: "high", category: "exfiltration",
    pattern: /https?:\/\/[^\s"'<>]{1,500}[?&](?:api[_-]?key|token|secret|password)=[^&\s"'<>]{3,}/i,
    description: "A URL contains a credential-like query parameter. URL values may leak through access logs, telemetry, browser history, or intermediary services.",
    recommendation: "Keep credentials out of URLs. Use secure authorization headers and verify ownership of the receiving endpoint.", referenceIds: ["snyk", "owasp-injection"],
  },
  {
    id: "SG-014", title: "Webhook, tunnel, or paste-service endpoint", severity: "medium", category: "exfiltration",
    pattern: /(?:discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|webhook\.site|requestbin\.[a-z]+|[\w.-]+\.ngrok(?:-free)?\.(?:app|io)|[\w.-]+\.trycloudflare\.com|pastebin\.com\/raw)/i,
    description: "The file references a service often used for callbacks, tunneling, or payload hosting. These services also have legitimate uses; no reputation lookup was performed.",
    recommendation: "Confirm endpoint ownership and exactly what data is sent. Avoid unapproved temporary tunnels and public collection endpoints.", referenceIds: ["cisco", "snyk"],
  },
  {
    id: "SG-015", title: "External network capability", severity: "low", category: "exfiltration",
    pattern: /\b(?:requests|httpx|axios)\.(?:get|post|put|patch|request)\s*\(|\bfetch\s*\(\s*["']https?:|\bcurl\s+[^\n]{0,160}https?:|urllib\.request|Invoke-(?:WebRequest|RestMethod)/i,
    description: "The skill makes or documents an outbound request. This is a capability indicator, not a claim that the endpoint or request is malicious.",
    recommendation: "Review the destination, payload, and handling of returned untrusted content. Prefer explicit outbound allowlists.", referenceIds: ["snyk", "owasp-injection"],
  },
  {
    id: "SG-016", title: "Download-and-execute pipeline", severity: "high", category: "execution",
    pattern: /(?:curl|wget)[^\n]{0,350}\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python3?|perl|node)\b|(?:bash|sh|zsh)\s+-c\s+["']?\$\(\s*(?:curl|wget)|(?:bash|sh|zsh)\s+<\(\s*(?:curl|wget)|(?:iwr|Invoke-WebRequest)[^\n]{0,250}\|\s*(?:iex|Invoke-Expression)\b|\b(?:iex|Invoke-Expression)\s*\(\s*(?:iwr|irm|New-Object)/i,
    description: "Downloaded content is passed directly to an interpreter. The code that runs is outside this archive and can change without the skill changing.",
    recommendation: "Remove direct download-to-shell execution. Obtain the exact artifact, inspect its source, and verify a pinned hash before any approved execution.", referenceIds: ["snyk", "cisco"],
  },
  {
    id: "SG-017", title: "Dynamic code evaluation", severity: "medium", category: "execution",
    pattern: /(?<![.\w])(?:eval|exec)\s*\(|new\s+Function\s*\(|\bInvoke-Expression\b/,
    description: "The skill evaluates dynamically constructed code or commands. Risk depends on where the evaluated input originates.",
    recommendation: "Replace dynamic evaluation with explicit operations and inspect every source of evaluated input. Never evaluate content fetched from an untrusted source.", referenceIds: ["cisco"],
  },
  {
    id: "SG-018", title: "Reverse-shell or remote-control indicator", severity: "critical", category: "execution",
    pattern: /\/dev\/tcp\/[^\s"']+|\b(?:nc|ncat|netcat)\b[^\n]{0,120}\s(?:-e|--exec)\s+(?:\/?(?:bin\/)?(?:ba)?sh|cmd)|\bos\.dup2\s*\(\s*\w+\.fileno\s*\(/i,
    description: "A pattern associated with redirecting a shell or process to a remote connection was found. Even if this is a quoted test example, it warrants explicit review before installation.",
    recommendation: "Do not run this skill until the remote-control behavior has been removed or independently justified. Isolate and investigate any environment where it already ran.", referenceIds: ["snyk", "cisco"],
  },
  {
    id: "SG-019", title: "Unsafe deserialization capability", severity: "medium", category: "execution",
    pattern: /\b(?:pickle|dill|cloudpickle|marshal)\.(?:load|loads)\s*\(/,
    description: "Python object or bytecode deserialization can execute code when input is untrusted. Bundled serialized data is not proven safe by this scan.",
    recommendation: "Avoid unsafe deserialization of third-party files. Prefer data-only formats with strict schemas, or independently review the exact input.", referenceIds: ["cisco"],
  },
  {
    id: "SG-020", title: "Broad destructive filesystem operation", severity: "high", category: "execution",
    pattern: /\brm\s+-(?:rf|fr)\s+["']?(?:\/(?:\s|$|["'])|~(?:\/|\s|$)|\$HOME)|Remove-Item[^\n]{0,140}-Recurse[^\n]{0,80}-Force|\bformat\s+[c-z]:/im,
    description: "The file contains a command that can recursively delete broad filesystem locations or format a drive. Context may be explanatory, but execution would be destructive.",
    recommendation: "Remove broad deletion commands and confine any necessary cleanup to a verified temporary directory with explicit approval.", referenceIds: ["snyk"],
  },
  {
    id: "SG-021", title: "Persistence or startup modification", severity: "medium", category: "persistence",
    pattern: /\bcrontab\b|\/etc\/cron|LaunchAgents|LaunchDaemons|\.bashrc\b|\.zshrc\b|authorized_keys\b|CurrentVersion[\\/]+Run\b|systemctl\s+enable\b|schtasks\s+\/create/i,
    description: "A startup, scheduled-task, shell-profile, or SSH persistence location is referenced. This can make behavior survive beyond the current agent session.",
    recommendation: "Verify whether a write actually occurs, reject unrelated startup changes, and audit existing persistence if the skill has already been installed.", referenceIds: ["snyk", "owasp-agentic"],
  },
  {
    id: "SG-022", title: "Persistent agent-memory modification", severity: "high", category: "persistence",
    pattern: /(?:write|append|overwrite|modify|update|>>|>)[^\n]{0,120}(?:MEMORY|SOUL|AGENTS|CLAUDE)\.md|open\s*\([^\n]{0,100}(?:MEMORY|SOUL|AGENTS|CLAUDE)\.md[^\n]{0,80}["'][aw]["']/i,
    description: "The content asks for a write to persistent agent memory or instructions. A malicious change can influence later tasks after the original skill is no longer active.",
    recommendation: "Require approval for memory or policy writes and review the proposed contents separately. Keep agent governance files read-only where practical.", referenceIds: ["snyk", "owasp-agentic"],
  },
  {
    id: "SG-023", title: "Elevated or overly broad permissions", severity: "medium", category: "persistence",
    pattern: /\bsudo\s+|\bchmod\s+(?:777|[ugo]*\+s)\b|--privileged\b|runas\s+\/user:administrator|Set-ExecutionPolicy\s+(?:Unrestricted|Bypass)/i,
    description: "The skill requests elevated execution or broad permissions. This expands the impact of accidental or malicious behavior.",
    recommendation: "Run with the least privilege required and avoid root, administrator, privileged-container, and world-writable permissions.", referenceIds: ["snyk", "owasp-agentic"],
  },
  {
    id: "SG-024", title: "Safety control or TLS verification bypass", severity: "high", category: "persistence",
    pattern: /(?:disable|bypass|turn off)[^\n]{0,45}(?:sandbox|antivirus|firewall|security checks|safety checks)|--dangerously-skip-permissions|rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0/i,
    description: "Instructions or code weaken a security boundary, approval mechanism, or transport verification. A troubleshooting pretext does not make this safe.",
    recommendation: "Keep approval, sandboxing, and TLS verification enabled. Fix the underlying compatibility problem rather than disabling security controls.", referenceIds: ["snyk", "cisco"],
  },
  {
    id: "SG-025", title: "Decode-then-execute behavior", severity: "high", category: "obfuscation",
    pattern: /(?:eval|exec|Function)[^\n]{0,140}(?:base64|atob|b64decode|fromCharCode|fromhex)|(?:base64\s+(?:-d|--decode)|b64decode\s*\()[^\n]{0,140}\|\s*(?:bash|sh|python)|powershell[^\n]{0,100}-(?:enc|encodedcommand)\b/i,
    description: "An encoded value is paired with code execution. This can conceal the behavior from a superficial review.",
    recommendation: "Replace obfuscated execution with readable source and review the decoded content without executing it.", referenceIds: ["snyk", "cisco"],
  },
  {
    id: "SG-026", title: "Remote or alternate-index dependency", severity: "medium", category: "supply-chain",
    pattern: /(?:pip|pip3|uv\s+pip)\s+install[^\n]{0,200}(?:https?:\/\/|git\+|--extra-index-url|--index-url)|npm\s+(?:install|i|add)\s+[^\n]{0,120}(?:https?:\/\/|git\+)|\bgit\s+clone\b/i,
    description: "Setup retrieves a dependency from a remote location or alternate index. Its content and transitive dependencies are outside this scan.",
    recommendation: "Verify package identity and origin, pin immutable versions or commits and hashes, and review downloaded dependencies separately.", referenceIds: ["snyk", "cisco"],
  },
  {
    id: "SG-027", title: "Unpinned Python dependency", severity: "low", category: "supply-chain",
    files: /(?:^|\/)requirements[^/]*\.txt$/i,
    pattern: /^[a-z][a-z0-9_.-]*(?:\[[a-z0-9_,.-]+\])?(?:\s*(?:>=|<=|~=|>|<|!=)[^\n]+)?\s*$/im,
    description: "A dependency is not pinned to an exact version. Future installations may resolve to a different artifact. No package vulnerability or reputation lookup was performed.",
    recommendation: "Use a reviewed lockfile, exact version pins, and artifact hashes. Audit transitive dependencies with a dedicated dependency scanner.", referenceIds: ["cisco", "snyk"],
  },
  {
    id: "SG-028", title: "Package installation lifecycle hook", severity: "medium", category: "supply-chain",
    files: /(?:^|\/)package\.json$/i,
    pattern: /"(?:preinstall|install|postinstall|prepare)"\s*:\s*"[^"\n]+"/i,
    description: "The package defines a lifecycle script that may run during installation. Many packages use these legitimately, but the hook and its entire call chain require review.",
    recommendation: "Inspect the referenced command and script before installing. Disable lifecycle scripts until their behavior is understood.", referenceIds: ["snyk", "cisco"],
  },
  {
    id: "SG-029", title: "Unrestricted declared tool access", severity: "medium", category: "persistence",
    pattern: /allowed-tools\s*:[^\n]{0,150}(?:Bash\(\*\)|["']?\*(?:["']|\s|$)|Bash\s*(?:$|\n))/im,
    description: "The skill declares broad tool permissions instead of narrowly scoped operations. Actual enforcement depends on the host agent.",
    recommendation: "Restrict declared tools and command scopes to the minimum needed, and enforce those restrictions in the agent runtime.", referenceIds: ["spec", "owasp-agentic"],
  },
  {
    id: "SG-030", title: "Shell or subprocess execution capability", severity: "low", category: "execution",
    pattern: /\bos\.system\s*\(|\bsubprocess\.(?:run|Popen|call|check_output)\s*\(|\b(?:execSync|spawnSync)\s*\(|shell\s*=\s*True/,
    description: "The skill can start a subprocess or shell. This is often a legitimate capability; the command, arguments, input validation, and permissions determine the risk.",
    recommendation: "Use fixed executables and argument arrays rather than shell interpolation. Keep untrusted input out of executable commands.", referenceIds: ["cisco"],
  },
  {
    id: "SG-031", title: "Remote instruction dependency", severity: "medium", category: "supply-chain",
    pattern: /(?:follow|load|fetch|read|execute)[^\n]{0,100}https?:\/\/[^\s"'<>]{1,250}(?:\.md\b|instructions|prompts)/i,
    description: "The skill appears to load instructions from an external source. The remote content is not bundled and can change after this archive is reviewed.",
    recommendation: "Bundle and pin reviewed instructions, or treat fetched text only as data. Never grant remote text the authority to alter tool behavior.", referenceIds: ["snyk", "owasp-injection"],
  },
  {
    id: "SG-032", title: "Password-protected payload setup", severity: "high", category: "obfuscation",
    pattern: /\bunzip\s+[^\n]{0,80}-P\s+|\b7z\s+[ex]\s+[^\n]{0,100}-p\S+/i,
    description: "Setup includes extracting a password-protected payload. Encrypted artifacts can hide malware from scanners and are not inspected here.",
    recommendation: "Obtain the unencrypted, readable source and review it before installation. Do not execute bundled or remotely retrieved encrypted payloads.", referenceIds: ["snyk", "koi"],
  },
  {
    id: "SG-037", title: "Downloaded payload made executable", severity: "high", category: "execution",
    pattern: /\b(?:curl|wget)\b[^\n]{0,350}(?:\n[^\n]{0,350}){0,2}\bchmod\s+\+x\b/i,
    description: "A download appears near a command that marks a file executable. Fake skill prerequisites have used this sequence to deliver infostealers; a legitimate installer may also match. The downloaded artifact was not retrieved or analyzed.",
    recommendation: "Obtain and inspect the exact artifact separately, verify its origin and immutable hash, and do not approve unexplained executable prerequisites.", referenceIds: ["koi", "snyk"],
  },
  {
    id: "SG-038", title: "Operating-system quarantine bypass", severity: "high", category: "persistence",
    pattern: /\bxattr\s+-[a-z]*c[a-z]*\s+|\bxattr\s+-[a-z]*d[a-z]*\s+com\.apple\.quarantine|\bspctl\s+--(?:master-disable|global-disable)/i,
    description: "The content clears quarantine-related metadata or disables an operating-system execution safeguard. This appeared in documented macOS skill-malware delivery chains, though some troubleshooting guides also use it.",
    recommendation: "Keep operating-system protections enabled. Investigate why the artifact is blocked and verify its source and signature rather than bypassing the warning.", referenceIds: ["koi"],
  },
  {
    id: "SG-039", title: "Keyboard capture capability", severity: "high", category: "credentials",
    pattern: /\bpynput\.keyboard\.Listener\b|\bkeyboard\.(?:on_press|hook|record)\s*\(|\bSetWindowsHookEx[AW]?\s*\(|\bGetAsyncKeyState\s*\(/,
    description: "The source references keyboard interception APIs. These can expose credentials and private input, although explicitly authorized accessibility or automation tools may use them legitimately.",
    recommendation: "Reject unexplained keyboard capture and inspect event handlers, storage, and outbound transfers. Require explicit consent for any justified input monitoring.", referenceIds: ["koi"],
  },
]
