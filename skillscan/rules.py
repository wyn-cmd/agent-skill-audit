"""Rule definitions used by the audit engine.

Every rule has a stable id, a severity and one or more compiled patterns. The
engine decides which text a rule sees (prose, a code span, a shell script or a
config value) through the scope field, so a rule that would fire on ordinary
documentation never gets handed a documentation line.
"""

import re

LOW = "low"
MEDIUM = "medium"
HIGH = "high"

SEVERITY_ORDER = [LOW, MEDIUM, HIGH]
SEVERITY_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2}

SCOPE_PROSE = "prose"
SCOPE_CODE = "code"
SCOPE_SCRIPT = "script"
SCOPE_CONFIG = "config"
SCOPE_FRONTMATTER = "frontmatter"


class Rule:
    """One audit check."""

    def __init__(self, rule_id, title, severity, patterns, scopes, advice):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.scopes = scopes
        self.advice = advice
        self.patterns = [re.compile(p, re.IGNORECASE) for p in patterns]


def _rules():
    return [
        Rule(
            "SS001",
            "destructive command",
            HIGH,
            [
                r"\brm\s+-[a-z]*[rf][a-z]*\s+(?:/|~|\$HOME|\*)",
                r"\bmkfs(?:\.\w+)?\s",
                r"\bdd\s+if=/dev/(?:zero|urandom)\s+of=/dev/",
                r":\(\)\s*\{\s*:\|\s*:&\s*\}\s*;",
                r"\bshred\s+-[a-z]*\s+/dev/",
                r"\bwipefs\b",
            ],
            [SCOPE_CODE, SCOPE_SCRIPT, SCOPE_CONFIG],
            "Delete or format only inside the workspace, and say which path is removed before it runs.",
        ),
        Rule(
            "SS002",
            "privilege escalation",
            HIGH,
            [
                r"\bsudo\s+(?!-n\s+true)",
                r"\bchmod\s+(?:-R\s+)?0?777\b",
                r"\bchown\s+(?:-R\s+)?root",
                r"\bsetcap\b",
                r"\busermod\s+-aG\s+sudo\b",
                r"\bvisudo\b",
            ],
            [SCOPE_CODE, SCOPE_SCRIPT, SCOPE_CONFIG],
            "Drop the elevated call or move it into a documented, user-run setup step.",
        ),
        Rule(
            "SS003",
            "remote script piped into a shell",
            HIGH,
            [
                r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b",
                r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:python3?|node|ruby|perl)\s*$",
                r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:python3?|node)\s+-\s*$",
                r"\biex\b\s*\(?\s*(?:new-object\s+net\.webclient|invoke-webrequest)",
                r"\b(?:curl|wget)\b[^\n]{0,120}-o\s*\S+\s*&&\s*(?:ba|z)?sh\s",
            ],
            [SCOPE_CODE, SCOPE_SCRIPT, SCOPE_CONFIG],
            "Download the script to a file, show it to the user, and run it only after review.",
        ),
        Rule(
            "SS004",
            "known drop or exfiltration endpoint",
            HIGH,
            [
                r"https?://[^\s\"')]*(?:webhook\.site|requestbin|pipedream\.net|transfer\.sh|0x0\.st|termbin\.com|pastebin\.com|ngrok\.(?:io|app)|t\.me/)",
                r"https?://(?:discord|discordapp)\.com/api/webhooks/",
                r"https?://hooks\.slack\.com/services/",
                r"\bapi\.telegram\.org/bot",
            ],
            [SCOPE_CODE, SCOPE_SCRIPT, SCOPE_CONFIG, SCOPE_PROSE],
            "Name the destination and why the data leaves the machine, or remove the call.",
        ),
        Rule(
            "SS005",
            "network call inside a command",
            MEDIUM,
            [
                r"\b(?:curl|wget|nc|ncat|netcat|telnet|scp|rsync)\b[^\n]{0,160}https?://",
                r"\b(?:http\.client|urllib\.request|requests\.(?:get|post)|httpx\.)\b",
                r"\bfetch\s*\(\s*[\"']https?://",
                r"\bInvoke-(?:WebRequest|RestMethod)\b",
            ],
            [SCOPE_CODE, SCOPE_SCRIPT, SCOPE_CONFIG],
            "Keep the host list in the documentation so the user can see every outbound destination.",
        ),
        Rule(
            "SS006",
            "credential or secret read",
            HIGH,
            [
                r"(?:cat|read|open|load|copy|scp|curl|post|upload|send|print|dump|tar|zip)[^\n]{0,60}(?:~/\.ssh|\.aws/credentials|/\.ssh/id_|id_rsa|id_ed25519|\.netrc|\.npmrc|\.pgpass|keychain|login\.keychain|credentials\.json|\.git-credentials)",
                r"(?:~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.netrc|\.git-credentials)[^\n]{0,60}(?:cat|read|open|copy|upload|send|post|curl)",
                r"\benv\s*\|\s*grep\s+-i\s+(?:key|token|secret|pass)",
                r"\bprintenv\s+(?:GITHUB_TOKEN|AWS_|OPENAI|ANTHROPIC)",
            ],
            [SCOPE_CODE, SCOPE_SCRIPT, SCOPE_CONFIG],
            "Read secrets from the environment at run time and never echo or transmit them.",
        ),
        Rule(
            "SS015",
            "secret value placed in a request or a printed line",
            MEDIUM,
            [
                r"(?:echo|printf|print|write|dump|tee)[^\n]{0,40}\$\{?(?:GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|STRIPE_SECRET_KEY)\}?",
                r"\b(?:curl|wget|nc|ncat|post|upload)[^\n]{0,60}\$\{?(?:GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|STRIPE_SECRET_KEY)\}?[^\n]{0,20}https?://",
            ],
            [SCOPE_CODE, SCOPE_SCRIPT, SCOPE_CONFIG],
            "Sending a key is sometimes the job. State which host receives it and keep the key scoped to that call.",
        ),
        Rule(
            "SS007",
            "write outside the workspace",
            MEDIUM,
            [
                r">>?\s*(?:/etc/|/usr/|/var/|/boot/|/opt/)",
                r">>?\s*~(?:/\.bashrc|/\.zshrc|/\.profile|/\.bash_profile|/\.ssh/|/\.config/)",
                r"\b(?:cp|mv|install)\b[^\n]{0,80}\s(?:/etc/|/usr/bin/|/usr/local/bin/|/boot/)",
                r"\b(?:tee|sed\s+-i|truncate)\b[^\n]{0,80}(?:/etc/|/usr/|/boot/)",
                r"\bcrontab\s+-",
                r"\bsystemctl\s+(?:enable|daemon-reload)",
                r"\b(?:launchctl|schtasks|reg\s+add)\b",
            ],
            [SCOPE_CODE, SCOPE_SCRIPT, SCOPE_CONFIG],
            "Write inside the project directory, and print anything that has to touch the wider system.",
        ),
        Rule(
            "SS008",
            "instruction aimed at the agent rather than the user",
            HIGH,
            [
                r"\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|earlier|above)\s+(?:instructions?|prompts?|rules?)",
                r"\bdisregard\s+(?:the\s+|all\s+|any\s+)?(?:previous|prior|system|above)",
                r"\bdo\s+not\s+(?:tell|inform|notify|ask|mention\s+to)\s+(?:the\s+)?user\b",
                r"\bwithout\s+(?:asking|informing|telling|notifying)\s+(?:the\s+)?user\b",
                r"\bdo\s+not\s+mention\b",
                r"\b(?:reveal|print|repeat|dump)\s+(?:your\s+)?system\s+prompt\b",
                r"\boverride\s+(?:your\s+)?(?:safety|guardrails|instructions|system)",
                r"\bkeep\s+this\s+(?:hidden|secret)\s+from\s+the\s+user\b",
            ],
            [SCOPE_PROSE, SCOPE_FRONTMATTER],
            "Skill text that instructs the agent to hide something from its user is a finding, not a feature. Remove it.",
        ),
        Rule(
            "SS009",
            "unpinned package or image in a launch command",
            MEDIUM,
            [
                r"\bnpx\s+(?:-y|--yes)\s+(?!@?[\w.-]+@\d)[\w@./-]+",
                r"\buvx\s+(?!-{1,2}[\w-]+\s)(?![\w.-]+@\d)[\w.-]+",
                r"\bpip\s+install\s+(?!-r\b)(?![\w.-]+==)[\w.-]+",
                r"\bdocker\s+run\b(?![^\n]*@sha256:)",
                r"\bcurl\s+-[a-zA-Z]*L\s+https?://\S+\s*\|\s*sh\b",
            ],
            [SCOPE_CONFIG, SCOPE_SCRIPT, SCOPE_CODE],
            "Pin the version or digest so the server code cannot change under the config.",
        ),
        Rule(
            "SS010",
            "literal secret in a config file",
            HIGH,
            [
                r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}",
                r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}",
                r"\bAKIA[0-9A-Z]{16}\b",
                r"\bxox[baprs]-[A-Za-z0-9-]{10,}",
                r"\bAIza[0-9A-Za-z_\-]{30,}",
                r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.",
                r"-----BEGIN\s+(?:RSA|OPENSSH|EC|PRIVATE)\s",
            ],
            [SCOPE_CONFIG, SCOPE_SCRIPT, SCOPE_PROSE, SCOPE_FRONTMATTER],
            "Move the value into the environment or a local untracked file and rotate the exposed key.",
        ),
        Rule(
            "SS011",
            "unrestricted tool grant",
            HIGH,
            [
                r"allowed[-_ ]tools\s*:\s*[\"']?\*",
                r"^\s*tools\s*:\s*[\"']?\*",
            ],
            [SCOPE_FRONTMATTER, SCOPE_CONFIG],
            "List the tools the skill actually needs instead of granting every tool.",
        ),
        Rule(
            "SS012",
            "broad capability set declared",
            MEDIUM,
            [
                r"allowed[-_ ]tools\s*:[^\n]*(?:Bash|Shell|Terminal|exec)[^\n]*(?:Write|Edit|MultiEdit)[^\n]*(?:WebFetch|WebSearch|http)",
            ],
            [SCOPE_FRONTMATTER],
            "Split the skill or narrow the grant: shell plus write plus network is the set that can do anything.",
        ),
        Rule(
            "SS013",
            "skipped safety or confirmation step",
            MEDIUM,
            [
                r"\bskip\s+(?:the\s+)?(?:confirmation|approval|prompt|dry[\s-]?run)\b",
                r"\bno\s+confirmation\s+(?:is\s+)?(?:needed|required)\b",
                r"\b(?:auto[- ]?approve|autoapprove|bypass\s+permissions?|dangerously-skip-permissions)\b",
                r"\bnever\s+(?:ask|confirm)\b",
            ],
            [SCOPE_PROSE, SCOPE_FRONTMATTER, SCOPE_CODE],
            "Keep the confirmation step, or state exactly what the user pre-approved.",
        ),
        Rule(
            "SS014",
            "skill file with no frontmatter metadata",
            LOW,
            [r"\A(?!(?:---\r?\n))"],
            [SCOPE_FRONTMATTER],
            "Add name and description frontmatter so the skill can be reviewed without reading the whole file.",
        ),
    ]


RULES = _rules()
RULE_BY_ID = {rule.rule_id: rule for rule in RULES}
