# Walk an agent configuration tree and report risky capability grants.
#
# The engine never executes anything. It reads the files a coding agent would
# read (skill files, MCP server configuration, hooks, shell and script files that
# ship with a skill) and matches them against the rules in rules.py.

import json
import os
import re
import stat

from .rules import (
    LOW,
    MEDIUM,
    HIGH,
    RULES,
    SEVERITY_ORDER,
    SEVERITY_RANK,
    SCOPE_CODE,
    SCOPE_CONFIG,
    SCOPE_FRONTMATTER,
    SCOPE_PROSE,
    SCOPE_SCRIPT,
)

IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "dist",
    "build",
}

TEXT_SUFFIXES = (
    ".md",
    ".markdown",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ps1",
    ".bat",
    ".cmd",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".rb",
    ".pl",
    ".php",
)

SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd")
CODE_SUFFIXES = (".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php")
CONFIG_SUFFIXES = (".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env")

CONFIG_BASENAMES = {
    "mcp.json",
    ".mcp.json",
    "claude_desktop_config.json",
    "settings.json",
    "settings.local.json",
    "config.json",
    "config.yaml",
    "config.yml",
    "config.toml",
    "gemini-settings.json",
}

INSTRUCTION_BASENAMES = {"skill.md", "agents.md", "agent.md", "claude.md"}

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_LINE_CHARS = 2000
MAX_SAMPLES = 3

IGNORE_FILE_RE = re.compile(r"skillscan:\s*ignore-file\b")
IGNORE_LINE_RE = re.compile(r"skillscan:\s*ignore(?!-file)\b(?:\s*([A-Z]{2}\d{3}(?:\s*,\s*[A-Z]{2}\d{3})*))?")
IGNORE_HEAD_LINES = 10


def parse_directives(text):
    # Read the suppression directives out of one file.
    #
    # Returns (ignore_whole_file, set_of_rule_ids). A bare "skillscan: ignore" on a
    # line silences that line only. "skillscan: ignore SS006,SS007" silences those
    # rules for the whole file. "skillscan: ignore-file" in the first ten lines
    # silences the file, which is what a fixture or an example tree wants.
    #
    lines = text.splitlines()
    ignore_file = any(IGNORE_FILE_RE.search(line) for line in lines[:IGNORE_HEAD_LINES])
    rule_ids = set()
    for line in lines:
        match = IGNORE_LINE_RE.search(line)
        if match and match.group(1):
            for part in match.group(1).split(","):
                rule_ids.add(part.strip())
    return ignore_file, rule_ids


def line_is_ignored(line):
    # True when the line carries a bare suppression directive.
    match = IGNORE_LINE_RE.search(line)
    return bool(match) and not match.group(1)


class Finding:
    # One rule hit against one file, with a few sample lines.

    def __init__(self, rule, path):
        self.rule_id = rule.rule_id
        self.title = rule.title
        self.severity = rule.severity
        self.advice = rule.advice
        self.path = path
        self.count = 0
        self.samples = []

    def add(self, lineno, text):
        self.count += 1
        if len(self.samples) < MAX_SAMPLES:
            self.samples.append((lineno, text))

    def sort_key(self):
        return (-SEVERITY_RANK[self.severity], self.rule_id, self.path)


class Report:
    # Everything one scan produced.

    def __init__(self, root):
        self.root = root
        self.files_scanned = 0
        self.files_skipped = 0
        self.files_ignored = 0
        self.warnings = []
        self.findings = []

    def counts(self):
        tally = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            tally[finding.severity] += 1
        return tally

    def worst_severity(self):
        if not self.findings:
            return None
        best = LOW
        for finding in self.findings:
            if SEVERITY_RANK[finding.severity] > SEVERITY_RANK[best]:
                best = finding.severity
        return best

    def to_dict(self):
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "files_ignored": self.files_ignored,
            "warnings": list(self.warnings),
            "counts": self.counts(),
            "findings": [
                {
                    "rule": finding.rule_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "path": finding.path,
                    "count": finding.count,
                    "advice": finding.advice,
                    "samples": [{"line": line, "text": text} for line, text in finding.samples],
                }
                for finding in self.findings
            ],
        }


def is_instruction_file(rel_path):
    base = os.path.basename(rel_path).lower()
    if base in INSTRUCTION_BASENAMES or base.endswith(".skill.md"):
        return True
    parts = [p.lower() for p in rel_path.split(os.sep)]
    return "skills" in parts and base.endswith((".md", ".markdown"))


def looks_like_config(rel_path, text):
    base = os.path.basename(rel_path).lower()
    if base in CONFIG_BASENAMES:
        return True
    if base.endswith(CONFIG_SUFFIXES) and '"mcpServers"' in text:
        return True
    return False


def parse_frontmatter(lines):
    # Return (frontmatter_lines, body_start_index). Empty list when absent.
    if not lines:
        return [], 0
    if lines[0].strip() != "---":
        return [], 0
    for index in range(1, len(lines)):
        if lines[index].strip() in ("---", "..."):
            return lines[1:index], index + 1
    return [], 0


def code_spans(line):
    # Text inside backticks on one line, including fenced-block single ticks.
    spans = []
    parts = line.split("`")
    for index in range(1, len(parts), 2):
        span = parts[index].strip()
        if span:
            spans.append(span)
    return spans


def strip_code_spans(line):
    parts = line.split("`")
    return " ".join(parts[0::2])


LIST_MARKER = re.compile(r"^(?:[-*+]\s+|\d+[.)]\s+|>\s+|\$\s+|#+\s+|!?\s*>)")

COMMAND_VERBS = {
    "awk",
    "bash",
    "cat",
    "chmod",
    "chown",
    "cp",
    "crontab",
    "curl",
    "dd",
    "docker",
    "doas",
    "env",
    "export",
    "find",
    "gh",
    "git",
    "go",
    "install",
    "launchctl",
    "make",
    "mkfs",
    "mv",
    "nc",
    "ncat",
    "netcat",
    "node",
    "npm",
    "npx",
    "pip",
    "pip3",
    "printenv",
    "python",
    "python3",
    "rm",
    "rsync",
    "scp",
    "schtasks",
    "sed",
    "sh",
    "shred",
    "source",
    "ssh",
    "sudo",
    "systemctl",
    "tar",
    "tee",
    "truncate",
    "unzip",
    "usermod",
    "uvx",
    "visudo",
    "wget",
    "wipefs",
    "yarn",
    "zip",
    "zsh",
}

VERB_SKIP = {"doas", "sudo"}


def looks_like_command(line):
    # True when a prose line is itself a command rather than a sentence about one.
    #
    # Documentation that names a command ("the sudo step is explained here") is not a
    # finding; a line that opens with the command and its arguments is.
    #
    text = line.strip()
    previous = None
    while previous != text:
        previous = text
        text = LIST_MARKER.sub("", text, count=1).strip()
    if not text:
        return False
    words = text.split()
    index = 0
    while index < len(words) and "=" in words[index] and not words[index].startswith(("=", "-")):
        index += 1
    if index >= len(words):
        return False
    first = words[index].strip("`\"'")
    while first in VERB_SKIP and index + 1 < len(words):
        index += 1
        first = words[index].strip("`\"'")
    return first in COMMAND_VERBS


def scope_for(rel_path, line, in_fence):
    # Decide which scope a line belongs to, for one file type.
    lower = rel_path.lower()
    if lower.endswith(SCRIPT_SUFFIXES):
        return [(SCOPE_SCRIPT, line)]
    if lower.endswith(CODE_SUFFIXES):
        return [(SCOPE_CODE, line)]
    if in_fence:
        return [(SCOPE_CODE, line)]
    if lower.endswith((".json", ".yaml", ".yml", ".toml", ".ini", ".cfg")) or os.path.basename(lower).startswith(".env"):
        return [(SCOPE_CONFIG, line)]
    entries = []
    spans = " ".join(code_spans(line))
    if spans:
        entries.append((SCOPE_CODE, spans))
    prose = strip_code_spans(line)
    if prose.strip():
        entries.append((SCOPE_PROSE, prose))
        if looks_like_command(prose):
            entries.append((SCOPE_CODE, prose))
    return entries


def scan_text(rel_path, text, report, findings, is_instruction, file_skips=None):
    file_skips = file_skips or set()
    lines = text.splitlines()
    frontmatter, body_start = parse_frontmatter(lines) if is_instruction else ([], 0)

    if is_instruction:
        if frontmatter:
            for offset, line in enumerate(frontmatter):
                apply_rules(rel_path, SCOPE_FRONTMATTER, line, offset + 2, findings, skip_rules=file_skips | {"SS014"})
        else:
            apply_rules(rel_path, SCOPE_FRONTMATTER, "", 0, findings, only_rules={"SS014"}, line_hint=1)

    in_fence = False
    for index in range(body_start, len(lines)):
        raw = lines[index]
        if raw.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if line_is_ignored(raw):
            continue
        line = raw[:MAX_LINE_CHARS]
        for scope, candidate in scope_for(rel_path, line, in_fence):
            apply_rules(rel_path, scope, candidate, index + 1, findings, skip_rules=file_skips)


def apply_rules(rel_path, scope, text, lineno, findings, skip_rules=None, only_rules=None, line_hint=None):
    skip_rules = skip_rules or set()
    for rule in RULES:
        if rule.rule_id in skip_rules:
            continue
        if only_rules is not None and rule.rule_id not in only_rules:
            continue
        if scope not in rule.scopes:
            continue
        hit = None
        for pattern in rule.patterns:
            if pattern.search(text):
                hit = pattern
                break
        if hit is None:
            continue
        key = (rule.rule_id, rel_path)
        finding = findings.get(key)
        if finding is None:
            finding = Finding(rule, rel_path)
            findings[key] = finding
        sample_line = lineno or line_hint or 0
        finding.add(sample_line, (text.strip() or "<empty>")[:160])


def locate(text, token):
    # Line number of the first line holding token, or 0 when it is not found.
    if not token:
        return 0
    for index, line in enumerate(text.splitlines(), start=1):
        if token in line:
            return index
    return 0


def scan_json_config(rel_path, text, findings, file_skips=None):
    # Look inside MCP server definitions rather than only at the raw text.
    file_skips = file_skips or set()
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return
    servers = []
    if isinstance(data, dict):
        for key in ("mcpServers", "servers", "mcp_servers"):
            value = data.get(key)
            if isinstance(value, dict):
                for name, body in value.items():
                    if isinstance(body, dict):
                        servers.append((name, body))
    for name, body in servers:
        command = body.get("command")
        args = body.get("args")
        joined = " ".join(str(part) for part in (args if isinstance(args, list) else []) if isinstance(part, (str, int, float)))
        line = f"{command} {joined}".strip()
        if line:
            apply_rules(rel_path, SCOPE_CONFIG, line, locate(text, str(command or "").split()[0] if command else ""), findings, skip_rules=file_skips)
        env = body.get("env")
        if isinstance(env, dict):
            for key, value in env.items():
                if isinstance(value, str) and len(value) > 12:
                    apply_rules(rel_path, SCOPE_CONFIG, f"{key}={value}", locate(text, str(key)), findings, skip_rules=file_skips)
        if body.get("autoApprove") is True or body.get("auto_approve") is True:
            key = ("SS013", rel_path)
            finding = findings.get(key)
            if finding is None:
                from .rules import RULE_BY_ID

                finding = Finding(RULE_BY_ID["SS013"], rel_path)
                findings[key] = finding
            finding.add(locate(text, "autoApprove") or locate(text, "auto_approve"), f"{name}: autoApprove true")


def scan_file(rel_path, full_path, report, findings):
    base = os.path.basename(rel_path).lower()
    if not (rel_path.lower().endswith(TEXT_SUFFIXES) or base.startswith(".env")):
        report.files_skipped += 1
        return
    try:
        info = os.stat(full_path)
    except OSError as exc:
        report.warnings.append(f"{rel_path}: cannot stat ({exc.strerror or exc})")
        report.files_skipped += 1
        return
    if not stat.S_ISREG(info.st_mode):
        report.warnings.append(f"{rel_path}: skipped, not a regular file")
        report.files_skipped += 1
        return
    size = info.st_size
    if size > MAX_FILE_BYTES:
        report.warnings.append(f"{rel_path}: skipped, {size} bytes is over the {MAX_FILE_BYTES} byte limit")
        report.files_skipped += 1
        return
    try:
        with open(full_path, "rb") as handle:
            blob = handle.read()
    except OSError as exc:
        report.warnings.append(f"{rel_path}: cannot read ({exc.strerror or exc})")
        report.files_skipped += 1
        return
    if b"\x00" in blob[:8192]:
        report.warnings.append(f"{rel_path}: skipped, binary content")
        report.files_skipped += 1
        return
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        text = blob.decode("utf-8", "replace")
        report.warnings.append(f"{rel_path}: not valid utf-8, undecodable bytes were replaced")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    ignore_file, file_skips = parse_directives(text)
    if ignore_file:
        report.files_ignored += 1
        return
    report.files_scanned += 1
    is_instruction = is_instruction_file(rel_path)
    scan_text(rel_path, text, report, findings, is_instruction, file_skips=file_skips)
    if looks_like_config(rel_path, text) and rel_path.lower().endswith(".json"):
        scan_json_config(rel_path, text, findings, file_skips=file_skips)


def iter_files(root, report):
    for current, dirnames, filenames in os.walk(root, onerror=lambda err: report.warnings.append(f"{err.filename}: cannot walk ({err.strerror})")):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
        for name in sorted(filenames):
            full = os.path.join(current, name)
            if os.path.islink(full):
                report.warnings.append(f"{os.path.relpath(full, root)}: skipped, symbolic link")
                report.files_skipped += 1
                continue
            rel = os.path.relpath(full, root)
            yield rel, full


def scan_tree(root, min_severity=LOW):
    # Scan root and return a Report. Raises ValueError when root is not a directory.
    if not os.path.isdir(root):
        raise ValueError(f"not a directory: {root}")
    report = Report(os.path.abspath(root))
    findings = {}
    for rel_path, full_path in iter_files(root, report):
        scan_file(rel_path, full_path, report, findings)
    floor = SEVERITY_RANK[min_severity]
    report.findings = sorted(
        (finding for finding in findings.values() if SEVERITY_RANK[finding.severity] >= floor),
        key=lambda finding: finding.sort_key(),
    )
    return report
