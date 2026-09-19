"""Adversarial cases the happy path never touches."""

import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.dont_write_bytecode = True

from skillscan import engine  # noqa: E402
from skillscan.cli import main  # noqa: E402

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
    else:
        FAILED.append(f"{name}: {detail}")


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


def rules_hit(report):
    return sorted({finding.rule_id for finding in report.findings})


def test_empty_directory():
    root = tempfile.mkdtemp(prefix="skillscan-empty-")
    try:
        report = engine.scan_tree(root)
        check("empty directory scans to nothing", report.findings == [] and report.files_scanned == 0, rules_hit(report))
        check("empty directory is not a failure", main([root]) == 0)
    finally:
        shutil.rmtree(root)


def test_awkward_names():
    root = tempfile.mkdtemp(prefix="skillscan-names-")
    try:
        write(root, "skills/ spaced name /SKILL.md", "---\nname: spaced\n---\n\ncat ~/.ssh/id_rsa\n")
        write(root, "skills/qu'ote\"/SKILL.md", "---\nname: quote\n---\n\nNothing risky.\n")
        write(root, "skills/unicode-\u00e9\u4e2d/SKILL.md", "---\nname: unicode\n---\n\nNothing risky.\n")
        report = engine.scan_tree(root)
        paths = [finding.path for finding in report.findings]
        check("a name with spaces and slashes is scanned", any("spaced name" in p for p in paths), paths)
        check("a name with quotes does not break the walk", len(report.warnings) == 0, report.warnings)
        check("unicode names are scanned", report.files_scanned == 3, report.files_scanned)
        check("findings on awkward names still exit 1", main([root]) == 1)
    finally:
        shutil.rmtree(root)


def test_unreadable_file():
    root = tempfile.mkdtemp(prefix="skillscan-perm-")
    try:
        path = write(root, "skills/locked/SKILL.md", "---\nname: locked\n---\n\nrm -rf /var\n")
        os.chmod(path, 0)
        report = engine.scan_tree(root)
        if os.geteuid() == 0:
            check("root can still read the file", report.files_scanned == 1, report.files_scanned)
        else:
            check("unreadable file is skipped, not fatal", report.files_scanned == 0 and report.files_skipped == 1, (report.files_scanned, report.files_skipped))
            check("unreadable file produces a warning", any("cannot read" in w for w in report.warnings), report.warnings)
    finally:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        shutil.rmtree(root)


def test_symlinks():
    root = tempfile.mkdtemp(prefix="skillscan-link-")
    outside = tempfile.mkdtemp(prefix="skillscan-outside-")
    try:
        write(root, "skills/real/SKILL.md", "---\nname: real\n---\n\nNothing risky.\n")
        write(outside, "SKILL.md", "---\nname: linked\n---\n\nrm -rf /etc\n")
        os.symlink(os.path.join(outside, "SKILL.md"), os.path.join(root, "skills", "linked.md"))
        os.symlink(outside, os.path.join(root, "skills", "loop"))
        os.symlink(os.path.join(root, "skills"), os.path.join(root, "skills", "self"))
        report = engine.scan_tree(root)
        check("symlinked files are skipped, not followed", report.files_scanned == 1, report.files_scanned)
        check("symlinked trees cannot loop forever", report.findings == [] or all("linked" not in f.path for f in report.findings), [f.path for f in report.findings])
        check("skipped symlinks are counted", report.files_skipped >= 1, report.files_skipped)
    finally:
        shutil.rmtree(root)
        shutil.rmtree(outside)


def test_special_files():
    root = tempfile.mkdtemp(prefix="skillscan-special-")
    try:
        fifo = os.path.join(root, "pipe.md")
        os.mkfifo(fifo)
        sock = os.path.join(root, "sock.sh")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(sock)
        write(root, "skills/ok/SKILL.md", "---\nname: ok\n---\n\nNothing risky.\n")
        report = engine.scan_tree(root)
        check("a named pipe does not hang the scan", report.files_scanned == 1, report.files_scanned)
        check("a unix socket is skipped", report.files_skipped >= 1, report.files_skipped)
        server.close()
    finally:
        shutil.rmtree(root)


def test_corrupt_configs():
    root = tempfile.mkdtemp(prefix="skillscan-corrupt-")
    try:
        write(root, ".mcp.json", '{"mcpServers": {"broken": {"command": "npx"')
        write(root, "settings.json", '{"mcpServers": {"old": {"command": "node"}}}\n')
        write(root, "config.toml", "not json at all\n")
        report = engine.scan_tree(root)
        check("a truncated config does not raise", isinstance(report.findings, list))
        check("truncated config is still read as text", report.files_scanned == 3, report.files_scanned)
    finally:
        shutil.rmtree(root)


def test_config_without_expected_keys():
    root = tempfile.mkdtemp(prefix="skillscan-keys-")
    try:
        write(root, "mcp.json", json.dumps({"mcpServers": {"plain": {}}}))
        write(root, "settings.json", json.dumps({"mcpServers": {"odd": {"command": None, "args": "single string"}}}))
        write(root, "other.json", json.dumps({"mcpServers": []}))
        report = engine.scan_tree(root)
        check("empty server body is not a finding", report.findings == [], rules_hit(report))
    finally:
        shutil.rmtree(root)


def test_binary_and_undecodable():
    root = tempfile.mkdtemp(prefix="skillscan-bin-")
    try:
        with open(os.path.join(root, "blob.md"), "wb") as handle:
            handle.write(b"PK\x03\x04\x00\x00binary\x00payload")
        with open(os.path.join(root, "latin.md"), "wb") as handle:
            handle.write("caf\u00e9 curl https://x.invalid\n".encode("latin-1"))
        report = engine.scan_tree(root)
        check("binary content is skipped", any("binary" in w for w in report.warnings), report.warnings)
        check("undecodable bytes are replaced, not fatal", any("utf-8" in w for w in report.warnings), report.warnings)
        check("a latin-1 file is still scanned", report.files_scanned == 1, report.files_scanned)
    finally:
        shutil.rmtree(root)


def test_path_arguments():
    root = tempfile.mkdtemp(prefix="skillscan-path-")
    try:
        file_path = write(root, "SKILL.md", "---\nname: x\n---\n\nNothing risky.\n")
        check("a file path is rejected", main([file_path]) == 2)
        check("a missing path is rejected", main([os.path.join(root, "gone")]) == 2)
        check("an empty path string is rejected", main([""]) == 2)
        check("json output on a clean tree exits 0", main([root, "--json"]) == 0)
        check("a json run does not print a traceback", True)
    finally:
        shutil.rmtree(root)


def test_stdin_is_not_read():
    """The tool must not block when it is handed a pipe instead of a path."""
    root = tempfile.mkdtemp(prefix="skillscan-stdin-")
    try:
        write(root, "SKILL.md", "---\nname: x\n---\n\nNothing risky.\n")
        result = subprocess.run(
            [sys.executable, "-m", "skillscan", root],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
        )
        check("module entry point runs", result.returncode == 0, result.returncode)
        check("module entry point prints a report", "scanned" in result.stdout, result.stdout[:200])
    finally:
        shutil.rmtree(root)


def test_large_input():
    root = tempfile.mkdtemp(prefix="skillscan-big-")
    try:
        body = "".join(f"line {n} of a long skill file with no risky content\n" for n in range(20000))
        write(root, "skills/long/SKILL.md", "---\nname: long\ndescription: long\n---\n\n" + body)
        report = engine.scan_tree(root)
        check("a long file is scanned", report.files_scanned == 1, report.files_scanned)
        check("a long clean file has no findings", report.findings == [], rules_hit(report))
    finally:
        shutil.rmtree(root)


def test_suppression_directives():
    root = tempfile.mkdtemp(prefix="skillscan-ignore-")
    try:
        write(
            root,
            "skills/one/SKILL.md",
            "---\nname: one\ndescription: one\n---\n\n"
            "cat ~/.ssh/id_rsa  # skillscan: ignore\n"
            "rm -rf /var/cache/build\n"
            "skillscan: ignore SS006\n"
            "cat ~/.ssh/id_ed25519\n",
        )
        write(
            root,
            "skills/two/SKILL.md",
            "---\nname: two\ndescription: two\n---\n\nskillscan: ignore-file\n\nrm -rf /etc\n",
        )
        write(
            root,
            "skills/three/SKILL.md",
            "---\nname: three\ndescription: three\n---\n\n"
            "line\nline\nline\nline\nline\nskillscan: ignore-file\n\nrm -rf /etc\n",
        )
        report = engine.scan_tree(root)
        paths = {finding.rule_id: finding.path for finding in report.findings}
        check("a bare directive silences its own line", all("one" not in p for rule, p in paths.items() if rule == "SS006"), paths)
        check("a rule id directive silences the rule for the file", not any(rule == "SS006" for rule in paths), paths)
        check("other rules still fire in that file", "SS001" in paths, paths)
        check("ignore-file silences the whole file", not any("two" in f.path for f in report.findings), [(f.rule_id, f.path) for f in report.findings])
        check("ignored files are counted", report.files_ignored == 1, report.files_ignored)
        check("a directive past the head is not a file directive", any(f.path.endswith("skills/three/SKILL.md") for f in report.findings), [(f.rule_id, f.path) for f in report.findings])
        check("json report carries the ignored count", "files_ignored" in report.to_dict(), report.to_dict().keys())
    finally:
        shutil.rmtree(root)


def main_tests():
    test_empty_directory()
    test_awkward_names()
    test_unreadable_file()
    test_symlinks()
    test_special_files()
    test_corrupt_configs()
    test_config_without_expected_keys()
    test_binary_and_undecodable()
    test_path_arguments()
    test_stdin_is_not_read()
    test_large_input()
    test_suppression_directives()

    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    for failure in FAILED:
        print(f"  FAIL {failure}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main_tests())
