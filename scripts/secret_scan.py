#!/usr/bin/env python3
"""Offline secret scanner (Security.md §17, Development-rules.md §12).

Runs with the standard library only, so it works with no network access — a real
Gitleaks/TruffleHog run happens in CI (see .github/workflows/security.yml) where those
tools are available; this is the local, always-available equivalent.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PATTERNS = {
    "AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Generic API key assignment": re.compile(
        r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{16,}['\"]"),
    "Private key header": re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP|DSA) PRIVATE KEY-----"),
    "JWT-shaped literal": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "Slack token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "Hardcoded password assignment": re.compile(
        r"(?i)password\s*[:=]\s*['\"](?!CHANGE_ME|<|\$\{|\.\.\.)[^'\"]{6,}['\"]"),
}

# Files where matches are expected and known-safe (documentation of the pattern itself,
# or values that are explicitly placeholders).
ALLOWLIST_FILES = {".env.example", "secret_scan.py", "Security.md", "Development-rules.md",
                   "conftest.py"}
# Exact strings that are legitimate, documented demo credentials — never a real secret.
# Named explicitly rather than broadening a pattern, so a *real* password assignment next
# to one of these still gets caught.
ALLOWLIST_VALUES = {"DemoPassw0rd!2026", "TestPassw0rd!2026"}
ALLOWLIST_DIR_PARTS = {".git", "node_modules", "__pycache__", ".pytest_cache", "ledger_data",
                       "htmlcov", ".venv", "venv"}
TEXT_EXTENSIONS = {".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env", ".sh", ".md",
                  ".html", ".css", ".tf", ".tfvars"}


def tracked_files() -> list[Path]:
    """Every file git would track: committed, staged, or untracked-but-not-ignored.

    `git ls-files` alone misses untracked and not-yet-committed files — exactly the
    files a pre-commit hook or a pre-commit-time audit most needs to see. A brand-new
    repository with no commits would otherwise report "clean" having checked nothing.
    """
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT, capture_output=True, text=True, check=True, timeout=15)
        files = [ROOT / line for line in result.stdout.splitlines() if line]
        if files:
            return files
        # An initialised-but-empty git index (no commits, nothing staged) still leaves
        # untracked files invisible to the command above in some git versions; fall
        # through to the filesystem walk rather than report a false "clean".
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return [p for p in ROOT.rglob("*")
            if p.is_file() and not any(part in ALLOWLIST_DIR_PARTS for part in p.parts)]


def scan() -> int:
    findings: list[str] = []
    for path in tracked_files():
        if path.name in ALLOWLIST_FILES or path.suffix not in TEXT_EXTENSIONS:
            continue
        if any(part in ALLOWLIST_DIR_PARTS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for label, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                if any(value in match.group(0) for value in ALLOWLIST_VALUES):
                    continue
                line = text.count("\n", 0, match.start()) + 1
                findings.append(f"{path.relative_to(ROOT)}:{line}  [{label}]  "
                               f"{match.group(0)[:60]}")

    if findings:
        print(f"SECRET SCAN: {len(findings)} potential finding(s):\n")
        for finding in findings:
            print(" ", finding)
        return 1
    print(f"SECRET SCAN: clean ({len(tracked_files())} files checked)")
    return 0


if __name__ == "__main__":
    sys.exit(scan())
