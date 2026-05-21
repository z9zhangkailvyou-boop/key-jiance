#!/usr/bin/env python3
"""Local secret scanner — detect accidentally committed API keys in your codebase.

Scans the current working tree and optionally git history for patterns
matching common API key formats plus high-entropy strings that look like keys.

Usage:
    python secret-scanner.py                  # scan working tree only
    python secret-scanner.py --git-history    # also scan git commit history
    python secret-scanner.py --entropy 4.0    # adjust entropy threshold (default 4.2)
    python secret-scanner.py --json           # machine-readable JSON output
"""

import argparse
import base64
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# Known API key regex patterns (tuple of name, regex, example)
# ---------------------------------------------------------------------------
PATTERNS: list[tuple[str, str, str]] = [
    # Anthropic (specific, must come before generic "sk-" patterns)
    ("Anthropic API Key", r"sk-ant-api[0-9]{2}-[a-zA-Z0-9_-]{32,128}", "sk-ant-api00-EXAMPLE"),
    # DeepSeek
    ("DeepSeek API Key", r"sk-[a-zA-Z0-9]{32,64}", "sk-EXAMPLE"),
    # OpenAI / Claude (broad catch-all for "sk-..." keys)
    ("OpenAI / Claude API Key", r"sk-[a-zA-Z0-9_-]{32,128}", "sk-proj-EXAMPLE"),
    # GitHub tokens
    ("GitHub Personal Access Token", r"ghp_[a-zA-Z0-9]{36,40}", "ghp_EXAMPLE"),
    ("GitHub OAuth Token", r"gho_[a-zA-Z0-9]{36,40}", "gho_EXAMPLE"),
    ("GitHub App Token", r"ghu_[a-zA-Z0-9]{36,40}", "ghu_EXAMPLE"),
    ("GitHub Refresh Token", r"ghr_[a-zA-Z0-9]{36,40}", "ghr_EXAMPLE"),
    # AWS
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "AKIAEXAMPLE"),
    ("AWS Secret Access Key", r"(?:^|[\s\"'=])(?=[A-Za-z0-9/+]{40})([A-Za-z0-9/+]{40})(?:$|[\s\"'])", "EXAMPLE"),
    # Google Cloud
    ("GCP API Key", r"AIza[0-9A-Za-z\-_]{35}", "AIzaEXAMPLE"),
    # Generic "secret" / "token" / "password" assignments
    ("Generic Secret Assignment", r'(?i)(?:api[_-]?key|secret|token|password|auth)\s*[:=]\s*["\'][\x20-\x7e]{16,}["\']', "API_KEY=EXAMPLE"),
    # Stripe
    ("Stripe Secret Key", r"(?:sk|rk)_(?:live|test)_[a-zA-Z0-9]{24,}", "sk_live_EXAMPLE"),
    # Slack
    ("Slack Bot Token", r"xox[baprs]-[a-zA-Z0-9-]{10,64}", "xoxb-EXAMPLE"),
    # JWT
    ("JSON Web Token", r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "eyJ.EXAMPLE.EXAMPLE"),
    # Generic hex key
    ("Hex Encoded Key", r"(?i)(?:key|secret|token)\s*=\s*[a-f0-9]{32,64}", "secret=EXAMPLE"),
    # Private key header markers
    ("Private Key Block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "-----BEGIN EXAMPLE KEY-----"),
    # Generic base64-looking high-entropy values in assignments
    ("Base64-like Assignment", r'[:=]\s?([A-Za-z0-9+/]{40,}={0,2})', "base64EXAMPLE"),
]

# Max line length to scan (skip minified / binary noise)
MAX_LINE_LENGTH = 1200

# Extensions to skip
SKIP_EXTENSIONS = {
    ".pyc", ".class", ".o", ".obj", ".exe", ".dll", ".so", ".dylib",
    ".jar", ".war", ".ear", ".zip", ".tar", ".gz", ".bz2", ".7z",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".webm",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".db", ".sqlite", ".sqlite3",
    ".pack", ".idx", ".bin",
}

# Paths to skip
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox",
             ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
             ".eggs", ".next", ".nuxt", "vendor", "bower_components"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml",
              "poetry.lock", "Cargo.lock", "Gemfile.lock", "Pipfile.lock",
              "go.sum", "*.min.js", "*.min.css", "*.map"}


def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string. Higher = more random-looking."""
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_high_entropy(token: str, threshold: float = 4.2) -> bool:
    """Check if a substring looks like a high-entropy key.

    Filters out common false positives like git hashes, UUIDs, hex strings
    that are structurally regular.
    """
    token = token.strip().strip("'\"")
    if len(token) < 16:
        return False
    ent = shannon_entropy(token)
    return ent >= threshold


def extract_candidate_tokens(line: str) -> list[tuple[str, int]]:
    """Extract substrings from a line that could be API keys.

    Returns list of (token, start_offset).
    """
    tokens = []
    # Split on common delimiters
    parts = re.split(r'[\s,;(){}\[\]]+', line)
    pos = 0
    for part in parts:
        if not part:
            pos += 1  # skip empty after delim
            continue
        idx = line.index(part, pos) if part in line[pos:] else pos
        clean = part.strip().strip('\'"')
        if len(clean) >= 16 and any(c.isalpha() for c in clean):
            tokens.append((clean, idx))
        pos = idx + len(part)
    return tokens


def should_skip_path(file_path: str) -> bool:
    """Decide if a path should be skipped during scan."""
    path = Path(file_path)
    # Skip dirs
    for part in path.parts:
        if part in SKIP_DIRS:
            return True
    # Skip extensions
    if path.suffix and path.suffix in SKIP_EXTENSIONS:
        return True
    # Skip specific files
    if path.name in SKIP_FILES:
        return True
    # Skip minified files
    if path.suffix in (".min.js", ".min.css") or ".min." in path.name:
        return True
    # Skip binary check
    if path.suffix in {".map", ".wasm", ".pyc"}:
        return True
    return False


def scan_line(line: str, entropy_threshold: float) -> list[dict]:
    """Scan a single line for secrets. Returns list of findings."""
    findings = []
    if not line.strip() or len(line) > MAX_LINE_LENGTH:
        return findings

    # 1. Known pattern matching
    known_ranges: list[tuple[int, int]] = []
    for name, pattern, _example in PATTERNS:
        for m in re.finditer(pattern, line):
            matched = (m.group(1) if m.lastindex else m.group(0)).strip().strip("'\"")
            if len(matched) < 8:
                continue
            start, end = m.start(), m.end()
            # Skip if this range overlaps an earlier (more specific) match
            if any(r_start < end and start < r_end for r_start, r_end in known_ranges):
                continue
            known_ranges.append((start, end))
            findings.append({
                "type": name,
                "severity": "high",
                "match": mask_secret(matched),
                "position": start,
            })

    # 2. High-entropy detection (catchall)
    candidates = extract_candidate_tokens(line)
    for token, offset in candidates:
        if not is_high_entropy(token, entropy_threshold):
            continue
        if token.startswith(("http://", "https://", "/", "./", "../")):
            continue
        if re.fullmatch(r"[0-9a-fA-F]{32,64}", token):
            continue
        # Skip if token overlaps with any known-pattern match
        token_end = offset + len(token)
        if any(r_start < token_end and offset < r_end for r_start, r_end in known_ranges):
            continue
        findings.append({
            "type": "High Entropy String",
            "severity": "medium",
            "match": mask_secret(token),
            "position": offset,
        })

    return findings


def mask_secret(secret: str) -> str:
    """Show first 4 + last 4 characters, middle masked."""
    if len(secret) <= 8:
        return secret[:2] + "*" * (len(secret) - 4) + secret[-2:]
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


def scan_file(file_path: str, entropy_threshold: float) -> list[dict]:
    """Scan a single file, return list of findings with location info."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line_findings = scan_line(line.rstrip("\n\r"), entropy_threshold)
                for f_item in line_findings:
                    f_item["file"] = file_path
                    f_item["line"] = lineno
                findings.extend(line_findings)
    except (PermissionError, OSError):
        pass
    return findings


def scan_working_tree(root: str, entropy_threshold: float) -> list[dict]:
    """Walk the directory tree and scan all eligible files."""
    all_findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Filter dirs in-place for speed
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            if should_skip_path(fpath):
                continue
            all_findings.extend(scan_file(fpath, entropy_threshold))
    return all_findings


def scan_git_history(root: str, entropy_threshold: float) -> list[dict]:
    """Scan git history (commit messages and diffs) for secrets."""
    findings = []
    try:
        # List all commits
        result = subprocess.run(
            ["git", "-C", root, "log", "--all", "--pretty=format:%H"],
            capture_output=True, text=True, check=True,
            timeout=60,
        )
        commits = result.stdout.strip().split("\n")
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return findings

    for commit_hash in commits:
        if not commit_hash.strip():
            continue
        try:
            diff = subprocess.run(
                ["git", "-C", root, "diff-tree", "--no-commit-id", "-r", "-p",
                 "--diff-filter=AM", commit_hash],
                capture_output=True, text=True, check=True,
                timeout=30,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            continue

        for lineno, line in enumerate(diff.stdout.split("\n"), 1):
            # Only scan added lines (lines starting with +, but not +++ header)
            if not line.startswith("+") or line.startswith("+++"):
                continue
            content = line[1:]  # strip the leading +
            line_findings = scan_line(content, entropy_threshold)
            for f_item in line_findings:
                f_item["commit"] = commit_hash[:12]
                f_item["line"] = lineno
            findings.extend(line_findings)

    return findings


def format_finding(f: dict, color: bool = True) -> str:
    """Human-readable single finding."""
    if color:
        RED = "\033[91m"
        YELLOW = "\033[93m"
        CYAN = "\033[96m"
        GRAY = "\033[90m"
        RESET = "\033[0m"
        BOLD = "\033[1m"
    else:
        RED = YELLOW = CYAN = GRAY = BOLD = RESET = ""

    location = f.get("file", f.get("commit", "?"))
    line_info = ""
    if "file" in f:
        line_info = f"{GRAY}:{RESET}{f['line']}"
    elif "commit" in f:
        line_info = f"{GRAY}@{RESET}{f.get('line', '?')}"

    sev_color = RED if f["severity"] == "high" else YELLOW
    return (
        f"  {sev_color}[{f['severity'].upper()}]{RESET} "
        f"{BOLD}{f['type']}{RESET} — "
        f"{f['match']}"
        f"  {GRAY}({location}{line_info}){RESET}"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Secret scanner — detect accidentally committed API keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          scan working tree
  %(prog)s --git-history            scan working tree + git history
  %(prog)s --entropy 3.8 --json     lower entropy threshold, JSON output
  %(prog)s --path ./src             scan a specific directory
        """,
    )
    parser.add_argument("--path", default=".", help="Root path to scan (default: .)")
    parser.add_argument("--git-history", action="store_true", help="Also scan git commit history")
    parser.add_argument("--entropy", type=float, default=4.2, help="Entropy threshold (default: 4.2, lower = more hits)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    root = os.path.abspath(args.path)
    use_color = not args.no_color and sys.stdout.isatty()

    if use_color:
        print(f"\033[1m\033[96mSecret Scanner\033[0m — {root}")
    else:
        print(f"Secret Scanner — {root}")
    print(f"Entropy threshold: {args.entropy}\n")

    # Phase 1: Working tree
    print("Scanning working tree...")
    findings = scan_working_tree(root, args.entropy)

    # Phase 2: Git history (optional)
    if args.git_history:
        if os.path.isdir(os.path.join(root, ".git")):
            print("Scanning git history...")
            git_findings = scan_git_history(root, args.entropy)
            findings.extend(git_findings)
        else:
            msg = "No .git directory found, skipping git history scan."
            if use_color:
                print(f"  \033[93m{msg}\033[0m")
            else:
                print(f"  {msg}")

    # Output
    if args.json:
        safe_findings = []
        for f_item in findings:
            safe = dict(f_item)
            safe["match"] = safe["match"].replace("*", "X")  # restore full match for JSON
            safe_findings.append(safe)
        print(json.dumps(safe_findings, indent=2, default=str))
    else:
        if not findings:
            if use_color:
                print("\033[92m✓ No secrets detected.\033[0m")
            else:
                print("✓ No secrets detected.")
        else:
            # Deduplicate by (file, line, type)
            seen = set()
            unique = []
            for f_item in findings:
                key = (f_item.get("file", f_item.get("commit")), f_item.get("line", 0), f_item["type"], f_item["match"])
                if key not in seen:
                    seen.add(key)
                    unique.append(f_item)

            unique.sort(key=lambda x: (
                x.get("file", x.get("commit", "")),
                x.get("line", 0),
            ))

            for f_item in unique:
                print(format_finding(f_item, color=use_color))

            high = sum(1 for f_item in unique if f_item["severity"] == "high")
            medium = sum(1 for f_item in unique if f_item["severity"] == "medium")
            summary = f"\n{len(unique)} finding(s): {high} high, {medium} medium"
            if use_color:
                print(f"\033[1m{summary}\033[0m")
            else:
                print(summary)

    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
    
EXCLUDE_PATHS = [
    "README.md",  # Documentation with example patterns
]
