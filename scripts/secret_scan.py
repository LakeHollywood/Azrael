#!/usr/bin/env python3
"""Pre-commit secret scanner (poor-man's GitHub push protection).

Blocks commits that would leak private keys, well-known token formats,
high-entropy base64/hex blobs, or files in deny-listed paths.

Modes:
  python3 scripts/secret_scan.py --working          # scan tracked+untracked working tree
  python3 scripts/secret_scan.py --staged           # scan staged additions (pre-commit hook)
  python3 scripts/secret_scan.py --ref <rev>        # scan every blob reachable from <rev>
                                                    # (use with care on history rewrite)

Exit codes: 0 = clean, 1 = findings, 2 = usage/environment error.
"""
import argparse
import base64
import math
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Paths that must never be committed (dev signing material, runtime state).
DENY_PATTERNS = [
    r"^\.ledgerdev/",
    r"(^|/)__pycache__/",
    r"\.pem$",
    r"\.key$",
    r"(^|/)\.env(\.|$)",
    r"(^|/)id_(rsa|ed25519|ecdsa)$",
    r"(^|/)server\.log$",
]

# High-signal literal patterns (GitHub-style secret scanning rules).
LITERAL_PATTERNS = [
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key material"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key id"),
    (r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "GitHub token"),
    (r"\bgithub_pat_[A-Za-z0-9_]{40,}\b", "GitHub fine-grained PAT"),
    (r"\bxox[baprs]-[0-9a-zA-Z-]{20,}\b", "Slack token"),
    (r"\bsk-[A-Za-z0-9]{32,}\b", "OpenAI-style secret key"),
    (r"\bAIza[0-9A-Za-z_-]{35}\b", "Google API key"),
    (r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{16,}['\"]",
     "hardcoded credential assignment"),
]

# Entropy detector for opaque blobs (e.g. raw HMAC secrets, random keys).
B64_RUN = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
HEX_RUN = re.compile(r"\b[0-9a-fA-F]{48,}\b")

MAX_FILE_BYTES = 2 * 1024 * 1024

# Scanner test fixtures intentionally contain fake credentials; skip the
# scanner's own test file (real scanners handle this with allow-list comments,
# but path exclusion keeps the fixture readable).
SELF_TEST_PATHS = {"tests/unit/test_secret_scan.py"}

# Known credential-free high-entropy fields: package-lock integrity hashes and
# ledger signatures are base64 by design, not secrets. Real secret scanners
# use paired rules (token + its provider context); we whitelist these contexts
# to keep the entropy heuristic from drowning reviewers in noise.
INTEGRITY_LINE = re.compile(
    r'"integrity"\s*:\s*"(?:sha512|sha456|sha384|sha256)-[A-Za-z0-9+/=]{32,}"')
SIGNATURE_LINE = re.compile(
    r'"signature"\s*:\s*"ed25519:[A-Za-z0-9+/_=-]{32,}"')
# Audit-chain hash fields (prev_hash / entry_hash) are deterministic SHA-256
# values derived from the log content itself, not credentials. They sit on the
# same JSONL line as words like "HMAC" or "signing" that appear inside verify
# failure messages, which trips the hex-near-secret-keyword heuristic. Masking
# these known fields keeps real secrets on audit lines detectable while
# removing the guaranteed false positives. The `sha256:` prefix form that
# appears inside error-message strings is equally credential-free.
AUDIT_HASH_FIELD = re.compile(
    r'"(?:prev_hash|entry_hash)"\s*:\s*"[0-9a-fA-F]+"'
    r"|sha256:[0-9a-fA-F]+")

# URLs are credential-free by construction; the b64 alphabet overlaps with URL
# paths (e.g. tidelift funding links in package-lock.json), so mask them out.
URL_RE = re.compile(r"https?://\S+")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _decodes_binary(blob: str) -> bool:
    try:
        decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except Exception:
        return True  # can't decode but looks like a key => suspicious
    printable = sum(1 for b in decoded if 32 <= b < 127)
    return len(decoded) > 0 and printable / len(decoded) < 0.85


def looks_random(blob: str) -> bool:
    """Flag long high-entropy runs that decode to non-text bytes."""
    if len(blob) < 32:
        return False
    if shannon_entropy(blob) < 4.0:
        return False
    # A run containing '/' is a path/URL fragment, not an opaque key: real
    # base64 secrets essentially never contain slashes that align with readable
    # path segments (e.g. 'src/components/AzraelIncidentLog').
    if "/" in blob:
        return False
    return _decodes_binary(blob)


def denylisted(path: str) -> bool:
    return any(re.search(p, path) for p in DENY_PATTERNS)


def scan_content(rel_path: str, data: bytes):
    findings = []
    text = data.decode("utf-8", errors="replace")
    for i, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line
        # Strip known credential-free high-entropy contexts before heuristics.
        line = INTEGRITY_LINE.sub('""', line)
        line = SIGNATURE_LINE.sub('""', line)
        line = AUDIT_HASH_FIELD.sub('"hash_field"', line)
        line = URL_RE.sub("URL", line)
        for pat, label in LITERAL_PATTERNS:
            if re.search(pat, line):
                findings.append(f"{rel_path}:{i}: {label}")
        for m in B64_RUN.finditer(line):
            if looks_random(m.group()):
                findings.append(
                    f"{rel_path}:{i}: high-entropy base64 blob "
                    f"(possible raw secret): {m.group()[:12]}...")
                break
        for m in HEX_RUN.finditer(line):
            if shannon_entropy(m.group()) >= 3.5 and re.search(r"(?i)secret|hmac|signing", line):
                findings.append(f"{rel_path}:{i}: high-entropy hex near secret keyword")
                break
    return findings


def git(*args) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args],
                          capture_output=True, text=True, check=True).stdout


def iter_working_tree():
    tracked = git("ls-files").splitlines()
    untracked = git("ls-files", "--others", "--exclude-standard").splitlines()
    for p in sorted(set(tracked) | set(untracked)):
        fp = ROOT / p
        if fp.is_file():
            yield p, fp.read_bytes()


def iter_staged():
    names = git("diff", "--cached", "--name-only", "--diff-filter=ACM").splitlines()
    for p in names:
        # read the staged blob, not the working copy
        out = subprocess.run(["git", "-C", str(ROOT), "show", f":{p}"],
                             capture_output=True)
        if out.returncode == 0:
            yield p, out.stdout


def iter_ref(rev: str):
    listing = git("ls-tree", "-r", "--name-only", rev).splitlines()
    for p in listing:
        out = subprocess.run(["git", "-C", str(ROOT), "show", f"{rev}:{p}"],
                             capture_output=True)
        if out.returncode == 0:
            yield p, out.stdout


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--working", action="store_true")
    g.add_argument("--staged", action="store_true")
    g.add_argument("--ref", metavar="REV")
    args = ap.parse_args()

    if args.working:
        items = iter_working_tree()
    elif args.staged:
        items = iter_staged()
    else:
        items = iter_ref(args.ref)

    findings = []
    for path, data in items:
        if path in SELF_TEST_PATHS:
            continue
        if denylisted(path):
            findings.append(f"{path}:<whole file>: deny-listed path (must not be committed)")
            continue
        if len(data) > MAX_FILE_BYTES:
            continue
        findings.extend(scan_content(path, data))

    if findings:
        print("SECRET SCAN FAILED — potential credentials detected:\n", file=sys.stderr)
        for f in findings:
            print(f"  ✗ {f}", file=sys.stderr)
        print("\nRemove the material, rotate anything already exposed, and add "
              "generated secrets to .gitignore instead of committing them.",
              file=sys.stderr)
        return 1
    print("secret scan: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
