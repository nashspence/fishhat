"""Conservative public-tree/history guard. Complements, not replaces, secret scanning."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAGE-SECRET-KEY-1[0-9A-Z]{30,}\b"),
]
BLOCKED_PARTS = {
    ".ssh",
    ".env",
    "baseline",
    "historical",
    "history",
    "audit",
    "docs",
    "plan",
    "evidence",
    "node_modules",
}
BLOCKED_SUFFIX = {
    ".age",
    ".pem",
    ".key",
    ".bundle",
    ".sqlite",
    ".db",
    ".zip",
    ".gz",
    ".pdf",
    ".docx",
    ".md",
}
ALLOWED_DOMAINS = {
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "docs.github.com",
    "json-schema.org",
    "www.rfc-editor.org",
    "pypi.org",
    "files.pythonhosted.org",
    "localhost",
    "www.apache.org",
    "apache.org",
    "mise.jdx.dev",
    "docs.ansible.com",
    "pyinfra.com",
    "kamal-deploy.org",
    "komo.do",
    "coolify.io",
    "doc.yunohost.org",
}


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT, stderr=subprocess.DEVNULL)


def concrete_host_allowed(host: str) -> bool:
    if (
        host in ALLOWED_DOMAINS
        or host.endswith((".invalid", ".example", ".test"))
        or host in {"example.com", "example.org", "example.net"}
    ):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or any(
            ip in ipaddress.ip_network(n)
            for n in (
                ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "169.254.169.254/32"]
                if ip.version == 4
                else ["2001:db8::/32"]
            )
        )
    except ValueError:
        return False


def check_text(
    name: str, text: str, extra_terms: Sequence[str] = (), *, git_commit: bool = False
) -> list[str]:
    problems = []
    for regex in SECRET_PATTERNS:
        if regex.search(text):
            problems.append(f"{name}: secret-shaped value")
    for term in extra_terms:
        if term.lower() in text.lower():
            problems.append(f"{name}: private denylist match")
    for raw in re.findall(r'(?:https?|ssh)://[^\s<>"\'`]+', text):
        raw = raw.rstrip(").,;:\u2060")
        # Regexes/grammar fragments are not concrete destinations.
        if any(c in raw for c in ("\\", "[", "]", "{", "}", "^", "$", "|")):
            continue
        try:
            host = urlsplit(raw).hostname
            if host and "." in host and not concrete_host_allowed(host):
                problems.append(f"{name}: non-example network destination")
        except ValueError:
            pass
    email_text = text
    if git_commit:
        headers, separator, message = text.partition("\n\n")
        headers = re.sub(
            r"^(?:author|committer) [^<>\n]+ <[^<>\n]+> [0-9]+ [+-][0-9]{4}$",
            "",
            headers,
            flags=re.MULTILINE,
        )
        message = re.sub(
            r"^Signed-off-by: dependabot\[bot\] <support@github\.com>$",
            "",
            message,
            flags=re.MULTILINE,
        )
        email_text = headers + separator + message
    for email in re.findall(r"(?<![\w.+-])[\w.+-]+@([\w.-]+\.[A-Za-z]{2,})", email_text):
        if not (
            email.endswith((".invalid", ".example", ".test", "users.noreply.github.com"))
            or email in {"example.com", "example.org", "example.net"}
        ):
            problems.append(f"{name}: non-example email/SSH domain")
    return problems


def run(history: bool = False, denylist: str | None = None) -> int:
    terms = json.loads(Path(denylist).read_text()) if denylist else []
    problems = []
    objects = 0
    try:
        names = [x.decode() for x in git("ls-files", "-z").split(b"\0") if x]
    except subprocess.CalledProcessError:
        names = [
            str(p.relative_to(ROOT))
            for p in ROOT.rglob("*")
            if p.is_file()
            and not any(
                x in p.parts
                for x in (".git", "__pycache__", ".pytest_cache", ".venv", "build", "dist")
            )
            and not any(x.endswith(".egg-info") for x in p.parts)
        ]
    for name in names:
        p = Path(name)
        if any(part in BLOCKED_PARTS for part in p.parts) or (
            p.suffix in BLOCKED_SUFFIX and name not in {"README.md", "AGENTS.md"}
        ):
            problems.append(f"{name}: forbidden public path")
        full = ROOT / name
        if full.is_symlink():
            problems.append(f"{name}: symbolic link requires review")
            continue
        try:
            text = full.read_text(encoding="utf-8")
        except (UnicodeError, OSError):
            problems.append(f"{name}: unexpected binary/unreadable content")
            continue
        problems += check_text(name, text, terms)
    if history:
        if git("rev-parse", "--is-shallow-repository").strip() != b"false":
            problems.append("history: shallow scan cannot establish full history")
        for line in git("rev-list", "--objects", "--all").decode().splitlines():
            oid = line.split(" ", 1)[0]
            kind = git("cat-file", "-t", oid).decode().strip()
            if kind not in {"blob", "commit", "tag"}:
                continue
            data = git("cat-file", "-p", oid)
            try:
                text = data.decode("utf-8")
            except UnicodeError:
                problems.append("history: unexpected binary object")
                continue
            objects += 1
            problems += check_text("history:" + oid[:12], text, terms, git_commit=kind == "commit")
    if problems:
        print("\n".join(sorted(set(problems))), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "pass",
                "files": len(names),
                "history_objects": objects,
                "scope": "path, destination, denylist and secret-pattern checks; not a guarantee against every disclosure",
            }
        )
    )
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--history", action="store_true")
    p.add_argument("--denylist")
    a = p.parse_args()
    raise SystemExit(run(a.history, a.denylist))
