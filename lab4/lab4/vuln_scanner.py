#!/usr/bin/env python3
"""
vuln_scanner.py
Simple multi-language static vulnerability pattern scanner.

Usage:
    python vuln_scanner.py -p /path/to/project -o report.json --format json
    python vuln_scanner.py -f some_file.py
"""

import re
import os
import argparse
import json
import csv
import sys
from dataclasses import dataclass, asdict
from typing import List, Optional, Pattern, Dict
from pathlib import Path
import multiprocessing
import traceback
import ast
import datetime

# -----------------------
# Rule data model
# -----------------------
@dataclass
class Rule:
    id: str
    description: str
    severity: str  # e.g., HIGH, MEDIUM, LOW
    pattern: Optional[str] = None  # regex string
    regex: Optional[Pattern] = None  # compiled regex (filled in)
    language: Optional[List[str]] = None  # hint: ["python","js","all"]
    suggestion: Optional[str] = None

# -----------------------
# Built-in rules
# -----------------------
# These are heuristics — extend freely.
RULES: List[Rule] = [
    Rule(
        id="R001",
        description="Hardcoded credential or password assignment",
        severity="HIGH",
        pattern=r"(password|passwd|pwd|secret|api_key|apikey|access_key|auth_token)\s*(?:[:=]\s*|\"|\')\s*([A-Za-z0-9_\-]{6,})",
        suggestion="Avoid hardcoding credentials. Use environment variables or secrets manager."
    ),
    Rule(
        id="R002",
        description="Possible AWS secret or access key (looks like AWS key)",
        severity="HIGH",
        pattern=r"AKIA[0-9A-Z]{16}",
        suggestion="Rotate and use IAM roles or env vars instead of embedding keys."
    ),
    Rule(
        id="R003",
        description="Use of eval or exec (Python)",
        severity="HIGH",
        pattern=r"\beval\s*\(|\bexec\s*\(",
        language=["python"],
        suggestion="Avoid eval/exec; use safer parsing or literal_eval."
    ),
    Rule(
        id="R004",
        description="pickle.loads or insecure deserialization (Python)",
        severity="HIGH",
        pattern=r"\bpickle\.(loads|load)\s*\(",
        language=["python"],
        suggestion="Avoid untrusted pickle data; use safer serialization formats (JSON)."
    ),
    Rule(
        id="R005",
        description="Subprocess with shell=True or system() call (possible command injection)",
        severity="HIGH",
        pattern=r"\b(subprocess\.Popen|subprocess\.call|os\.system|popen)\s*\(",
        suggestion="Avoid shell=True or passing unsanitized input to shell. Use list args."
    ),
    Rule(
        id="R006",
        description="HTTP request with verify=False (insecure TLS validation)",
        severity="HIGH",
        pattern=r"\bverify\s*=\s*False\b",
        suggestion="Do not disable TLS verification in production."
    ),
    Rule(
        id="R007",
        description="Use of weak hashing algorithms (MD5/SHA1)",
        severity="MEDIUM",
        pattern=r"\b(md5|sha1|unhexlify\(|hashlib\.(md5|sha1))\b",
        suggestion="Use SHA-256 or stronger & use HMAC when appropriate."
    ),
    Rule(
        id="R008",
        description="SQL-like string concatenation (possible SQL injection)",
        severity="HIGH",
        pattern=r"(SELECT|INSERT|UPDATE|DELETE).{0,200}(\+|%s|\%|\{\s*[^}]+\s*\})",
        suggestion="Use parameterized queries / prepared statements instead of string concatenation."
    ),
    Rule(
        id="R009",
        description="Use of HTTP (not HTTPS) in URLs",
        severity="MEDIUM",
        pattern=r"http://[^\s'\"<>]+",
        suggestion="Prefer HTTPS URLs; avoid sending secrets over HTTP."
    ),
    Rule(
        id="R010",
        description="Possible private key material in file (BEGIN PRIVATE KEY / RSA PRIVATE KEY)",
        severity="HIGH",
        pattern=r"-----BEGIN (RSA )?PRIVATE KEY-----",
        suggestion="Don’t commit private keys. Use secrets manager and .gitignore."
    ),
    Rule(
        id="R011",
        description="Hardcoded JWT secret-like strings or token=xxx",
        severity="HIGH",
        pattern=r"(jwt_secret|secret_key|SECRET_KEY)\s*(?:[:=]\s*|\"|\')([A-Za-z0-9_\-]{8,})",
        suggestion="Store secrets outside code."
    ),
    Rule(
        id="R012",
        description="Use of insecure randomness (random.random() for security-sensitive use)",
        severity="MEDIUM",
        pattern=r"\brandom\.random\s*\(",
        suggestion="Use secrets module or os.urandom for cryptographic randomness."
    ),
    Rule(
        id="R013",
        description="Possible XSS: inserting raw user input into HTML or innerHTML",
        severity="HIGH",
        pattern=r"innerHTML\s*=|\bdocument\.write\s*\(",
        language=["javascript","all"],
        suggestion="Sanitize or escape user inputs before inserting into HTML."
    ),
    # Add more rules here...
]

# precompile regexes
for r in RULES:
    if r.pattern:
        try:
            r.regex = re.compile(r.pattern, flags=re.IGNORECASE | re.DOTALL)
        except Exception as e:
            print(f"Failed to compile pattern for {r.id}: {e}", file=sys.stderr)

# -----------------------
# Scanner implementation
# -----------------------
@dataclass
class Finding:
    file: str
    line_no: int
    snippet: str
    rule_id: str
    rule_desc: str
    severity: str
    suggestion: Optional[str]

def scan_file_text(path: Path, text: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = text.splitlines()
    joined_text = text
    # line offsets for match to line number mapping
    for rule in RULES:
        # skip language-specific rules if file extension not matching
        if rule.language:
            # infer language from extension
            ext = path.suffix.lower().lstrip('.')
            lang_map = {
                'py': 'python', 'js': 'javascript', 'jsx': 'javascript', 'ts': 'typescript',
                'java': 'java', 'rb': 'ruby', 'php': 'php', 'go': 'go', 'rs': 'rust'
            }
            file_lang = lang_map.get(ext, 'all')
            if 'all' not in rule.language and file_lang not in rule.language:
                continue

        if rule.regex is None:
            continue
        for m in rule.regex.finditer(joined_text):
            start = m.start()
            # compute line number
            line_no = joined_text.count("\n", 0, start) + 1
            # snippet (line)
            snippet = lines[line_no-1].strip() if 0 <= line_no-1 < len(lines) else (m.group(0)[:200] + "...")
            findings.append(Finding(
                file=str(path),
                line_no=line_no,
                snippet=snippet,
                rule_id=rule.id,
                rule_desc=rule.description,
                severity=rule.severity,
                suggestion=rule.suggestion
            ))
    return findings

def scan_file_ast_python(path: Path, text: str) -> List[Finding]:
    """Extra checks using Python AST to reduce false positives for Python files."""
    findings: List[Finding] = []
    try:
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return findings  # parsing failed -> skip AST checks

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call):
            try:
                func = node.func
                # detect eval/exec direct calls
                if isinstance(func, ast.Name) and func.id in ('eval', 'exec'):
                    findings.append(Finding(
                        file=str(path),
                        line_no=node.lineno,
                        snippet=ast.get_source_segment(text, node).strip() if ast.get_source_segment(text, node) else func.id,
                        rule_id="R003",
                        rule_desc="Use of eval/exec (AST detected)",
                        severity="HIGH",
                        suggestion="Avoid eval/exec; use safer parsing or literal_eval."
                    ))
                # detect pickle.load(s)
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == 'pickle' and func.attr in ('loads','load'):
                    findings.append(Finding(
                        file=str(path),
                        line_no=node.lineno,
                        snippet=ast.get_source_segment(text, node).strip() if ast.get_source_segment(text, node) else "pickle.*",
                        rule_id="R004",
                        rule_desc="pickle.loads or load (insecure deserialization)",
                        severity="HIGH",
                        suggestion="Avoid untrusted pickle data."
                    ))
                # detect subprocess with shell=True
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == 'subprocess' and func.attr in ('Popen','call','run'):
                    # check keywords
                    for kw in node.keywords:
                        if getattr(kw, 'arg', None) == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append(Finding(
                                file=str(path),
                                line_no=node.lineno,
                                snippet=ast.get_source_segment(text, node).strip() if ast.get_source_segment(text, node) else "subprocess.*(shell=True)",
                                rule_id="R005",
                                rule_desc="subprocess called with shell=True",
                                severity="HIGH",
                                suggestion="Avoid shell=True; use list args."
                            ))
            except Exception:
                pass
            self.generic_visit(node)

    Visitor().visit(tree)
    return findings

def scan_path(path: Path, include_exts: Optional[List[str]] = None, skip_dirs: Optional[List[str]] = None) -> List[Finding]:
    if skip_dirs is None:
        skip_dirs = ['.git', 'node_modules', '__pycache__', 'venv', '.venv']
    findings: List[Finding] = []
    if path.is_file():
        files = [path]
    else:
        files = []
        for root, dirs, filenames in os.walk(path):
            # prune dirs
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fn in filenames:
                fpath = Path(root) / fn
                if include_exts:
                    if fpath.suffix.lower().lstrip('.') not in include_exts:
                        continue
                files.append(fpath)

    # parallel scanning
    cpu = max(1, multiprocessing.cpu_count() - 1)
    pool = multiprocessing.Pool(processes=min(cpu, 8))
    jobs = []
    for f in files:
        # only scan text files (try to decode)
        jobs.append(pool.apply_async(scan_single_file_job, (str(f),)))
    pool.close()
    for j in jobs:
        try:
            res: List[Finding] = j.get(timeout=30)
            findings.extend(res)
        except Exception as e:
            # if job failed, include the traceback as LOW severity finding
            tb = traceback.format_exc()
            findings.append(Finding(
                file="internal",
                line_no=0,
                snippet=str(e)[:200],
                rule_id="ERR001",
                rule_desc="Scanner internal error",
                severity="LOW",
                suggestion=tb
            ))
    pool.join()
    return sorted(findings, key=lambda x: (x.severity, x.file, x.line_no), reverse=True)

def scan_single_file_job(file_path: str) -> List[Finding]:
    p = Path(file_path)
    try:
        raw = p.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return []
    findings = scan_file_text(p, raw)
    # python specific AST checks
    if p.suffix.lower() == '.py':
        findings.extend(scan_file_ast_python(p, raw))
    return findings

# -----------------------
# Output helpers
# -----------------------
def print_findings(findings: List[Finding]):
    if not findings:
        print("No suspicious findings detected. (Not a proof of secure code.)")
        return
    severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    findings_sorted = sorted(findings, key=lambda f: (severity_order.get(f.severity,0), f.file, f.line_no), reverse=True)
    for f in findings_sorted:
        print(f"[{f.severity}] {f.rule_id} — {f.rule_desc}")
        print(f"  File: {f.file}:{f.line_no}")
        print(f"  Snippet: {f.snippet}")
        if f.suggestion:
            print(f"  Suggestion: {f.suggestion}")
        print("-" * 60)

def export_findings(findings: List[Finding], out_path: Path, fmt: str):
    data = [asdict(f) for f in findings]
    if fmt == 'json':
        out_path.write_text(json.dumps({
            "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
            "findings": data
        }, indent=2), encoding='utf-8')
        print(f"Wrote JSON report to {out_path}")
    elif fmt == 'csv':
        with out_path.open('w', newline='', encoding='utf-8') as fh:
            writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()) if data else ['file','line_no','snippet','rule_id','rule_desc','severity','suggestion'])
            writer.writeheader()
            for d in data:
                writer.writerow(d)
        print(f"Wrote CSV report to {out_path}")
    else:
        raise ValueError("Unsupported format: " + fmt)

# -----------------------
# CLI
# -----------------------
def parse_args():
    p = argparse.ArgumentParser(description="Simple Vulnerability Pattern Scanner")
    p.add_argument('-p', '--path', default='.', help='Path to file or project root to scan (default: current dir)')
    p.add_argument('-o', '--output', default=None, help='Output report file (optional). If not provided, no file is written.')
    p.add_argument('--format', choices=['json','csv'], default='json', help='Report format (json/csv)')
    p.add_argument('--ext', nargs='*', help='Only include these file extensions (without dot). Example: py js java')
    p.add_argument('--skip', nargs='*', help='Directories to skip (default: .git node_modules venv __pycache__)')
    p.add_argument('--quiet', action='store_true', help='Minimal console output')
    return p.parse_args()

def main():
    args = parse_args()
    target = Path(args.path).resolve()
    if not target.exists():
        print("Path does not exist:", target, file=sys.stderr)
        sys.exit(2)

    print(f"Scanning {target} ...")
    findings = scan_path(target, include_exts=args.ext, skip_dirs=args.skip)
    if not args.quiet:
        print_findings(findings)
    if args.output:
        outp = Path(args.output)
        export_findings(findings, outp, args.format)
    else:
        print(f"Total findings: {len(findings)}")

if __name__ == '__main__':
    main()
