
from typing import Dict, List, Tuple
from pathlib import Path
import json
import re
import hashlib
from .detectors import DETECTORS

def iter_text_files(root: Path, extensions=(".txt", ".csv", ".md")):
    root = Path(root)
    if root.is_file():
        if root.suffix.lower() in extensions:
            yield root
        return
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in extensions:
            yield p

def _hash_value(val: str, salt: str) -> str:
    h = hashlib.sha256()
    h.update((salt + val).encode("utf-8"))
    return h.hexdigest()

def redact_text(content: str, mode: str = "mask", salt: str = "") -> Tuple[str, List[Dict]]:
    """Return redacted content and findings list"""
    findings: List[Dict] = []
    redacted = content

    # We apply replacements sequentially and collect findings based on original content
    for det in DETECTORS:
        matches = list(det.regex.finditer(content))
        for m in matches:
            val = m.group(0)
            findings.append({
                "type": det.name,
                "value": val,
                "start": m.start(),
                "end": m.end(),
                "severity": det.severity,
            })

        def repl(match):
            val = match.group(0)
            if mode == "mask":
                return det.mask_func(val)
            elif mode == "hash":
                return _hash_value(val, salt or "pii-redactor-lite")
            else:
                return "[REDACTED]"

        redacted = re.sub(det.regex, repl, redacted)

    return redacted, findings

def process_path(in_path, out_dir, mode="mask", salt=""):
    in_path = Path(in_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary: Dict[str, int] = {}
    file_reports = []

    for f in iter_text_files(in_path):
        txt = f.read_text(encoding="utf-8", errors="ignore")
        redacted, findings = redact_text(txt, mode=mode, salt=salt)

        # write redacted file preserving relative structure
        rel = f.name if in_path.is_file() else f.relative_to(in_path)
        out_file = out_dir / rel
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(redacted, encoding="utf-8")

        # update summary
        per_type = {}
        for item in findings:
            summary[item["type"]] = summary.get(item["type"], 0) + 1
            per_type[item["type"]] = per_type.get(item["type"], 0) + 1

        file_reports.append({
            "file": str(f),
            "out_file": str(out_file),
            "counts": per_type,
            "total_findings": len(findings),
        })

    return {"summary": summary, "files": file_reports}
