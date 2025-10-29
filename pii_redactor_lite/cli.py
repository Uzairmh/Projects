
import argparse
from pathlib import Path
from .redactor import process_path
from .report import render_html_report, write_json_report

def main():
    p = argparse.ArgumentParser(description="PII Redactor Lite: scan and redact basic PII in text-like files.")
    p.add_argument("--in", dest="in_path", required=True, help="Input file or directory")
    p.add_argument("--out", dest="out_dir", required=True, help="Output directory for redacted files")
    p.add_argument("--mode", choices=["mask", "hash"], default="mask", help="Redaction mode")
    p.add_argument("--salt", default="", help="Optional salt for hash mode")
    p.add_argument("--json", dest="json_report", default="", help="Path to JSON report to write")
    p.add_argument("--html", dest="html_report", default="", help="Path to HTML report to write")

    args = p.parse_args()

    report = process_path(args.in_path, args.out_dir, mode=args.mode, salt=args.salt)

    if args.json_report:
        write_json_report(report, args.json_report)
    if args.html_report:
        render_html_report(report, args.html_report)

    # Basic console output
    total = sum(report["summary"].values()) if report["summary"] else 0
    print(f"Processed {len(report['files'])} file(s), found {total} potential PII item(s).")

if __name__ == "__main__":
    main()
