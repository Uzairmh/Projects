
# PII Redactor Lite

_A project that detects and redacts common UK PII in text-like files, and generates a report._

- Scans `.txt`, `.csv`, and `.md` files for common UK PII patterns: **emails**, **UK mobile numbers**, **UK postcodes**, **National Insurance numbers**, and **NHS numbers** (pattern-based).
- Creates **redacted copies** (mask or hash mode).
- Produces a **JSON** and optional **HTML report** summarising findings per file and per PII type.

> ⚠️ Detection is heuristic and pattern-based; it may produce false positives/negatives. Always manually review.

## Quickstart

```bash
python -m venv .venv
# On Windows: .venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate

# No external deps required; stdlib only
python -m pii_redactor_lite.cli --in sample_data --out redacted --json report.json --html report.html
open report.html  # macOS
# or: start report.html  # Windows
```

### Modes
- `--mode mask` (default): masks sensitive values (e.g., `john@example.com` -> `***@example.com`).
- `--mode hash --salt <secret>`: replaces matched values with a SHA-256 hash (useful for pseudonymisation).

## Example
Sample inputs are in `sample_data/`. After running, see `redacted/` for masked files and `report.html` for a summary.

## Project Structure
```
pii-redactor-lite/
├─ pii_redactor_lite/
│  ├─ __init__.py
│  ├─ detectors.py        # Regex patterns + masking
│  ├─ redactor.py         # Core processing
│  └─ cli.py              # Command-line interface
├─ sample_data/
│  ├─ contacts.txt
│  └─ leads.csv
├─ tests/
│  └─ test_detectors.py
└─ README.md
```
