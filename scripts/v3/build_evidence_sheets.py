"""Build evidence sheets for the 10 Stage 2 flagged crates from Part C."""

from __future__ import annotations

import json
from pathlib import Path
import re
import requests

ROOT = Path(__file__).resolve().parents[2]
STAGE1_PATH = ROOT / "data" / "prod_v2" / "stage1_results.json"
STAGE2_PATH = ROOT / "data" / "prod_v2" / "stage2_results.json"
OUT_DIR = ROOT / "review" / "evidence_sheets_v35"
OUT_DIR.mkdir(parents=True, exist_ok=True)

CATEGORIES: dict[str, re.Pattern] = {
    "network": re.compile(
        r"\b(reqwest|ureq|hyper|isahc|surf|attohttpc|http_req|curl)\s*::|\b(TcpStream|UdpSocket)\b|\bstd::net::|\btokio::net::"
    ),
    "process_spawn": re.compile(r"\bCommand::new\b|\bprocess::Command\b"),
    "sensitive_paths": re.compile(
        r"authorized_keys|\.ssh\b|id_rsa|id_ed25519|\.aws\b|\.gnupg|\.npmrc|\.cargo/credentials|"
        r"\.env\b|\bwallet\b|keychain|Login Data|\.kube\b",
        re.I,
    ),
    "decode_payload": re.compile(
        r"base64::|from_base64|b64decode|base64_decode|\bdecode_config\b|\bSTANDARD\.decode\b"
    ),
    "fs_walk": re.compile(r"\bwalkdir\b|\bWalkDir\b|\bread_dir\b|\bglob\s*\("),
    "ip_literal_url": re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}"),
}
_COMMENT = re.compile(r"^\s*(//|\*|/\*)")

PROC_MACRO_SUSPICIOUS = ["std::process", "std::net", "std::fs::write", "reqwest", "ureq"]

TARGET_SAMPLES = [
    "prod_pop_0138",
    "prod_pop_0086",
    "prod_pop_0272",
    "prod_rand_0224",
    "prod_rand_0401",
    "prod_rand_0560",
    "prod_rand_0281",
    "prod_rand_0879",
    "prod_rand_0948",
    "prod_rand_0994",
]

def get_crates_io_meta(name: str, version: str) -> dict:
    try:
        url = f"https://crates.io/api/v1/crates/{name}"
        headers = {"User-Agent": "CrateShield-Audit/1.0 (bench@example.com)"}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            c_data = data.get("crate", {})
            v_list = data.get("versions", [])
            v_data = next((v for v in v_list if v.get("num") == version), {})
            return {
                "created_at": c_data.get("created_at"),
                "updated_at": c_data.get("updated_at"),
                "repository": c_data.get("repository"),
                "documentation": c_data.get("documentation"),
                "homepage": c_data.get("homepage"),
                "downloads": c_data.get("downloads"),
                "version_downloads": v_data.get("downloads"),
                "version_created_at": v_data.get("created_at"),
            }
    except Exception as e:
        print(f"Error fetching crates.io for {name}: {e}")
    return {}

def check_osv_vulnerabilities(name: str, version: str) -> list[dict]:
    try:
        url = "https://api.osv.dev/v1/query"
        body = {
            "version": version,
            "package": {"name": name, "ecosystem": "crates.io"},
        }
        r = requests.post(url, json=body, timeout=10)
        if r.status_code == 200:
            return r.json().get("vulns", [])
    except Exception as e:
        print(f"Error checking OSV for {name}: {e}")
    return []

def find_exact_trigger_lines(extracted_path: Path, fired_signals: list[str]) -> list[dict]:
    findings = []
    rs_files = list(extracted_path.rglob("*.rs"))
    
    # Check build.rs triggers
    build_rs_file = extracted_path / "build.rs"
    if "build_rs" in fired_signals and build_rs_file.exists():
        try:
            content = build_rs_file.read_text(encoding="utf-8", errors="ignore")
            for lineno, line in enumerate(content.splitlines(), 1):
                if _COMMENT.match(line):
                    continue
                for pat_name, pat in [
                    ("process_spawn", re.compile(r"Command::new|process::Command")),
                    ("file_write", re.compile(r"fs::write|File::create")),
                    ("network", re.compile(r"TcpStream|reqwest|curl")),
                    ("env_read", re.compile(r'env::var\s*\(\s*"([^"]+)"\)')),
                ]:
                    if pat.search(line):
                        rel = build_rs_file.relative_to(extracted_path)
                        findings.append({
                            "file": str(rel),
                            "line": lineno,
                            "signal": f"build_rs ({pat_name})",
                            "snippet": line.strip()[:200]
                        })
        except Exception:
            pass

    # Check proc-macro triggers
    if "proc_macro" in fired_signals:
        for f in rs_files:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                for lineno, line in enumerate(content.splitlines(), 1):
                    for imp in PROC_MACRO_SUSPICIOUS:
                        if imp in line and not _COMMENT.match(line):
                            rel = f.relative_to(extracted_path)
                            findings.append({
                                "file": str(rel),
                                "line": lineno,
                                "signal": f"proc_macro (suspicious_import: {imp})",
                                "snippet": line.strip()[:200]
                            })
            except Exception:
                pass

    # Check source_scan triggers
    for cat in ["network", "process_spawn", "sensitive_paths", "decode_payload", "fs_walk", "ip_literal_url"]:
        sig_name = f"source_scan.{cat}"
        if sig_name in fired_signals:
            pat = CATEGORIES.get(cat)
            if not pat:
                continue
            cat_matches = 0
            for f in rs_files:
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                    for lineno, line in enumerate(content.splitlines(), 1):
                        if _COMMENT.match(line):
                            continue
                        if pat.search(line):
                            rel = f.relative_to(extracted_path)
                            findings.append({
                                "file": str(rel),
                                "line": lineno,
                                "signal": sig_name,
                                "snippet": line.strip()[:200]
                            })
                            cat_matches += 1
                            if cat_matches >= 5:  # Cap per category to keep readable
                                break
                    if cat_matches >= 5:
                        break
                except Exception:
                    pass
    return findings

def get_declared_purpose_text(extracted_path: Path) -> dict:
    cargo_toml = extracted_path / "Cargo.toml"
    desc = ""
    repo = ""
    readme_name = ""
    readme_text = ""
    if cargo_toml.exists():
        txt = cargo_toml.read_text(encoding="utf-8", errors="ignore")
        for line in txt.splitlines():
            line_str = line.strip()
            if line_str.startswith("description") and "=" in line_str:
                desc = line_str.split("=", 1)[1].strip(" \"'")
            if line_str.startswith("repository") and "=" in line_str:
                repo = line_str.split("=", 1)[1].strip(" \"'")
            if line_str.startswith("readme") and "=" in line_str:
                readme_name = line_str.split("=", 1)[1].strip(" \"'")

    for candidate in [readme_name, "README.md", "README.txt", "readme.md", "README"]:
        if candidate:
            rp = extracted_path / candidate
            if rp.exists():
                readme_text = rp.read_text(encoding="utf-8", errors="ignore")[:1000]
                break

    return {
        "description": desc,
        "repository": repo,
        "readme_excerpt": readme_text.strip()
    }

def determine_task2_severity_note(fired_signals: list[str], reasoning: str, findings: list[dict]) -> str | None:
    comb = " ".join(fired_signals).lower() + " " + reasoning.lower() + " " + " ".join(f["signal"] for f in findings).lower()
    actions = []
    if "fs::write" in comb or "file_write" in comb:
        actions.append("file write")
    if "command" in comb or "process_spawn" in comb or "curl" in comb or "shell" in comb:
        actions.append("command execution")
    if "sensitive_paths" in comb or "credential" in comb or "secrets" in comb or "api_key" in comb:
        actions.append("credential read")

    if actions:
        return f"This crate's flagged behavior, if malicious, would involve: {' / '.join(actions)}."
    return None

def main():
    s1_data = json.load(open(STAGE1_PATH, encoding="utf-8"))
    s2_data = json.load(open(STAGE2_PATH, encoding="utf-8"))

    sheets_meta = []

    for sid in TARGET_SAMPLES:
        c1 = s1_data[sid]
        c2 = s2_data[sid]
        name = c1["name"]
        ver = c1["version"]
        cohort = c1["sample_type"]
        downloads = c1.get("downloads", 0)
        fired_signals = c1.get("fired_signals", [])
        extracted_path = Path(c1["extracted_path"])

        print(f"Processing {sid}: {name} v{ver}...")
        c_io = get_crates_io_meta(name, ver)
        osv_vulns = check_osv_vulnerabilities(name, ver)
        purpose = get_declared_purpose_text(extracted_path)
        findings = find_exact_trigger_lines(extracted_path, fired_signals)

        clf = c2.get("classification", {})
        stage2_verdict = clf.get("verdict", "SUSPICIOUS")
        malware_score = clf.get("malware_score", 0.0)
        reasoning = clf.get("reasoning", "")
        primary_signals = clf.get("primary_signals", [])

        repo_url = c_io.get("repository") or purpose.get("repository") or "None listed"
        crates_io_url = f"https://crates.io/crates/{name}/{ver}"
        docs_rs_url = f"https://docs.rs/{name}/{ver}"

        vuln_status = "None found in OSV/RustSec database"
        if osv_vulns:
            vuln_status = f"FLAGGED: {len(osv_vulns)} advisory/advisories found ({', '.join(v.get('id', '') for v in osv_vulns)})"

        severity_note = determine_task2_severity_note(fired_signals, reasoning, findings)

        sheet_content = f"""# Evidence Sheet: `{name}` (v{ver})

**Sample ID**: `{sid}`  
**Cohort**: `{cohort}`  
**Triage Recommendation**: Pending Human Review  

---

## 1. Package Metadata & Registry Links
* **Crate Name**: `{name}`
* **Version**: `{ver}`
* **crates.io**: [{crates_io_url}]({crates_io_url})
* **docs.rs**: [{docs_rs_url}]({docs_rs_url})
* **Repository**: {f'[{repo_url}]({repo_url})' if repo_url.startswith('http') else repo_url}
* **Downloads**: {downloads:,} total registry downloads ({c_io.get('version_downloads', 'N/A')} for this version)
* **Created Date**: {c_io.get('created_at', 'Unknown')}
* **Last Updated**: {c_io.get('updated_at', 'Unknown')}
* **Vulnerability DB Status (OSV / RustSec)**: {vuln_status}

---

## 2. Severity & Priority Note (Task 2)
{f'> [!WARNING]\n> **Severity Warning**: {severity_note}' if severity_note else '> *Standard Priority*: No high-severity execution/credential vectors detected.'}

---

## 3. Stage 1 Pre-Screen Capability Triggers
* **Fired Signal Categories**: `{', '.join(fired_signals)}`

### Exact Source Trigger Lines:
"""
        if findings:
            sheet_content += "| File | Line | Trigger Rule / Pattern | Matched Source Snippet |\n| :--- | :---: | :--- | :--- |\n"
            for f in findings:
                clean_snippet = f['snippet'].replace('|', '\\|')
                sheet_content += f"| `{f['file']}` | {f['line']} | `{f['signal']}` | `{clean_snippet}` |\n"
        else:
            sheet_content += "*Trigger occurred in whole-crate AST analysis / metadata evaluation (no individual single-line regex snippet matched).*\n"

        sheet_content += f"""
---

## 4. Declared Stated Purpose (Prompt Context)
* **Cargo.toml Description**:  
  > "{purpose.get('description') or 'No description provided in Cargo.toml'}"

* **README Excerpt (as fed to LLM contextual analyzer)**:
```markdown
{purpose.get('readme_excerpt') or 'No README file present in extracted archive.'}
```

---

## 5. Stage 2 Verbatim LLM Evaluation (`gemini-3.5-flash-lite`)
* **Stage 2 Verdict**: `{stage2_verdict}`
* **Malware Score**: `{malware_score}`
* **Primary Signals Cited by Model**: `{', '.join(primary_signals) if primary_signals else 'None'}`
* **Verbatim Reasoning**:
> {reasoning}

---

## 6. Human Reviewer Verdict Block
* **Reviewer Decision**:
  - [ ] **TRUE POSITIVE (Malicious)**
  - [ ] **FALSE POSITIVE (Benign)**
  - [ ] **UNSURE / AMBIGUOUS**
* **Reviewer Notes & Justification**:
  ```text

  ```
"""
        out_file = OUT_DIR / f"{name}.md"
        out_file.write_text(sheet_content, encoding="utf-8")
        print(f"Wrote {out_file}")

        sheets_meta.append({
            "sid": sid,
            "name": name,
            "ver": ver,
            "cohort": cohort,
            "downloads": downloads,
            "signals": fired_signals,
            "stage2_verdict": stage2_verdict,
            "malware_score": malware_score,
            "severity_note": severity_note,
            "file": f"{name}.md",
        })

    # Generate INDEX.md
    index_content = """# Human Review Package: Stage 2 Flagged Crates (v3.5)

**Total Flagged Crates**: 10  
**Cohort Split**: 3 Popular (`popular_300`), 7 Random (`random_1000`)  
**Status**: Awaiting human `reviewer_verdict` in `review/flagged_for_review_v35.csv`.

---

## Index of Evidence Sheets

| Sample ID | Crate Name | Version | Cohort | Downloads | Stage 2 Score | Severity Note | Evidence Sheet |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- | :---: |
"""
    for m in sheets_meta:
        sev_badge = "**High (Action)**" if m["severity_note"] else "Normal"
        index_content += f"| `{m['sid']}` | **{m['name']}** | {m['ver']} | `{m['cohort']}` | {m['downloads']:,} | `{m['malware_score']}` | {sev_badge} | [{m['name']}.md]({m['file']}) |\n"

    index_content += """
---

## Priority Review Notes (Task 2 Factual Flags)

The following crates exhibit flagged behavior that, if malicious, would involve high-severity vectors (file writes, command execution, or credential access):

"""
    for m in sheets_meta:
        if m["severity_note"]:
            index_content += f"* **`{m['name']}` (v{m['ver']})**: {m['severity_note']}\n"

    index_content += """
---

## Instructions for Human Reviewer
1. Review the individual evidence sheets in this directory (`review/evidence_sheets_v35/`).
2. Record your verdicts (`TP`, `FP`, or `UNSURE`) in `review/flagged_for_review_v35.csv` under the `reviewer_verdict` column.
3. Return the completed CSV to the agent to finalize the production false-positive rate and close `REPORT_V35.md`.
"""
    (OUT_DIR / "INDEX.md").write_text(index_content, encoding="utf-8")
    print("Wrote review/evidence_sheets_v35/INDEX.md")

if __name__ == "__main__":
    main()
