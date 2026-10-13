"""Ingestion of the OpenSSF malicious-packages crates.io reports.

IMPORTANT: https://github.com/ossf/malicious-packages contains *advisory
reports* in OSV JSON format -- it does NOT contain the malicious crates'
source code. Most reported crates have since been removed from crates.io,
so a report only becomes an analyzable dataset entry if its (name, version)
can still be downloaded. `probe_availability` records that (metadata + HEAD
requests only; it never downloads a crate), and `build_dataset` marks each
entry `analyzable` accordingly so the ablation does not silently crash or
silently shrink.

Provenance: the reports under data/ossf/crates.io are verbatim copies;
data/ossf/manifest.json records the source commit. Licence: Apache-2.0
(data/ossf/LICENSE).
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from crateshield.config import (
    CRATES_IO_API, DATASET_PATH, OSSF_AVAILABILITY_PATH,
    OSSF_CRATES_DIR, OSSF_CRATES_PATH, OSSF_MANIFEST_PATH, OSSF_REPO_API, USER_AGENT,
)
from crateshield.ingestion.downloader import is_crate_available_locally

logger = logging.getLogger(__name__)

LABEL_ORIGIN = "ossf-malicious-packages"
REPORT_URL_BASE = "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/crates.io"


def normalize_name(name: str) -> str:
    """crates.io treats '-' and '_' as equivalent for name uniqueness."""
    return (name or "").lower().replace("-", "_")


# --------------------------------------------------------------------------
# Loading + parsing reports
# --------------------------------------------------------------------------
def load_reports(crates_dir: Path | None = None) -> list[dict]:
    """Parsed OSV reports; each dict gets a `_relpath` key (dir/ID.json)."""
    crates_dir = Path(crates_dir) if crates_dir else OSSF_CRATES_DIR
    out = []
    for p in sorted(crates_dir.glob("*/*.json")):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Skipping unreadable OSSF report %s: %s", p, e)
            continue
        doc["_relpath"] = f"{p.parent.name}/{p.name}"
        out.append(doc)
    return out


def affected_packages(report: dict) -> list[dict]:
    """One dict per crates.io `affected` entry:
    {"name", "versions": [...], "all_versions": bool}.

    all_versions is True only when the report lists no explicit versions and
    its range starts at 0 with no `fixed`/`last_affected` bound -- i.e. the
    whole crate name is malicious, not just particular releases.
    """
    out = []
    for aff in report.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem", "crates.io") != "crates.io" or not pkg.get("name"):
            continue
        versions = list(aff.get("versions") or [])
        all_versions = False
        if not versions:
            for r in aff.get("ranges") or []:
                events = r.get("events") or []
                starts_at_zero = any(e.get("introduced") == "0" for e in events)
                bounded = any(("fixed" in e) or ("last_affected" in e) for e in events)
                if starts_at_zero and not bounded:
                    all_versions = True
        out.append({"name": pkg["name"], "versions": versions, "all_versions": all_versions})
    return out


# Keyword-derived categories: these only restate what the report text says.
_CATEGORY_RULES = [
    ("typosquatting", r"typosquat"),
    ("compromised-maintainer-account", r"appears to be compromised|account[^.]{0,40}compromised"),
    ("malicious-dependency", r"(declares|adds) a dependency on"),
    ("build-time-payload-campaign", r"coordinated (crates\.io )?(build-time payload )?campaign"),
    ("remote-binary-download", r"downloads?\b[^.]{0,120}\bbinary"),
    ("data-exfiltration", r"\bPOSTs?\b|exfiltrat|\bsteals\b"),
    ("ssh-persistence", r"authorized_keys"),
    ("suspicious-domain-contact", r"communicates with a domain associated with malicious activity"),
    ("malicious-command-execution", r"executes one or more commands associated with malicious behavior"),
]


def derive_categories(details: str) -> list[str]:
    text = details or ""
    return [name for name, pat in _CATEGORY_RULES if re.search(pat, text, re.IGNORECASE)]


def label_evidence(details: str, origins: list[str]) -> str:
    text = details or ""
    if re.search(r"not analy[sz]ed directly", text, re.IGNORECASE):
        return "campaign-attributed"  # weaker: behaviour inferred from sibling crates
    if "ossf-package-analysis" in origins or "OpenSSF Package Analysis" in text:
        return "dynamic-analysis"
    return "written-report"


def _origins(report: dict) -> list[str]:
    ds = report.get("database_specific") or {}
    return [o.get("source") for o in ds.get("malicious-packages-origins", []) if o.get("source")]


def known_malicious_names(reports: list[dict] | None = None) -> set[str]:
    """Normalized names of crates whose ENTIRE name is reported malicious
    (all versions). Version-specific reports (e.g. arrayref 0.3.10) are
    excluded on purpose: arrayref, internment and append-only-vec are
    legitimate, widely used crates, so name-only denylisting them would flag
    every crate that depends on them."""
    reports = load_reports() if reports is None else reports
    names: set[str] = set()
    for rep in reports:
        for aff in affected_packages(rep):
            if aff["all_versions"]:
                names.add(normalize_name(aff["name"]))
    return names


# --------------------------------------------------------------------------
# Availability probing (metadata + HEAD only; never downloads a crate)
# --------------------------------------------------------------------------
def _http() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s


def load_availability(path: Path | None = None) -> dict:
    path = Path(path) if path else OSSF_AVAILABILITY_PATH
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("crates", {})
    except (OSError, json.JSONDecodeError):
        return {}


def probe_availability(targets: dict[str, list[str]], session: requests.Session | None = None,
                       pause: float = 0.4) -> dict:
    """targets: {crate_name: [versions to check]}. For each crate, calls
    only the crates.io API (metadata GET) -- never the static tarball host
    and never downloads a crate. "downloadable" is inferred from the API's
    own version listing: a version that still appears there (and is not
    yanked) is servable; crates.io removes a version's listing entirely
    once a tarball is pulled for malice, so an empty/missing listing is a
    reliable "gone" signal. (An earlier version of this function HEAD/Range
    probed static.crates.io directly, but that host's WAF returns 403 for
    HEAD and Range requests regardless of whether the object exists, which
    made that check meaningless -- confirmed by comparing a 403'd HEAD
    against a 200 plain GET on the same still-live object, and against the
    API returning an empty version list for genuinely removed crates.)
    Returns a snapshot dict suitable for data/ossf/availability.json."""
    s = session or _http()
    snap: dict[str, dict] = {}
    for name, versions in sorted(targets.items()):
        entry: dict = {"checked_name": name, "crate_exists": False, "listed_versions": {},
                       "target_versions": {}}
        try:
            r = s.get(f"{CRATES_IO_API}/{name}", timeout=20)
            if r.status_code == 200:
                j = r.json()
                entry["crate_exists"] = True
                entry["real_name"] = j.get("crate", {}).get("name", name)
                entry["listed_versions"] = {v["num"]: {"yanked": bool(v.get("yanked"))}
                                            for v in j.get("versions", [])}
            else:
                entry["api_status"] = r.status_code
        except (requests.RequestException, ValueError) as e:
            entry["api_error"] = str(e)[:120]
        check = list(versions) or list(entry["listed_versions"])
        for v in check:
            listed = entry["listed_versions"].get(v)
            entry["target_versions"][v] = {
                "listed": listed is not None,
                "yanked": listed["yanked"] if listed else None,
                "downloadable": bool(listed and not listed["yanked"]),
            }
        snap[normalize_name(name)] = entry
        time.sleep(pause)
    return snap


def save_availability(snapshot: dict, path: Path | None = None) -> None:
    path = Path(path) if path else OSSF_AVAILABILITY_PATH
    payload = {
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "method": ("crates.io API metadata only (version listing implies downloadability -- "
               "static.crates.io HEAD/Range is blocked regardless of object existence; "
               "see probe_availability docstring). No crate was downloaded."),
        "crates": snapshot,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


# --------------------------------------------------------------------------
# Dataset construction
# --------------------------------------------------------------------------
def _seed_entries(seed_path: Path) -> tuple[list[dict], dict]:
    """Hand-curated entries (anything not derived from OSSF) plus header."""
    if not Path(seed_path).exists():
        return [], {}
    doc = json.loads(Path(seed_path).read_text())
    seeds = [c for c in doc.get("crates", []) if c.get("label_origin") != LABEL_ORIGIN]
    return seeds, doc


def _availability_for(avail: dict, name: str, version: str | None) -> bool | None:
    rec = avail.get(normalize_name(name))
    if not rec or version is None:
        return None
    tv = rec.get("target_versions", {}).get(version)
    return None if tv is None else tv.get("downloadable")


def build_dataset(seed_path: Path | None = None, reports: list[dict] | None = None,
                  availability: dict | None = None) -> dict:
    """Merge hand-curated seed entries with one entry per (crate, version)
    from the OSSF reports. Idempotent: OSSF-derived entries in an existing
    dataset.json are regenerated, seed entries are preserved.

    - A report naming explicit versions -> one entry per version.
    - A report covering all versions -> if a seed entry has the same crate
      name, the report is merged into it as an additional source; else, if
      the crate is still live and the availability snapshot lists its
      versions, one entry per listed version; else one entry with
      version=None (not analyzable).
    """
    seed_path = Path(seed_path) if seed_path else DATASET_PATH
    reports = load_reports() if reports is None else reports
    availability = load_availability() if availability is None else availability
    seeds, header = _seed_entries(seed_path)

    entries: list[dict] = [dict(e) for e in seeds]
    by_key = {(normalize_name(e["name"]), e.get("version")): e for e in entries}
    by_name: dict[str, list[dict]] = {}
    for e in entries:
        by_name.setdefault(normalize_name(e["name"]), []).append(e)

    def add_source(entry: dict, rep: dict) -> None:
        srcs = entry.setdefault("additional_sources", [])
        if rep["id"] not in srcs and rep["id"] != entry.get("label_source"):
            srcs.append(rep["id"])

    for rep in reports:
        rid = rep.get("id", rep.get("_relpath", "?"))
        rep = {**rep, "id": rid}
        details = rep.get("details") or ""
        origins = _origins(rep)
        cats = derive_categories(details)
        evidence = label_evidence(details, origins)
        if evidence == "campaign-attributed":
            # These reports mention the campaign's typosquat (proc-macro1) by name, but the
            # crate being reported is a helper, not itself a typosquat.
            cats = [c for c in cats if c != "typosquatting"]
        report_url = f"{REPORT_URL_BASE}/{rep['_relpath']}"
        for aff in affected_packages(rep):
            name = aff["name"]
            nn = normalize_name(name)
            versions: list[str | None] = list(aff["versions"])
            versions_source = "OSV report"
            if not versions:
                if nn in by_name:  # merge into curated entry / entries of same crate
                    for e in by_name[nn]:
                        add_source(e, rep)
                    continue
                rec = availability.get(nn) or {}
                live = list((rec.get("target_versions") or {}).keys()) if rec.get("crate_exists") else []
                if aff["all_versions"] and live:
                    versions, versions_source = live, "crates.io listing (report covers all versions)"
                else:
                    versions = [None]
            for v in versions:
                key = (nn, v)
                if key in by_key:
                    add_source(by_key[key], rep)
                    continue
                dl = _availability_for(availability, name, v)
                high_major = None
                if v:
                    m = re.match(r"(\d+)\.", v)
                    high_major = bool(m and int(m.group(1)) >= 99)
                entry = {
                    "name": name, "version": v, "label": "MALICIOUS",
                    "label_source": rep["id"], "label_origin": LABEL_ORIGIN,
                    "label_evidence": evidence,
                    "attack_category": ",".join(cats) if cats else "unspecified",
                    "attack_category_method": "keyword match on OSV details text (not manual review)",
                    "report_published": (rep.get("published") or "")[:10] or None,
                    "url": report_url,
                    "affects_all_versions": aff["all_versions"],
                    "downloadable_on_crates_io": dl,
                    "analyzable": bool(v is not None and dl is not False),
                }
                if versions_source != "OSV report" and v is not None:
                    entry["version_source"] = versions_source
                if high_major:
                    entry["version_major_ge_99"] = True
                if v is None:
                    entry["note"] = ("Report covers all versions and the crate is no longer listed on "
                                     "crates.io; no downloadable version, so it cannot be analyzed by "
                                     "the download-based pipeline (kept as ground-truth metadata).")
                elif dl is False:
                    entry["note"] = ("Version no longer appears in the crate's crates.io version "
                                     "listing at probe time (removed).")
                elif dl is None:
                    entry["note"] = "Availability not probed; run `python -m crateshield build-dataset --probe`."
                entries.append(entry)
                by_key[key] = entry
                by_name.setdefault(nn, []).append(entry)

    # curated entries: refresh analyzable flag from the snapshot when we have one
    for e in entries:
        if e.get("label_origin") == LABEL_ORIGIN:
            continue
        if e.get("local_benchmark_crate"):
            e["analyzable"] = True
            continue
        dl = _availability_for(availability, e["name"], e.get("version"))
        e.setdefault("downloadable_on_crates_io", dl)
        if dl is not None:
            e["downloadable_on_crates_io"] = dl
        e["analyzable"] = bool(e.get("version") is not None and e.get("downloadable_on_crates_io") is not False)

    manifest = {}
    if OSSF_MANIFEST_PATH.exists():
        try:
            manifest = json.loads(OSSF_MANIFEST_PATH.read_text())
        except (OSError, json.JSONDecodeError):
            manifest = {}

    labels: dict[str, int] = {"MALICIOUS": 0, "SUSPICIOUS": 0, "BENIGN": 0}
    for e in entries:
        labels[e["label"]] = labels.get(e["label"], 0) + 1
    n_analyzable = sum(1 for e in entries if e.get("analyzable"))
    return {
        "dataset_version": "2.0.0-ossf",
        "construction_date": datetime.now(timezone.utc).date().isoformat(),
        "note": ("Seed entries + OSSF malicious-packages crates.io reports. Reports are advisories, not "
                 "source code: only entries with analyzable=true can be run through the pipeline. There "
                 "are NO benign entries yet, so FPR/precision cannot be computed -- add a benign set "
                 "before drawing conclusions from the ablation."),
        "ossf_source": {k: manifest.get(k) for k in ("source_repo", "commit", "commit_date", "retrieved_at")},
        "total_crates": len(entries),
        "analyzable_crates": n_analyzable,
        "label_counts": labels,
        "crates": entries,
    }


def write_dataset(dataset: dict, path: Path | None = None) -> Path:
    path = Path(path) if path else DATASET_PATH
    path.write_text(json.dumps(dataset, indent=2, ensure_ascii=False) + "\n")
    return path


def dataset_targets(dataset: dict) -> dict[str, list[str]]:
    """{name: [explicit versions]} to probe, for every entry in the dataset."""
    t: dict[str, list[str]] = {}
    for e in dataset.get("crates", []):
        t.setdefault(e["name"], [])
        if e.get("version") and e["version"] not in t[e["name"]]:
            t[e["name"]].append(e["version"])
    return t


# --------------------------------------------------------------------------
# Refresh from GitHub (network)
# --------------------------------------------------------------------------
def _gh_session() -> requests.Session:
    s = _http()
    s.headers["Accept"] = "application/vnd.github+json"
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


def _manifest(commit: str | None, commit_date: str | None, n: int, method: str) -> dict:
    return {
        "source_repo": "https://github.com/ossf/malicious-packages",
        "source_path": OSSF_CRATES_PATH,
        "commit": commit,
        "commit_date": commit_date,
        "retrieved_at": datetime.now(timezone.utc).date().isoformat(),
        "retrieved_via": method,
        "n_reports": n,
        "license": "Apache-2.0 (see LICENSE in this directory)",
        "format": "OSV schema JSON reports (advisory metadata). The repository does NOT contain the "
                  "malicious crates' source code.",
        "note": "Files under crates.io/ are verbatim copies. Do not edit.",
    }


def _refresh_via_git(dest: Path) -> dict:
    """Sparse, blob-filtered shallow clone of just osv/malicious/crates.io.
    No GitHub API calls, so no rate limit (the contents API allows only 60
    unauthenticated requests/hour per IP)."""
    import shutil
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "repo"

        def git(*args: str) -> str:
            return subprocess.run(["git", *args], cwd=None if args[0] == "clone" else repo, check=True,
                                  capture_output=True, text=True, timeout=300).stdout.strip()

        git("clone", "--depth", "1", "--filter=blob:none", "--sparse",
            "https://github.com/ossf/malicious-packages.git", str(repo))
        git("sparse-checkout", "set", OSSF_CRATES_PATH)
        commit = git("rev-parse", "HEAD")
        commit_date = git("log", "-1", "--format=%cI")
        src = repo / OSSF_CRATES_PATH
        n = 0
        dest.mkdir(parents=True, exist_ok=True)
        for f in sorted(src.glob("*/*.json")):
            json.loads(f.read_text(encoding="utf-8"))  # validate before copying
            (dest / f.parent.name).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, dest / f.parent.name / f.name)
            n += 1
    return _manifest(commit, commit_date, n, "git sparse clone")


def _refresh_via_api(dest: Path, s: requests.Session) -> dict:
    """Fallback when git is unavailable: contents API (1 call for the directory
    list + 1 per crate directory; set GITHUB_TOKEN to raise the 60/hr limit)."""
    resp = s.get(f"{OSSF_REPO_API}/contents/{OSSF_CRATES_PATH}", timeout=30)
    resp.raise_for_status()
    dirs = [e for e in resp.json() if e.get("type") == "dir"]
    dest.mkdir(parents=True, exist_ok=True)
    n = 0
    for d in dirs:
        r = s.get(d["url"], timeout=30)
        r.raise_for_status()
        for f in r.json():
            if f.get("type") != "file" or not f["name"].endswith(".json"):
                continue
            raw = s.get(f["download_url"], timeout=30)
            raw.raise_for_status()
            json.loads(raw.text)  # validate before writing
            (dest / d["name"]).mkdir(parents=True, exist_ok=True)
            (dest / d["name"] / f["name"]).write_text(raw.text, encoding="utf-8")
            n += 1
    commit = None
    cr = s.get(f"{OSSF_REPO_API}/commits/main", timeout=30)
    if cr.status_code == 200:
        commit = cr.json().get("sha")
    return _manifest(commit, None, n, "GitHub contents API")


def refresh_from_github(dest: Path | None = None, session: requests.Session | None = None,
                        prefer_git: bool = True) -> dict:
    """Re-download every report under osv/malicious/crates.io, overwrite the
    local verbatim copies and rewrite manifest.json (next to `dest`). Uses a
    git sparse clone when git is installed, else the GitHub contents API."""
    dest = Path(dest) if dest else OSSF_CRATES_DIR
    manifest = None
    if prefer_git:
        try:
            manifest = _refresh_via_git(dest)
        except (FileNotFoundError, OSError) as e:  # git not installed
            logger.warning("git unavailable (%s); falling back to the GitHub API", e)
        except Exception as e:
            logger.warning("git refresh failed (%s); falling back to the GitHub API", e)
    if manifest is None:
        manifest = _refresh_via_api(dest, session or _gh_session())
    (dest.parent / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest
