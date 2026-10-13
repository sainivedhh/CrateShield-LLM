"""Downloads crate tarballs from crates.io and extracts them safely.

SAFETY NOTE: Extraction never executes anything. build.rs and all source
files are read as plain text only. Never run `cargo build`, `cargo check`,
or any cargo/rustc subprocess against downloaded, unreviewed crates.
"""
from __future__ import annotations

import logging
import tarfile
import tempfile
from pathlib import Path

import requests

from crateshield.config import CRATES_IO_API, CRATES_IO_STATIC, USER_AGENT

logger = logging.getLogger(__name__)


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
    return s


def get_crate_metadata(name: str, session: requests.Session | None = None) -> dict:
    s = session or _session()
    resp = s.get(f"{CRATES_IO_API}/{name}", timeout=20)
    resp.raise_for_status()
    return resp.json()


def _candidate_names(name: str, version: str) -> list[str]:
    """Generates possible naming variants for the crate (crates.io treats '-' and '_' interchangeably)."""
    return [
        f"{name}-{version}",
        f"{name.replace('-', '_')}-{version}",
        f"{name.replace('_', '-')}-{version}",
    ]


def is_crate_available_locally(name: str, version: str | None) -> bool:
    """Checks whether the crate's tarball or extracted directory exists locally on disk."""
    if not version:
        return False
    from crateshield.config import EXTRACTED_DIR, RAW_DIR
    for c in _candidate_names(name, version):
        extracted = EXTRACTED_DIR / c
        if extracted.exists() and any(extracted.iterdir()):
            return True
        tarball = RAW_DIR / f"{c}.crate"
        if tarball.exists() and tarball.stat().st_size > 0:
            return True
    return False


def locate_crate_root(extracted_dir: Path) -> Path:
    """Finds the root directory containing Cargo.toml inside an extracted crate directory."""
    if not extracted_dir.exists():
        return extracted_dir
    if (extracted_dir / "Cargo.toml").exists():
        return extracted_dir
    subdirs = [p for p in extracted_dir.iterdir() if p.is_dir() and not p.name.startswith(".")]
    for s in subdirs:
        if (s / "Cargo.toml").exists():
            return s
    if len(subdirs) == 1:
        return subdirs[0]
    return extracted_dir


def download_crate(name: str, version: str, dest_dir: Path,
                    session: requests.Session | None = None) -> Path:
    """Downloads the .crate tarball for name@version. Returns local path.
    If the tarball is already present locally in dest_dir, skips network download and uses cache."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    # Check for existing local tarball first (original name, underscored, hyphenated)
    for c in _candidate_names(name, version):
        existing = dest_dir / f"{c}.crate"
        if existing.exists() and existing.stat().st_size > 0:
            logger.info("Using cached crate tarball for %s v%s from %s", name, version, existing)
            return existing

    s = session or _session()
    names_to_try = [name]
    if "_" in name:
        names_to_try.append(name.replace("_", "-"))
    if "-" in name:
        names_to_try.append(name.replace("-", "_"))

    last_err = None
    for n in names_to_try:
        url = f"{CRATES_IO_STATIC}/{n}/{n}-{version}.crate"
        try:
            resp = s.get(url, timeout=30)
            if resp.status_code == 200 and resp.content:
                out_path = dest_dir / f"{name}-{version}.crate"
                out_path.write_bytes(resp.content)
                logger.info("Downloaded %s v%s from %s to %s", name, version, url, out_path)
                return out_path
            resp.raise_for_status()
        except requests.RequestException as e:
            last_err = e

    err_msg = (
        f"Failed to download crate '{name}@{version}' from crates.io static CDN. "
        f"The crate was likely purged from crates.io or is inaccessible, and no local "
        f"tarball was found in {dest_dir}."
    )
    if last_err:
        raise RuntimeError(err_msg) from last_err
    raise FileNotFoundError(err_msg)


def extract_crate(tarball_path: Path, extract_root: Path) -> Path:
    """Extracts a .crate (gzipped tar) file. Rejects path-traversal entries
    (zip-slip style attacks) AND symlink/hardlink entries whose target
    would resolve outside extract_root -- a plain path-traversal check on
    member.name alone is insufficient, since a tar can contain a symlink
    entry with a "safe"-looking name (e.g. "notes.txt") that actually
    points at an absolute path or a ../../ escape when followed. These are
    untrusted tarballs by definition, so both checks are required."""
    extract_root.mkdir(parents=True, exist_ok=True)
    resolved_root = extract_root.resolve()

    with tarfile.open(tarball_path, "r:gz") as tar:
        safe_members = []
        for member in tar.getmembers():
            member_path = (extract_root / member.name).resolve()
            if not str(member_path).startswith(str(resolved_root)):
                logger.warning("Skipping unsafe tar member (path traversal): %s", member.name)
                continue

            if member.issym() or member.islnk():
                link_target = member.linkname
                # Resolve where the link WOULD point, relative to its own
                # location inside the extraction root, not the cwd.
                target_path = (member_path.parent / link_target).resolve()
                if not str(target_path).startswith(str(resolved_root)):
                    logger.warning("Skipping unsafe tar member (symlink/hardlink "
                                    "escapes extraction root): %s -> %s",
                                    member.name, link_target)
                    continue

            safe_members.append(member)

        # Python 3.12+: the 'data' filter enforces these same protections
        # (and more, e.g. device files) at the tarfile-library level too --
        # belt and suspenders. Older Pythons don't support `filter`, so
        # fall back gracefully to the manual checks above only.
        try:
            tar.extractall(path=extract_root, members=safe_members, filter="data")
        except TypeError:
            tar.extractall(path=extract_root, members=safe_members)

    return locate_crate_root(extract_root)


def download_and_extract(name: str, version: str, work_dir: Path,
                          session: requests.Session | None = None) -> Path:
    from crateshield.config import RAW_DIR, EXTRACTED_DIR

    # 1. Check if already extracted locally
    for c in _candidate_names(name, version):
        extracted_path = EXTRACTED_DIR / c
        if extracted_path.exists() and any(extracted_path.iterdir()):
            crate_root = locate_crate_root(extracted_path)
            logger.info("Using existing extracted crate for %s v%s from %s", name, version, crate_root)
            return crate_root

    # 2. Check if raw tarball exists locally before fetching from network
    tarball = None
    for c in _candidate_names(name, version):
        candidate_tarball = RAW_DIR / f"{c}.crate"
        if candidate_tarball.exists() and candidate_tarball.stat().st_size > 0:
            tarball = candidate_tarball
            logger.info("Using cached tarball for %s v%s from %s", name, version, tarball)
            break

    if tarball is None:
        tarball = download_crate(name, version, RAW_DIR, session)

    target_extracted = EXTRACTED_DIR / f"{name}-{version}"
    return extract_crate(tarball, target_extracted)


def read_file(path: Path) -> str | None:
    if not path or not path.exists() or not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def collect_rs_files(crate_dir: Path, exclude_paths: set[Path] | None = None) -> dict[str, str]:
    """Collects every .rs file Cargo could actually compile into the
    library/binary for this crate -- not just crate_dir/src, which is only
    the DEFAULT location. A crate can redirect its lib/bin targets via
    [lib] path=... or [[bin]] path=... in Cargo.toml; code sitting outside
    src/ under a custom path would otherwise be invisible to every signal
    extractor that consumes source_files (unsafe/FFI detection,
    proc-macro suspicious-import scanning).

    exclude_paths: absolute, resolved paths to explicitly leave out --
    used to keep the build script (Signal 1's own domain) out of this
    scan, so build.rs's own unsafe/FFI usage doesn't inflate the
    LIBRARY's unsafe-block count (Signal 2), which is a different,
    separately-reported signal category.

    Also excludes examples/, tests/, and benches/ at the crate root --
    these are not compiled into the shipped library/binary by `cargo
    build` (only by `cargo test`/`cargo bench`/`cargo run --example`),
    so illustrative unsafe/FFI usage there would misrepresent what's
    actually in the artifact users depend on. A custom lib/bin path is
    still honored even if it happens to point inside one of these dirs,
    since exclude_paths only covers the build script, not these
    directories, and custom_paths (below) are added back explicitly.

    Falls back to scanning the whole crate_dir (still excluding target/)
    if Cargo.toml doesn't parse, so a parse failure fails safe (scans too
    much) rather than silently missing real source (scanning too little).
    """
    exclude_paths = exclude_paths or set()
    cargo_toml = read_file(crate_dir / "Cargo.toml")
    custom_paths: set[Path] = set()

    if cargo_toml:
        try:
            import tomllib
            doc = tomllib.loads(cargo_toml)
            lib_path = doc.get("lib", {}).get("path")
            if lib_path:
                custom_paths.add((crate_dir / lib_path).resolve())
            for bin_entry in doc.get("bin", []):
                bin_path = bin_entry.get("path")
                if bin_path:
                    custom_paths.add((crate_dir / bin_path).resolve())
        except Exception:
            logger.warning("Could not parse Cargo.toml for custom lib/bin paths; "
                            "scanning entire crate directory as a safe fallback")

    _NON_SHIPPED_DIRS = {"target", "examples", "tests", "benches"}

    out: dict[str, str] = {}
    for p in crate_dir.rglob("*.rs"):
        parts = p.relative_to(crate_dir).parts
        if parts and parts[0] in _NON_SHIPPED_DIRS:
            continue  # not compiled by `cargo build` into the shipped artifact
        resolved = p.resolve()
        if resolved in exclude_paths:
            continue  # explicitly excluded (e.g. the build script -- Signal 1's own domain)
        rel = p.relative_to(crate_dir).as_posix()
        content = read_file(p)
        if content is not None:
            out[rel] = content

    # Ensure any custom lib/bin path outside src/ is explicitly included
    # even if the rglob above somehow missed it (e.g. symlinked in oddly).
    for cp in custom_paths:
        if cp.exists() and cp.is_file():
            rel = (cp.relative_to(crate_dir.resolve())).as_posix() if cp.is_relative_to(crate_dir.resolve()) else str(cp)
            if rel not in out:
                content = read_file(cp)
                if content is not None:
                    out[rel] = content

    return out


def resolve_build_script_path(cargo_toml_text: str | None) -> str | None:
    """Resolves the ACTUAL build script Cargo will run for this crate,
    per Cargo's own resolution rules:
      - [package] build = "custom/path.rs"  -> use that exact path
      - [package] build = false             -> no build script at all,
                                                even if build.rs physically exists
      - key omitted (or build = true)       -> default to "build.rs" if present

    Returns the relative path to check, or None if no build script runs.
    Checking this instead of hardcoding "build.rs" closes both an evasion
    vector (attacker renames the script and points `build` at it) and a
    false-positive vector (build = false with a stale build.rs left in
    the tarball, which Cargo will never execute).
    """
    if not cargo_toml_text:
        return "build.rs"  # no manifest info -> fall back to Cargo's own default

    try:
        import tomllib
        doc = tomllib.loads(cargo_toml_text)
    except Exception:
        # Manifest didn't parse cleanly (some crates ship slightly malformed
        # or edge-case TOML) -- fall back to the default name rather than
        # silently reporting no build script at all.
        logger.warning("Could not parse Cargo.toml to resolve build script path; "
                        "defaulting to 'build.rs'")
        return "build.rs"

    build_value = doc.get("package", {}).get("build")

    if build_value is False:
        return None
    if isinstance(build_value, str) and build_value.strip():
        return build_value.strip()
    return "build.rs"  # omitted or `build = true` -> Cargo's own default


def preprocess_crate(name: str, version: str, crate_dir: Path) -> dict:
    cargo_toml = read_file(crate_dir / "Cargo.toml")
    build_script_path = resolve_build_script_path(cargo_toml)
    build_rs_content = read_file(crate_dir / build_script_path) if build_script_path else None
    exclude = {(crate_dir / build_script_path).resolve()} if build_script_path else set()

    return {
        "name": name,
        "version": version,
        "cargo_toml": cargo_toml,
        "build_rs": build_rs_content,
        "build_script_path": build_script_path,  # None if Cargo won't run one at all
        "source_files": collect_rs_files(crate_dir, exclude_paths=exclude),
        "cargo_lock": read_file(crate_dir / "Cargo.lock"),
    }
