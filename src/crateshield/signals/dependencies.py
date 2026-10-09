"""Signal 5 — dependency analyzer. Parses [dependencies] AND
[target.'cfg(...)'.dependencies] from Cargo.toml, without executing
anything. Platform-specific dependency tables are a real evasion vector
if left unchecked -- an attacker can hide a malicious dependency behind
a target.cfg gate specifically because naive scanners only check the
plain [dependencies] section."""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Extra names to treat as known-malicious (in addition to the OSSF list below).
KNOWN_MALICIOUS_DEPS: set[str] = set()

_OSSF_NAMES_CACHE: set[str] | None = None


def _norm(name: str) -> str:
    return name.lower().replace("-", "_")


def known_malicious_names() -> set[str]:
    """Names whose ENTIRE crate is reported malicious by the OSSF
    malicious-packages reports (all-versions reports only; see
    ingestion.ossf.known_malicious_names for why version-specific reports
    are excluded), plus KNOWN_MALICIOUS_DEPS. This is an advisory lookup, the
    same kind of evidence cargo-audit uses -- it is NOT behavioural detection,
    and evaluation results that include it should say so."""
    global _OSSF_NAMES_CACHE
    from crateshield.config import USE_OSSF_DENYLIST
    names = {_norm(n) for n in KNOWN_MALICIOUS_DEPS}
    if USE_OSSF_DENYLIST:
        if _OSSF_NAMES_CACHE is None:
            try:
                from crateshield.ingestion.ossf import known_malicious_names as _ossf
                _OSSF_NAMES_CACHE = _ossf()
            except Exception as e:  # missing data dir must not break analysis
                logger.warning("Could not load OSSF denylist: %s", e)
                _OSSF_NAMES_CACHE = set()
        names |= _OSSF_NAMES_CACHE
    return names


def _collect_deps_via_toml(doc: dict) -> tuple[list[str], list[str], int]:
    """Returns (all_dep_names, pinned_dep_names, dev_dep_count) by walking
    every dependency table: [dependencies], [dev-dependencies], and every
    [target.<cfg>.dependencies] table."""
    names: list[str] = []
    pinned: list[str] = []

    def _walk(table: dict):
        for dep_name, spec in table.items():
            # `alias = { package = "real-name" }` renames a dependency: the key
            # is only a local alias, the registry crate is `package`. Checking
            # the key alone lets an attacker hide a known-bad crate behind an
            # innocuous alias.
            real = spec.get("package") if isinstance(spec, dict) and isinstance(spec.get("package"), str) else dep_name
            names.append(real)
            if isinstance(spec, str) and _looks_pinned(spec):
                pinned.append(real)
            elif isinstance(spec, dict):
                version = spec.get("version")
                if isinstance(version, str) and _looks_pinned(version):
                    pinned.append(real)

    _walk(doc.get("dependencies", {}))
    for target_cfg, target_table in doc.get("target", {}).items():
        _walk(target_table.get("dependencies", {}))

    dev_deps = doc.get("dev-dependencies", {})
    for target_cfg, target_table in doc.get("target", {}).items():
        dev_deps = {**dev_deps, **target_table.get("dev-dependencies", {})}

    return names, pinned, len(dev_deps)


def _looks_pinned(version_str: str) -> bool:
    v = version_str.strip().strip('"')
    return bool(v) and v[0].isdigit()  # exact "1.2.3", not "^1", "~1", ">=1"


def analyze_dependencies(cargo_toml: str | None) -> dict:
    if not cargo_toml:
        return {"count": 0, "names": [], "dev_dependency_count": 0,
                 "suspicious": [], "pinned": False}

    try:
        import tomllib
        doc = tomllib.loads(cargo_toml)
    except Exception:
        logger.warning("Could not parse Cargo.toml for dependency analysis; "
                        "returning empty result rather than a partial/wrong one")
        return {"count": 0, "names": [], "dev_dependency_count": 0,
                 "suspicious": [], "pinned": False, "parse_error": True}

    names, pinned, dev_count = _collect_deps_via_toml(doc)
    known = known_malicious_names()
    suspicious = sorted({n for n in names if _norm(n) in known})

    return {
        "count": len(names),
        "names": names,
        "dev_dependency_count": dev_count,
        "suspicious": suspicious,
        "suspicious_basis": ("reported malicious for all versions in OSSF malicious-packages / "
                             "KNOWN_MALICIOUS_DEPS" if suspicious else None),
        "pinned": len(pinned) > 0,
    }
