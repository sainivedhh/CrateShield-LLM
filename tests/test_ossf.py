import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from crateshield.ingestion import ossf


def test_bundled_reports_load():
    reports = ossf.load_reports()
    assert len(reports) == 20
    assert all(r["id"].startswith("MAL-") for r in reports)


def test_affected_packages_explicit_and_all_versions():
    reports = {r["id"]: r for r in ossf.load_reports()}
    arrayref = ossf.affected_packages(reports["MAL-2026-14336"])[0]
    assert arrayref["name"] == "arrayref" and arrayref["versions"] == ["0.3.10"]
    assert arrayref["all_versions"] is False
    proc = ossf.affected_packages(reports["MAL-2026-14338"])[0]
    assert proc["name"] == "proc-macro1" and proc["all_versions"] is True


def test_denylist_only_contains_whole_crate_reports():
    """arrayref/internment/append-only-vec are LEGIT crates with one bad release;
    denylisting their names would flag everything that depends on them."""
    names = ossf.known_malicious_names()
    assert "proc_macro1" in names and "logs_update" in names
    for legit in ("arrayref", "internment", "append_only_vec"):
        assert legit not in names


def test_categories_are_keyword_derived_and_conservative():
    cats = ossf.derive_categories("The crate has no build script. It POSTs files and appends a key to authorized_keys.")
    assert "data-exfiltration" in cats and "ssh-persistence" in cats
    assert "remote-binary-download" not in cats


def test_campaign_helpers_are_not_labelled_typosquats():
    ds = ossf.build_dataset(seed_path=Path("/nonexistent"), availability={})
    by_name = {e["name"]: e for e in ds["crates"]}
    assert by_name["aovine"]["label_evidence"] == "campaign-attributed"
    assert "typosquatting" not in by_name["aovine"]["attack_category"]
    assert "typosquatting" in by_name["proc-macro1"]["attack_category"]


def test_build_dataset_expands_versions_and_merges_seed(tmp_path):
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"crates": [
        {"name": "rustdecimal", "version": "1.0.0", "label": "MALICIOUS", "label_source": "RUSTSEC-2022-0042"}]}))
    ds = ossf.build_dataset(seed_path=seed, availability={})
    rd = [e for e in ds["crates"] if e["name"] == "rustdecimal"]
    assert len(rd) == 1 and "MAL-2022-1" in rd[0]["additional_sources"]
    assert len([e for e in ds["crates"] if e["name"] == "lsh"]) == 2  # 99.0.1 and 99.1.0


def test_build_dataset_is_idempotent(tmp_path):
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"crates": []}))
    first = ossf.build_dataset(seed_path=seed, availability={})
    seed.write_text(json.dumps(first))
    second = ossf.build_dataset(seed_path=seed, availability={})
    assert first["total_crates"] == second["total_crates"]


def test_unavailable_or_versionless_entries_are_not_analyzable():
    avail = {"arrayref": {"crate_exists": True, "target_versions": {"0.3.10": {"downloadable": False}}}}
    ds = ossf.build_dataset(seed_path=Path("/nonexistent"), availability=avail)
    by = {(e["name"], e["version"]): e for e in ds["crates"]}
    assert by[("arrayref", "0.3.10")]["analyzable"] is False
    assert by[("proc-macro1", None)]["analyzable"] is False


def test_live_all_versions_crate_expands_from_availability():
    avail = {"logs_update": {"crate_exists": True, "target_versions": {
        "0.0.1": {"downloadable": True}, "0.0.2": {"downloadable": True}}}}
    ds = ossf.build_dataset(seed_path=Path("/nonexistent"), availability=avail)
    lu = [e for e in ds["crates"] if e["name"] == "logs-update"]
    assert sorted(e["version"] for e in lu) == ["0.0.1", "0.0.2"]
    assert all(e["analyzable"] for e in lu)


def test_bundled_dataset_json_is_consistent():
    from crateshield.config import DATASET_PATH
    ds = json.loads(DATASET_PATH.read_text())
    assert ds["total_crates"] == len(ds["crates"])
    assert ds["analyzable_crates"] == sum(1 for e in ds["crates"] if e["analyzable"])
    assert all(e["version"] for e in ds["crates"] if e["analyzable"])
