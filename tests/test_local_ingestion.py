import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from crateshield.ingestion.downloader import (
    _candidate_names,
    download_crate,
    download_and_extract,
    is_crate_available_locally,
    locate_crate_root,
)


def test_candidate_names_handles_hyphens_and_underscores():
    cands = _candidate_names("faster_log", "0.1.2")
    assert "faster_log-0.1.2" in cands
    assert "faster-log-0.1.2" in cands


def test_locate_crate_root_direct_cargo_toml(tmp_path):
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "test"\n')
    assert locate_crate_root(tmp_path) == tmp_path


def test_locate_crate_root_nested_subdir(tmp_path):
    nested = tmp_path / "test-1.0.0"
    nested.mkdir()
    (nested / "Cargo.toml").write_text('[package]\nname = "test"\n')
    assert locate_crate_root(tmp_path) == nested


def test_download_crate_uses_local_cache_without_network(tmp_path, monkeypatch):
    # If network is called, fail the test
    import requests
    def mock_get(*args, **kwargs):
        raise RuntimeError("Network should not be called when file is cached locally")
    monkeypatch.setattr(requests.Session, "get", mock_get)

    crate_file = tmp_path / "my_crate-0.1.0.crate"
    crate_file.write_bytes(b"dummy tarball content")

    result = download_crate("my_crate", "0.1.0", tmp_path)
    assert result == crate_file


def test_download_and_extract_uses_existing_extracted_dir(tmp_path, monkeypatch):
    import crateshield.config as config
    monkeypatch.setattr(config, "EXTRACTED_DIR", tmp_path / "extracted")
    monkeypatch.setattr(config, "RAW_DIR", tmp_path / "raw")

    extracted_target = tmp_path / "extracted" / "local_malware-0.1.0"
    extracted_target.mkdir(parents=True)
    (extracted_target / "Cargo.toml").write_text('[package]\nname = "local_malware"\n')

    # Ensure no network download or extraction occurs
    import crateshield.ingestion.downloader as dl
    def fail_download(*args, **kwargs):
        raise RuntimeError("Should not attempt download")
    monkeypatch.setattr(dl, "download_crate", fail_download)

    res = download_and_extract("local_malware", "0.1.0", tmp_path)
    assert res == extracted_target
    assert is_crate_available_locally("local_malware", "0.1.0")
