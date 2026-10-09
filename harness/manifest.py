"""Dataset Manifest schema and serialization for CrateShield Evaluation Harness.

Implements Section 10 of the spec:
sample_id, view_id, pair_id, cluster_id (= base crate), tier, split,
label, label_evidence, base_crate, base_version, dump_date, template_id,
category, placement, obfuscation_level, surface_variant, payload_bytes,
size_bytes, loc, build_rs_present, template_author, seed, view_hash.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SampleRecord:
    sample_id: str
    view_id: str
    pair_id: str
    cluster_id: str          # Identifies base crate family
    tier: int                # 1: real in-the-wild, 2: reconstruction, 3: injected pair
    split: str               # "tune" or "eval"
    label: str               # "BENIGN" or "MALICIOUS"
    label_evidence: str      # e.g. "presumed-benign (no RustSec/OSSF report)", "injected-twin"
    base_crate: str          # Real base crate name (INTERNAL ONLY)
    base_version: str        # Real base version (INTERNAL ONLY)
    dump_date: str
    template_id: str | None = None
    category: str | None = None          # C1..C8
    placement: str | None = None         # P1..P5
    obfuscation_level: int = 0           # 0 plain, 1 encoded, 2 split/XOR
    surface_variant: str | None = None
    payload_bytes: int = 0
    size_bytes: int = 0
    loc: int = 0
    build_rs_present: bool = True
    template_author: str | None = None
    seed: int = 42
    view_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SampleRecord:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class BenchmarkManifest:
    version: str = "v1"
    created_at: str = ""
    seed: int = 42
    target_scale: int = 40
    records: list[SampleRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "seed": self.seed,
            "target_scale": self.target_scale,
            "total_samples": len(self.records),
            "samples": [r.to_dict() for r in self.records],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BenchmarkManifest:
        records = [SampleRecord.from_dict(r) for r in data.get("samples", [])]
        return cls(
            version=data.get("version", "v1"),
            created_at=data.get("created_at", ""),
            seed=data.get("seed", 42),
            target_scale=data.get("target_scale", 40),
            records=records,
        )

    def get_tune_bases(self) -> set[str]:
        return {r.cluster_id for r in self.records if r.split == "tune"}

    def get_eval_bases(self) -> set[str]:
        return {r.cluster_id for r in self.records if r.split == "eval"}

    def validate_disjointness(self) -> bool:
        """Enforces Acceptance Gate G6: tune and eval base crates are strictly disjoint."""
        tune_bases = self.get_tune_bases()
        eval_bases = self.get_eval_bases()
        overlap = tune_bases & eval_bases
        if overlap:
            raise AssertionError(f"Gate G6 violation: tune and eval share base crates: {overlap}")
        return True


def save_manifest(manifest: BenchmarkManifest, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest.validate_disjointness()
    path.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")


def load_manifest(path: Path) -> BenchmarkManifest:
    data = json.loads(path.read_text(encoding="utf-8"))
    manifest = BenchmarkManifest.from_dict(data)
    manifest.validate_disjointness()
    return manifest
