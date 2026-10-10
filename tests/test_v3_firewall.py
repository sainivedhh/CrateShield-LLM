"""Tests Independence Firewall for harness/gen_v3 (Hard Rule 5).

Ensures harness/gen_v3 does NOT import:
- crateshield.signals
- harness.baselines
- crateshield.llm.prompt
- any internal detectors or rule modules
"""
import ast
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
GEN_V3_DIR = ROOT / "harness" / "gen_v3"

FORBIDDEN_MODULES = {
    "crateshield.signals",
    "crateshield.llm.prompt",
    "harness.baselines",
    "harness.audit_v2",
    "harness.eval_v2",
}


def get_all_imports(file_path: Path) -> set[str]:
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module)
    return imports


def test_independence_firewall_imports():
    if not GEN_V3_DIR.exists():
        pytest.skip("harness/gen_v3 directory does not exist yet")
    
    py_files = list(GEN_V3_DIR.glob("**/*.py"))
    assert len(py_files) > 0, "Expected Python files in harness/gen_v3"
    
    for py in py_files:
        imports = get_all_imports(py)
        for imp in imports:
            for forbidden in FORBIDDEN_MODULES:
                assert not (imp == forbidden or imp.startswith(forbidden + ".")), (
                    f"FIREWALL VIOLATION in {py.name}: imports forbidden module '{imp}'"
                )