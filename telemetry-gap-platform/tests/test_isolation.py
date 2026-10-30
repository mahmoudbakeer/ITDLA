"""AST-based static verification of strict data isolation (Phase 7).

Guarantees that the AblationManifest and tgap.ablate are NEVER imported or
referenced inside detection, correlation, gap-localization, or reporting modules.
"""

import ast
from pathlib import Path
import pytest


ISOLATED_MODULES = [
    "tgap/detect.py",
    "tgap/deep_detect.py",
    "tgap/correlate.py",
    "tgap/gaps.py",
    "tgap/deep_gaps.py",
    "tgap/report.py",
    "tgap/normalize.py",
]


@pytest.mark.parametrize("rel_path", ISOLATED_MODULES)
def test_ablation_manifest_never_imported_or_referenced(rel_path: str):
    module_path = Path(rel_path)
    assert module_path.exists(), f"Module {rel_path} not found"

    source = module_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=rel_path)

    for node in ast.walk(tree):
        # Check `import tgap.ablate` or `import ablate`
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert "ablate" not in alias.name, (
                    f"Data Isolation Violation: {rel_path} imports '{alias.name}'"
                )

        # Check `from tgap.ablate import ...`
        elif isinstance(node, ast.ImportFrom):
            mod_name = node.module or ""
            assert "ablate" not in mod_name, (
                f"Data Isolation Violation: {rel_path} imports from '{mod_name}'"
            )
            for alias in node.names:
                assert alias.name != "AblationManifest", (
                    f"Data Isolation Violation: {rel_path} imports AblationManifest"
                )

        # Check identifier references to `AblationManifest`
        elif isinstance(node, ast.Name):
            assert node.id != "AblationManifest", (
                f"Data Isolation Violation: {rel_path} references 'AblationManifest'"
            )
