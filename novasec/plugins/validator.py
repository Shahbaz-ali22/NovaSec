"""
NovaSec Plugin Safety Validator.

Checks plugin manifests and source files for safety issues before loading.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from novasec.core.exceptions import PluginValidationError
from novasec.plugins.base import PluginManifest

logger = logging.getLogger(__name__)

# Forbidden constructs in plugin source code
FORBIDDEN_FUNCTIONS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_IMPORTS = {"subprocess", "os.system", "pty"}


class PluginSafetyValidator:
    """
    Validates plugin manifests and source code for safety compliance.

    Raises :class:`PluginValidationError` if safety checks fail.
    """

    def validate(self, manifest: PluginManifest, plugin_dir: Path) -> None:
        """Run all safety checks for *manifest* and *plugin_dir*."""
        self._check_version_format(manifest)
        self._scan_source_files(plugin_dir)

    def _check_version_format(self, manifest: PluginManifest) -> None:
        """Verify manifest version fields are valid semver."""
        import re
        semver_pattern = r"^\d+\.\d+\.\d+$"
        if not re.match(semver_pattern, manifest.version):
            raise PluginValidationError(
                f"Plugin {manifest.name!r} has invalid version: {manifest.version!r}. "
                "Must be semver (e.g. 1.0.0)."
            )

    def _scan_source_files(self, plugin_dir: Path) -> None:
        """AST-scan Python files for forbidden constructs."""
        for py_file in plugin_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source)
                self._check_ast(py_file.name, tree)
            except SyntaxError as e:
                raise PluginValidationError(
                    f"Syntax error in {py_file.name}: {e}"
                )

    def _check_ast(self, filename: str, tree: ast.AST) -> None:
        """Walk the AST and flag forbidden constructs."""
        for node in ast.walk(tree):
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in FORBIDDEN_FUNCTIONS:
                    raise PluginValidationError(
                        f"Plugin file {filename!r} uses forbidden function: {func.id!r}. "
                        "Use novasec.infrastructure.subprocess.runner.SubprocessRunner instead."
                    )
