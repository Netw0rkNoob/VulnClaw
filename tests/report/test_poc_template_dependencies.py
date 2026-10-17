"""Pin what PoC templates are allowed to import.

PoC scripts are handed to users as report artifacts and are also executed with
``sys.executable`` (the interpreter that imported vulnclaw). A template that
imports a module the project does not depend on therefore produces a script that
crashes with ``ModuleNotFoundError`` on a clean install, before it sends a
single request.

This test keeps every template's imports to modules the executing interpreter
can actually import.
"""

from __future__ import annotations

import ast
import importlib.util
import sys

import pytest

from vulnclaw.report.verifier import PoCGenerator


def _top_level_imports(code: str) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(ast.parse(code)):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            modules.add(node.module.split(".")[0])
    return modules


def _templates() -> dict[str, str]:
    templates = dict(PoCGenerator.POC_TEMPLATES)
    templates["__generic__"] = PoCGenerator._generic_template()
    return templates


@pytest.mark.parametrize("name", sorted(_templates()))
def test_template_imports_are_available_to_the_verifier(name):
    code = _templates()[name]
    for module in sorted(_top_level_imports(code)):
        if module in sys.stdlib_module_names:
            continue
        assert importlib.util.find_spec(module) is not None, (
            f"PoC template {name!r} imports {module!r}, which the interpreter "
            f"running PoCs ({sys.executable}) cannot import. The generated PoC "
            f"would exit non-zero before reaching the target."
        )


def test_templates_do_not_import_requests():
    """``requests`` is not a project dependency; httpx is."""
    for name, code in _templates().items():
        assert "requests" not in _top_level_imports(code), name
