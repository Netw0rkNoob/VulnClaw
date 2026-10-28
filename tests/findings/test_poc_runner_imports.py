"""The PoC runner is executed with ``sys.executable``.

``execute_plan`` runs ``PROGRAM`` in a subprocess launched with the interpreter
that imported vulnclaw, so every module the runner imports must be importable by
that interpreter. 0.4.1 shipped templates that began with ``import requests``
while ``requests`` was not declared as a dependency, and the generated scripts
died with ``ModuleNotFoundError`` before sending a request.

``tests/findings/test_poc.py`` proves the runner works end to end; this test
pins the narrower invariant so a future edit cannot reintroduce an undeclared
import.
"""

import ast
import importlib.util
import sys

from vulnclaw.findings.poc import PROGRAM


def _top_level_imports(code: str) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(ast.parse(code)):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            modules.add(node.module.split(".")[0])
    return modules


def test_poc_runner_only_imports_modules_the_interpreter_can_import():
    for module in sorted(_top_level_imports(PROGRAM)):
        if module in sys.stdlib_module_names:
            continue
        assert importlib.util.find_spec(module) is not None, (
            f"the PoC runner imports {module!r}, which the interpreter that runs "
            f"it ({sys.executable}) cannot import; the generated verify.py would "
            f"exit with ModuleNotFoundError before sending a request"
        )
