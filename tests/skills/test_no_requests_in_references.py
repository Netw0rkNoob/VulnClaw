"""The model's reference material must not instruct it to use ``requests``.

``python_execute`` runs model-written code with ``sys.executable``, and
``requests`` is not a declared dependency, so any prompt or skill example that
imports or calls ``requests`` produces code that dies with
``ModuleNotFoundError`` before sending a request.

This guard scans the system prompts and the skill reference markdown (which
``load_skill_reference`` feeds to the model) for ``requests`` module usage.
"""

import pathlib
import re

import vulnclaw

_PKG = pathlib.Path(vulnclaw.__file__).resolve().parent

_FILES = [
    _PKG / "agent" / "prompts_en.py",
    _PKG / "agent" / "prompts_zh.py",
]
_FILES += sorted(p for p in (_PKG / "skills").rglob("*") if p.suffix in (".md", ".py"))

# ``import requests`` / ``from requests ...``, or any attribute access such as
# ``requests.get`` / ``requests.Session`` / ``requests.put``.
_MODULE_USAGE = re.compile(r"\b(?:import requests|from requests)\b|requests\.[A-Za-z_]")


def test_references_do_not_instruct_requests():
    offenders: list[str] = []
    for path in _FILES:
        text = path.read_text(encoding="utf-8")
        for match in _MODULE_USAGE.finditer(text):
            offenders.append(f"{path.relative_to(_PKG)}: {match.group(0)!r}")
    assert not offenders, (
        "prompts/skills still reference the requests module, which is not a "
        "dependency:\n" + "\n".join(offenders)
    )
