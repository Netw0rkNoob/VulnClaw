from __future__ import annotations

import json
from pathlib import Path


def _catalog(language: str) -> dict[str, str]:
    path = Path(__file__).resolve().parents[2] / "vulnclaw" / "i18n" / f"{language}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_translation_catalogs_have_matching_keys_outside_skill_namespace():
    """Every non-skill key must exist in both en.json and zh.json.

    ``skill.<name>.description`` overrides are intentionally English-only
    (frontmatter descriptions are authored in Chinese and used as fallback),
    so they are excluded here.
    """
    english = {k for k in _catalog("en") if not k.startswith("skill.")}
    chinese = {k for k in _catalog("zh") if not k.startswith("skill.")}

    assert english == chinese
