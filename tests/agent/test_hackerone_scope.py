"""Tests for HackerOne structured-scope fetch and explicit skill injection."""

from __future__ import annotations

import json
import urllib.error
from typing import Any

import pytest

from vulnclaw.agent.hackerone_scope import (
    execute_hackerone_scope,
    extract_program_handle,
    MAX_PAGES,
    fetch_program_scope,
    format_scope_report,
)


class _FakeResponse:
    def __init__(self, body: dict[str, Any], status: int = 200) -> None:
        self._raw = json.dumps(body).encode("utf-8")
        self.status = status

    def read(self) -> bytes:
        return self._raw

    def getcode(self) -> int:
        return self.status

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _team_payload(nodes: list[dict[str, Any]], *, has_next: bool = False) -> dict[str, Any]:
    return {
        "data": {
            "team": {
                "id": "gid://hackerone/Team/1",
                "handle": "crypto",
                "name": "Crypto.com",
                "structured_scopes": {
                    "total_count": len(nodes),
                    "pageInfo": {
                        "hasNextPage": has_next,
                        "endCursor": "cursor-1" if has_next else None,
                    },
                    "nodes": nodes,
                },
            }
        }
    }


class TestExtractHandle:
    def test_from_policy_scopes_url(self):
        assert (
            extract_program_handle("https://hackerone.com/crypto/policy_scopes")
            == "crypto"
        )

    def test_from_quoted_url(self):
        assert (
            extract_program_handle('"https://hackerone.com/example/policy_scopes"')
            == "example"
        )

    def test_bare_handle(self):
        assert extract_program_handle("security") == "security"

    def test_rejects_directory(self):
        with pytest.raises(ValueError):
            extract_program_handle("https://hackerone.com/directory")


class TestFetchProgramScope:
    def test_splits_in_and_out_of_scope(self):
        nodes = [
            {
                "asset_identifier": "*.crypto.com",
                "asset_type": "WILDCARD",
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
                "max_severity": "critical",
                "instruction": "main assets",
            },
            {
                "asset_identifier": "https://crypto.com/exchange",
                "asset_type": "URL",
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
                "max_severity": "critical",
                "instruction": "",
            },
            {
                "asset_identifier": "blog.crypto.com",
                "asset_type": "URL",
                "eligible_for_submission": False,
                "eligible_for_bounty": False,
                "max_severity": "none",
                "instruction": "",
            },
        ]

        def opener(_request: Any, timeout: float = 0) -> _FakeResponse:
            return _FakeResponse(_team_payload(nodes))

        bundle = fetch_program_scope(
            "https://hackerone.com/crypto/policy_scopes", opener=opener
        )
        assert bundle.handle == "crypto"
        assert bundle.program_name == "Crypto.com"
        assert len(bundle.in_scope) == 2
        assert len(bundle.out_of_scope) == 1
        assert bundle.out_of_scope[0].identifier == "blog.crypto.com"
        first = bundle.first_direct_asset()
        assert first is not None
        assert first.identifier == "*.crypto.com"

        report = format_scope_report(bundle)
        assert "Starting recon on *.crypto.com" in report
        assert "blog.crypto.com" in report

    def test_truncated_pagination_raises_instead_of_returning_partial_scope(self):
        """Silently stopping at MAX_PAGES would hide out-of-scope assets."""
        calls = {"n": 0}

        def opener(_request: Any, timeout: float = 0) -> _FakeResponse:
            calls["n"] += 1
            return _FakeResponse(
                _team_payload(
                    [
                        {
                            "id": f"gid://hackerone/StructuredScope/{calls['n']}",
                            "asset_type": "URL",
                            "asset_identifier": f"host{calls['n']}.crypto.com",
                            "eligible_for_submission": True,
                            "eligible_for_bounty": True,
                        }
                    ],
                    has_next=True,
                )
            )

        with pytest.raises(RuntimeError, match="partial scope"):
            fetch_program_scope("crypto", opener=opener)
        assert calls["n"] == MAX_PAGES

    def test_missing_cursor_with_more_pages_raises(self):
        def opener(_request: Any, timeout: float = 0) -> _FakeResponse:
            payload = _team_payload([], has_next=True)
            payload["data"]["team"]["structured_scopes"]["pageInfo"]["endCursor"] = None
            return _FakeResponse(payload)

        with pytest.raises(RuntimeError, match="no pagination cursor"):
            fetch_program_scope("crypto", opener=opener)

    def test_missing_team_raises(self):
        def opener(_request: Any, timeout: float = 0) -> _FakeResponse:
            return _FakeResponse({"data": {"team": None}})

        with pytest.raises(RuntimeError, match="not found"):
            fetch_program_scope("ghost-program", opener=opener)

    def test_execute_surfaces_paste_suggestion_on_failure(self):
        def boom(_request: Any, timeout: float = 0) -> Any:
            raise urllib.error.URLError("offline")

        # Patch at urllib level through execute path by patching fetch.
        # Use direct execute with monkeypatched fetch via args only after
        # extract fails... better: stub open via broken domain handle using
        # monkeypatch on module.
        from vulnclaw.agent import hackerone_scope as mod

        original = mod.fetch_program_scope

        def fail(seed: str, **kwargs: Any) -> Any:
            raise RuntimeError("network down")

        mod.fetch_program_scope = fail  # type: ignore[assignment]
        try:
            out = execute_hackerone_scope({"program": "crypto"})
        finally:
            mod.fetch_program_scope = original  # type: ignore[assignment]
        assert out.startswith("[!] failed to load HackerOne scope:")
        assert "paste" in out.lower()


class TestExplicitSkillInjection:
    def test_explicit_hackerone_injects_skill_body(self):
        from vulnclaw.agent.skill_context import get_active_skill_context

        ctx = get_active_skill_context(
            "Use VulnClaw skill hackerone. https://hackerone.com/crypto/policy_scopes"
        )
        assert ctx is not None
        assert "Active skill (explicit invocation)" in ctx
        assert "hackerone_scope" in ctx
        assert "Never treat `hackerone.com` as the recon/pentest target" in ctx
        # optional-index disclaimer must not apply to explicit launch
        assert "optional reference material only" not in ctx.lower()

    def test_keyword_match_still_optional_index_only(self):
        from vulnclaw.agent.skill_context import get_active_skill_context

        ctx = get_active_skill_context("对这个APP做逆向分析")
        assert ctx is not None
        assert "optional reference material only" in ctx.lower()
        assert "Active skill (explicit invocation)" not in ctx
