"""Tests for vulnclaw.agent.token_counter — estimation + sliding-window truncation."""

from vulnclaw.agent.token_counter import (
    estimate_message_tokens,
    estimate_tokens,
    truncate_messages,
)


class TestEstimateTokens:
    def test_empty_list(self):
        assert estimate_tokens([]) == 0

    def test_string_content(self):
        msg = {"role": "user", "content": "a" * 400}
        n = estimate_message_tokens(msg)
        # ~400/4 = 100, plus overheads
        assert 100 <= n <= 115

    def test_none_content(self):
        msg = {"role": "assistant", "content": None}
        # Only role + message overhead, no content
        assert estimate_message_tokens(msg) > 0

    def test_multimodal_list_content(self):
        msg = {
            "role": "user",
            "content": [
                {"type": "text", "text": "x" * 40},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
            ],
        }
        n = estimate_message_tokens(msg)
        # text ~10 + image fixed 256 + overhead
        assert n > 256

    def test_tool_calls(self):
        msg = {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "call_123",
                    "type": "function",
                    "function": {"name": "python_execute", "arguments": '{"code": "print(1)"}'},
                }
            ],
        }
        n = estimate_message_tokens(msg)
        bare = estimate_message_tokens({"role": "assistant", "content": ""})
        assert n > bare

    def test_tool_role_message(self):
        msg = {"role": "tool", "tool_call_id": "call_123", "content": "result text"}
        assert estimate_message_tokens(msg) > 0

    def test_total_is_sum(self):
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hello"},
        ]
        assert estimate_tokens(msgs) == sum(estimate_message_tokens(m) for m in msgs)

    def test_non_dict_message(self):
        assert estimate_message_tokens("raw string") > 0


class TestTruncateMessages:
    def _msgs(self, n: int, size: int = 400):
        out = [{"role": "system", "content": "S" * size}]
        for i in range(n):
            role = "user" if i % 2 == 0 else "assistant"
            out.append({"role": role, "content": f"{i}" + "M" * size})
        return out

    def test_no_truncation_under_budget(self):
        msgs = self._msgs(3)
        result = truncate_messages(msgs, max_tokens=1_000_000)
        assert result == msgs

    def test_empty_list(self):
        assert truncate_messages([], max_tokens=100) == []

    def test_single_message(self):
        msgs = [{"role": "system", "content": "x" * 10000}]
        result = truncate_messages(msgs, max_tokens=10)
        # System preserved, nothing else to drop
        assert result == msgs

    def test_preserves_system_prompt(self):
        msgs = self._msgs(20)
        result = truncate_messages(msgs, max_tokens=600, preserve_system=True)
        assert result[0]["role"] == "system"
        assert result[0]["content"] == msgs[0]["content"]

    def test_preserves_recent_messages(self):
        msgs = self._msgs(20)
        result = truncate_messages(msgs, max_tokens=600, min_recent=4)
        # Last 4 original messages must survive at the tail
        assert result[-4:] == msgs[-4:]

    def test_inserts_truncation_notice(self):
        from vulnclaw.i18n import current_lang, init_i18n

        previous_lang = current_lang()
        init_i18n(lang="zh")  # notice text is localized; pin Chinese for the assertion
        try:
            msgs = self._msgs(20)
            result = truncate_messages(msgs, max_tokens=600)
            notices = [m for m in result if "上下文截断" in str(m.get("content", ""))]
            assert len(notices) == 1
            # Notice sits right after the system prompt
            assert result[1] is notices[0]
        finally:
            init_i18n(lang=previous_lang)

    def test_result_fits_budget(self):
        msgs = self._msgs(40)
        budget = 1500
        result = truncate_messages(msgs, max_tokens=budget)
        assert estimate_tokens(result) <= budget

    def test_drops_oldest_middle_first(self):
        msgs = self._msgs(20)
        result = truncate_messages(msgs, max_tokens=900, min_recent=4)
        kept_contents = {m["content"] for m in result}
        # The very first body message (oldest) should be gone
        assert msgs[1]["content"] not in kept_contents
        # A later body message should be kept
        assert msgs[-2]["content"] in kept_contents

    def test_no_system_when_preserve_false(self):
        msgs = self._msgs(20)
        result = truncate_messages(msgs, max_tokens=600, preserve_system=False)
        # First message treated as ordinary body; may or may not survive,
        # but it is not force-preserved
        assert estimate_tokens(result) <= 600 + estimate_message_tokens(msgs[-1])

    def test_zero_max_tokens_returns_copy(self):
        msgs = self._msgs(3)
        result = truncate_messages(msgs, max_tokens=0)
        assert result == msgs
        assert result is not msgs

    def test_few_messages_than_min_recent(self):
        msgs = [
            {"role": "system", "content": "S" * 5000},
            {"role": "user", "content": "U" * 5000},
        ]
        result = truncate_messages(msgs, max_tokens=10, min_recent=4)
        # Body has only 1 message <= min_recent, so nothing dropped
        assert result == msgs


def test_truncation_never_orphans_tool_result_at_recent_boundary():
    messages = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "A" * 1200},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "call-1",
                    "type": "function",
                    "function": {"name": "probe", "arguments": "{}"},
                }
            ],
        },
        {"role": "tool", "tool_call_id": "call-1", "content": "result"},
        {"role": "assistant", "content": "observed"},
        {"role": "user", "content": "next"},
        {"role": "assistant", "content": "working"},
    ]

    result = truncate_messages(messages, max_tokens=80, min_recent=4)

    tool_index = next(
        index for index, message in enumerate(result) if message.get("role") == "tool"
    )
    assistant = result[tool_index - 1]
    assert assistant.get("role") == "assistant"
    assert {call["id"] for call in assistant["tool_calls"]} == {"call-1"}


def test_truncation_keeps_assistant_and_all_tool_results_together():
    tool_exchange = [
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "call-1",
                    "type": "function",
                    "function": {"name": "probe", "arguments": "{}"},
                },
                {
                    "id": "call-2",
                    "type": "function",
                    "function": {"name": "probe", "arguments": "{}"},
                },
            ],
        },
        {"role": "tool", "tool_call_id": "call-1", "content": "one"},
        {"role": "tool", "tool_call_id": "call-2", "content": "two"},
    ]
    messages = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "A" * 1200},
        *tool_exchange,
        {"role": "assistant", "content": "observed"},
    ]

    result = truncate_messages(messages, max_tokens=120, min_recent=2)

    present = [message for message in result if message.get("role") in {"assistant", "tool"}]
    assert present[:3] == tool_exchange
