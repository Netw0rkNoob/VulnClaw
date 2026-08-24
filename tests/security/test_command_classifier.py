"""Unit tests for the Codex-style shell-command classifier."""

from __future__ import annotations

import pytest

from vulnclaw.agent.command_classifier import (
    classify_shell_command,
    parse_trusted_commands,
)


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "cat /etc/hostname",
        "echo hello world",
        "pwd",
        "grep -r pattern src/",
        "find . -name '*.py' -maxdepth 2",
        "file report.pdf",
        "stat /etc/passwd",
        "wc -l main.py",
        "git status",
        "git log --oneline -10",
        "git diff HEAD~1",
        "md5sum payload.bin",
        "whoami && uname -a",  # sequencing of allowed commands
        "cd /tmp && ls -la",  # env-agnostic cd + allow
        "FOO=1 BAR=2 ls",  # leading assignments stripped
    ],
)
def test_allow_readonly_table(command):
    assert classify_shell_command(command).decision == "allow"


@pytest.mark.parametrize(
    "command,fragment",
    [
        ("git push origin main", "read-only subcommand"),
        ("git reset --hard HEAD", "read-only subcommand"),
        ("find . -delete", "-delete"),
        ("find . -name x -exec rm {} ;", "can execute"),
        ("python -c 'print(1)'", "interpreters and shells"),
        ("bash -c 'id'", "interpreters and shells"),
        ("node -e 'require(1)'", "interpreters and shells"),
        ("sudo nmap -p80 h", "'sudo' is never auto-approved"),
        ("/tmp/evil --payload x", "not in the trusted command table"),
        ("ls > /tmp/out.txt", "unsupported shell construct"),
        ("echo $(whoami)", "unsupported shell construct"),
        ("cat `whoami`", "unsupported shell construct"),
        ("echo hi | nc host port", "never auto-approved"),  # nc banned
    ],
)
def test_prompt_with_reason(command, fragment):
    verdict = classify_shell_command(command)
    assert verdict.decision == "prompt"
    assert fragment in verdict.reason


def test_pipeline_splits_and_evaluates_each_side():
    # codex parity: pipelines are decomposed; every segment must qualify.
    assert classify_shell_command("ls | sort").decision == "allow"
    verdict = classify_shell_command("ls | /tmp/evil")
    assert verdict.decision == "prompt"


class TestOperatorExtensions:
    def test_exact_prefix_allows_any_args(self):
        prefixes, _ = parse_trusted_commands(["nmap"])
        assert classify_shell_command(
            "nmap -sV -p1-65535 --script-safe 10.0.0.1", prefixes
        ).decision == "allow"

    def test_multi_token_prefix(self):
        prefixes, _ = parse_trusted_commands(["git diff"])
        assert classify_shell_command("git diff HEAD~3", prefixes).decision == "allow"
        assert (
            classify_shell_command("git status", prefixes).decision == "allow"
        )  # base table still applies
        verdict = classify_shell_command("git push", prefixes)
        assert verdict.decision == "prompt"

    def test_banned_extension_refused_with_warning(self):
        prefixes, warnings = parse_trusted_commands(["bash -c", "sudo nmap"])
        assert prefixes == (("sudo", "nmap"),) or prefixes == ()
        assert any("'bash'" in w for w in warnings)

    def test_case_insensitive_binary_match(self):
        prefixes = (("nmap",),)
        assert (
            classify_shell_command("NMAP -p80 h", prefixes).decision == "allow"
        )

    def test_subsequent_tokens_are_exact(self):
        prefixes = (("nmap", "-sV"),)
        assert (
            classify_shell_command("nmap -sV h", prefixes).decision == "allow"
        )
        # case-sensitive beyond the first token: falls back to base table
        assert (
            classify_shell_command("nmap -sv h", prefixes).decision == "prompt"
        )


class TestEdgeCases:
    def test_empty_command_allows_nothing_to_spawn(self):
        verdict = classify_shell_command("")
        assert verdict.decision == "allow"  # nothing to run

    def test_unterminated_quote_prompts(self):
        assert classify_shell_command('echo "unterminated').decision == "prompt"

    def test_quoted_metachars_are_safe(self):
        assert (
            classify_shell_command(
                "grep -r 'a|b;$(x)' logs/"
            ).decision
            == "allow"
        )
