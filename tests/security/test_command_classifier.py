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
        "md5sum payload.bin",
        "whoami && uname -a",  # sequencing of allowed commands
        "cd /tmp && ls -la",  # env-agnostic cd + allow
        "grep --include=*.py pattern src/",  # assignment-looking args after the command stay allowed
        "cut -d= -f1 data.txt",  # '=' inside argument values is not an assignment prefix
    ],
)
def test_allow_readonly_table(command):
    assert classify_shell_command(command).decision == "allow"


@pytest.mark.parametrize(
    "command,fragment",
    [
        ("git status", "not in the trusted command table"),
        ("git push origin main", "not in the trusted command table"),
        ("git reset --hard HEAD", "not in the trusted command table"),
        ("sort -o /tmp/out input", "not in the trusted command table"),
        ("uniq input /tmp/out", "not in the trusted command table"),
        ("diff --output=/tmp/out before after", "writes to a file"),
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
        ('echo "$(whoami)"', "quoted substitution"),
        ('printf "`whoami`"', "quoted substitution"),
        ("echo hi | nc host port", "never auto-approved"),  # nc banned
    ],
)
def test_prompt_with_reason(command, fragment):
    verdict = classify_shell_command(command)
    assert verdict.decision == "prompt"
    assert fragment in verdict.reason


class TestLeadingEnvAssignments:
    """``sh -c`` applies FOO=bar prefixes before command lookup.

    A leading ``PATH=`` hijacks the binary search and ``LD_PRELOAD`` /
    ``GIT_EXEC_PATH`` inject code into the allowlisted binary itself, so an
    assignment prefix must never be stripped away and auto-approved.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "PATH=/tmp/evil ls",  # binary-search hijack (verified RCE)
            "LD_PRELOAD=/tmp/evil.so cat /etc/passwd",  # loader injection
            "DYLD_INSERT_LIBRARIES=/tmp/evil.dylib file report.pdf",
            "GIT_EXEC_PATH=/tmp/evil git status",  # git helper hijack
            "PYTHONPATH=/tmp/evil ls",  # unknown name anyway, keep prompt
            "FOO=1 BAR=2 ls",  # multiple assignments
            "FOO=1",  # assignment-only segment
            "PATH=/usr/bin:/bin grep -r x /etc",  # benign value, still prompt
        ],
    )
    def test_assignment_prefix_never_auto_approves(self, command):
        assert classify_shell_command(command).decision == "prompt"

    def test_assignment_prefix_reports_specific_reason(self):
        verdict = classify_shell_command("PATH=/tmp/evil ls")
        assert "environment assignment" in verdict.reason

    def test_compound_with_one_assignment_segment_prompts(self):
        # Only one segment is tainted; the whole command still needs approval.
        verdict = classify_shell_command("cat /etc/hostname; PATH=/tmp/evil ls")
        assert verdict.decision == "prompt"
        assert "environment assignment" in verdict.reason

    def test_trusted_prefix_cannot_override_assignment_guard(self):
        trusted, _ = parse_trusted_commands(["ls -la"])
        verdict = classify_shell_command(
            "LD_PRELOAD=/tmp/evil.so ls -la", trusted
        )
        assert verdict.decision == "prompt"


def test_pipeline_splits_and_evaluates_each_side():
    # codex parity: pipelines are decomposed; every segment must qualify.
    assert classify_shell_command("ls | wc -l").decision == "allow"
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
        assert classify_shell_command("git status", prefixes).decision == "prompt"
        verdict = classify_shell_command("git push", prefixes)
        assert verdict.decision == "prompt"

    def test_explicit_git_prefix_can_override_builtin_absence(self):
        prefixes, _ = parse_trusted_commands(["git push"])
        assert classify_shell_command("git push origin main", prefixes).decision == "allow"

    def test_banned_extension_refused_with_warning(self):
        prefixes, warnings = parse_trusted_commands(["bash -c", "sudo nmap"])
        assert prefixes == (("sudo", "nmap"),) or prefixes == ()
        assert any("'bash'" in w for w in warnings)

    def test_case_insensitive_binary_match(self):
        prefixes, _ = parse_trusted_commands(["NMAP"])
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
