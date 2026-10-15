"""Unit tests for the headless scan-mode presets and exit-code contract."""

from __future__ import annotations

import json

from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.headless import (
    DEFAULT_FAIL_ON,
    EXIT_CANDIDATES,
    EXIT_CLEAN,
    EXIT_ERROR,
    EXIT_VERIFIED,
    FindingClassification,
    ScanProfile,
    build_run_summary,
    classify_report_findings,
    determine_exit_code,
    effective_scope_mode,
    resolve_scan_profile,
    run_directory,
    scan_mode_profile,
    write_run_artifacts,
)


class TestScanModePresets:
    def test_standard_mirrors_config_session_values(self):
        config = VulnClawConfig()
        profile = scan_mode_profile(config, "standard")
        s = config.session
        assert profile.max_steps == s.solve_max_steps
        assert profile.max_directions == s.solve_max_directions
        assert profile.max_tool_rounds == s.solve_max_tool_rounds
        assert profile.max_parallel == s.solve_max_parallel
        assert profile.max_rounds == s.max_rounds
        assert profile.scan_mode == "standard"

    def test_quick_turns_fan_out_off_and_shrinks_effort(self):
        config = VulnClawConfig()
        profile = scan_mode_profile(config, "quick")
        assert profile.max_parallel == 1  # fan-out off (single agent)
        assert profile.max_steps < config.session.solve_max_steps
        assert profile.max_tool_rounds < config.session.solve_max_tool_rounds
        assert profile.max_steps >= 1

    def test_deep_deepens_effort_and_opens_fan_out(self):
        config = VulnClawConfig()
        profile = scan_mode_profile(config, "deep")
        assert profile.max_steps > config.session.solve_max_steps
        assert profile.max_rounds > config.session.max_rounds
        assert profile.max_parallel >= 12  # full fan-out (~12 concurrent)

    def test_unknown_scan_mode_falls_back_to_standard(self):
        config = VulnClawConfig()
        assert scan_mode_profile(config, "bogus").scan_mode == "standard"

    def test_explicit_flags_override_preset(self):
        config = VulnClawConfig()
        profile = resolve_scan_profile(config, "quick", max_steps=999, max_parallel=7)
        assert profile.max_steps == 999  # explicit override wins
        assert profile.max_parallel == 7
        # untouched knobs keep the quick preset
        assert profile.max_tool_rounds == scan_mode_profile(config, "quick").max_tool_rounds

    def test_resolve_without_overrides_equals_preset(self):
        config = VulnClawConfig()
        assert resolve_scan_profile(config, "deep") == scan_mode_profile(config, "deep")


# ── Exit-code contract ──────────────────────────────────────────────


class TestClassifyFindings:
    def test_counts_current_verified_and_suspected_findings(self):
        c = classify_report_findings({
            "verified": [{"title": "Controlled result"}],
            "findings": [
                {"assessment": {"outcome": outcome}}
                for outcome in ("verified", "suspected_high", "suspected_low", "rejected")
            ],
        })
        assert c.verified == 1
        assert c.candidates == 2

    def test_empty_report(self):
        c = classify_report_findings({"verified": [], "findings": []})
        assert not c.has_verified and not c.has_candidates


class TestExitCodeContract:
    def test_clean_run_returns_zero(self):
        c = FindingClassification(verified=0, candidates=0)
        assert determine_exit_code(c, "verified") == EXIT_CLEAN

    def test_verified_finding_returns_two(self):
        c = FindingClassification(verified=1, candidates=0)
        assert determine_exit_code(c, DEFAULT_FAIL_ON) == EXIT_VERIFIED

    def test_only_candidates_returns_three_under_fail_on_any(self):
        c = FindingClassification(verified=0, candidates=2)
        assert determine_exit_code(c, "any") == EXIT_CANDIDATES

    def test_default_verified_does_not_trip_on_candidates(self):
        c = FindingClassification(verified=0, candidates=2)
        # default policy trips on verified only → candidates do not block
        assert determine_exit_code(c, "verified") == EXIT_CLEAN

    def test_fail_on_any_trips_on_candidates(self):
        c = FindingClassification(verified=0, candidates=1)
        assert determine_exit_code(c, "any") == EXIT_CANDIDATES

    def test_fail_on_never_returns_zero_despite_verified(self):
        c = FindingClassification(verified=3, candidates=1)
        assert determine_exit_code(c, "never") == EXIT_CLEAN

    def test_fail_on_verified_trips_on_verified_only(self):
        assert determine_exit_code(FindingClassification(1, 0), "verified") == EXIT_VERIFIED
        assert determine_exit_code(FindingClassification(0, 5), "verified") == EXIT_CLEAN

    def test_exit_error_is_reserved_and_never_returned_by_contract(self):
        for policy in ("verified", "any", "never"):
            for v in (0, 2):
                for cand in (0, 3):
                    code = determine_exit_code(FindingClassification(v, cand), policy)
                    assert code != EXIT_ERROR


# ── Run artifacts ───────────────────────────────────────────────────


class TestRunArtifacts:
    def test_run_directory_is_slugged_and_deterministic(self, tmp_path):
        d = run_directory(tmp_path, "https://example.com/app", "20260709-abcd")
        assert d.parent == tmp_path
        assert d.name == "https-example.com-app-20260709-abcd"

    def test_write_run_artifacts_writes_summary_json(self, tmp_path):
        config = VulnClawConfig()
        profile = resolve_scan_profile(config, "quick")
        classification = FindingClassification(verified=1, candidates=0)
        summary = build_run_summary(
            target="https://example.com",
            scan_mode="quick",
            scope_mode="auto",
            fail_on="verified",
            profile=profile,
            classification=classification,
            exit_code=EXIT_VERIFIED,
            report_path="/tmp/report.md",
        )
        run_dir = run_directory(tmp_path, "https://example.com", "run1")
        path = write_run_artifacts(run_dir, summary)
        assert path.exists()
        loaded = json.loads(path.read_text())
        assert loaded["target"] == "https://example.com"
        assert loaded["scan_mode"] == "quick"
        assert loaded["scope_mode"] == "auto"
        # auto is recorded but currently degrades to full (Target diff-scope #35)
        assert loaded["scope_mode_effective"] == "full"
        assert loaded["exit_code"] == EXIT_VERIFIED
        assert loaded["findings"] == {"verified": 1, "candidates": 0, "total": 1}
        assert loaded["profile"]["max_parallel"] == 1

    def test_scan_profile_as_dict_roundtrip(self):
        profile = ScanProfile(1, 2, 3, 4, 5, "quick")
        assert profile.as_dict()["scan_mode"] == "quick"

    def test_effective_scope_mode_degrades_auto_to_full(self):
        # auto diff-scoping is not computed here (Target model #35) → falls back
        assert effective_scope_mode("auto") == "full"
        assert effective_scope_mode("full") == "full"
