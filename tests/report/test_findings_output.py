"""Tests for structured findings output — findings.json + SARIF 2.1.0 emitter.

Drives the public seams of vulnclaw/report/findings_output.py and asserts on the
observable artifact shape:
- inclusion gate: only verification_status == "verified" reaches the verified set
  and SARIF; rejected/candidate present in findings.json but excluded from SARIF,
- SARIF: web findings → logicalLocations + synthetic anchor; code findings →
  physicalLocation from code_location; evidence_refs → artifactLocation attachments;
  cwe → rule/result properties + taxonomies,
- structural validity against the SARIF 2.1.0 shape (stdlib checks, no validator).
"""

import json

from tests.reporting_fixtures import assessed_findings, assessed_snapshot
from vulnclaw.agent.context import EvidenceRef, SessionState, VulnerabilityFinding
from vulnclaw.findings.types import FindingAssessment
from vulnclaw.report.findings_output import (
    build_findings_document,
    is_report_included,
    to_sarif,
    write_findings_artifacts,
)


def _verified(**kwargs) -> VulnerabilityFinding:
    finding = VulnerabilityFinding(**kwargs)
    finding.mark_verified(note="confirmed", evidence_level="L4")
    finding.assessment = FindingAssessment(outcome="verified", method="poc", reason="Controlled test result")
    return assessed_findings([finding])[0]


def _web_finding() -> VulnerabilityFinding:
    return _verified(
        title="SQLi in login",
        severity="Critical",
        vuln_type="SQLi",
        impact="Full DB compromise",
        evidence="error-based extraction",
        cwe="CWE-89",
        cvss=9.8,
        endpoint="https://shop.example.com/login",
        method="POST",
        subagent_provenance={"task_id": "b1.t1", "agent_id": "w1"},
        evidence_refs=[
            EvidenceRef(kind="http_capture", path="http/req-9.json", request_id="req-9"),
            EvidenceRef(kind="sandbox_output", path="sandbox/sqli/out.txt"),
        ],
    )


def _code_finding() -> VulnerabilityFinding:
    return _verified(
        title="Hardcoded AWS key",
        severity="High",
        vuln_type="Secret",
        evidence="literal key in source",
        cwe="CWE-798",
        code_location="src/config/settings.py:128:5",
    )


def _make_mixed_session() -> SessionState:
    state = SessionState(target="https://shop.example.com")
    state.add_finding(_web_finding())
    state.add_finding(_code_finding())

    rejected = VulnerabilityFinding(
        title="Bogus XSS", severity="Medium", vuln_type="XSS", evidence="maybe"
    )
    rejected.mark_rejected(reason="false positive")
    rejected.assessment = FindingAssessment(outcome="rejected", method="poc", reason="Controlled exclusion")
    state.add_finding(rejected)

    # candidate (has vuln_type so it isn't intake-quarantined)
    state.add_finding(
        VulnerabilityFinding(
            title="Weak header", severity="Low", vuln_type="Info Leak", evidence="server header"
        )
    )
    for finding in state.findings:
        if finding.assessment is None:
            finding.assessment = FindingAssessment(outcome="suspected_low", method="evidence_review", reason="Indirect evidence")
    return state


class TestInclusionGate:
    def test_gate_predicate(self):
        assert is_report_included(_web_finding())
        rejected = VulnerabilityFinding(title="x", vuln_type="XSS", evidence="e")
        rejected.mark_rejected(reason="fp")
        assert not is_report_included(rejected)
        candidate = VulnerabilityFinding(title="y", vuln_type="XSS", evidence="e")
        assert not is_report_included(candidate)


class TestFindingsDocument:
    def test_all_findings_present_verified_subset_gated(self):
        session = _make_mixed_session()
        doc = build_findings_document(assessed_snapshot(session))

        assert doc["schema_version"] == "1.2"
        assert doc["tool"]["name"] == "VulnClaw"
        assert doc["target"] == "https://shop.example.com"

        # findings.json carries ALL findings, including rejected/candidate.
        titles = {f["title"] for f in doc["findings"]}
        assert "SQLi in login" in titles
        assert "Bogus XSS" in titles  # rejected present for audit
        assert any("Weak header" in t for t in titles)  # candidate present
        assert doc["summary"]["total"] == 4

        # verified subset only contains verification_status == "verified"
        verified_titles = {f["title"] for f in doc["verified"]}
        assert verified_titles == {"SQLi in login", "Hardcoded AWS key"}
        assert doc["summary"]["verified"] == 2
        assert doc["summary"]["rejected"] == 1

    def test_summary_verified_matches_deduped_array(self):
        # Two identical verified findings dedup to one in the `verified` array;
        # summary.verified must track that deduplicated length, not the raw bucket
        # count over all findings (which would report 2 and break consumers).
        kwargs = dict(
            title="SQLi in login",
            severity="Critical",
            vuln_type="SQLi",
            evidence="error-based extraction confirms injectable id param on /login?id=1",
        )
        state = SessionState(target="https://shop.example.com")
        # bypass add_finding's exact dedup so both raw findings live in state.findings
        state.findings.append(_verified(**kwargs))
        state.findings.append(_verified(**kwargs))

        doc = build_findings_document(assessed_snapshot(state))
        assert doc["summary"]["total"] == 2  # every raw finding counted
        assert len(doc["verified"]) == 1  # deduplicated array
        assert doc["summary"]["verified"] == 1  # summary aligned with the array

    def test_findings_json_serializes_evidence_refs(self):
        session = _make_mixed_session()
        doc = build_findings_document(assessed_snapshot(session))
        sqli = next(f for f in doc["findings"] if f["title"] == "SQLi in login")
        refs = sqli["evidence_refs"]
        assert {"kind": "http_capture", "path": "http/req-9.json", "request_id": "req-9"} in refs
        assert {
            "kind": "sandbox_output",
            "path": "sandbox/sqli/out.txt",
            "request_id": None,
        } in refs


class TestSarifShape:
    def _sarif(self):
        return to_sarif(assessed_findings([_web_finding(), _code_finding()]), target="https://shop.example.com")

    def test_top_level_shape(self):
        sarif = self._sarif()
        assert sarif["version"] == "2.1.0"
        assert sarif["$schema"].endswith("sarif-2.1.0.json")
        assert isinstance(sarif["runs"], list) and len(sarif["runs"]) == 1
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "VulnClaw"
        assert isinstance(driver["rules"], list) and driver["rules"]
        # every result references a rule that exists
        rule_ids = {r["id"] for r in driver["rules"]}
        for result in sarif["runs"][0]["results"]:
            assert result["ruleId"] in rule_ids
            assert result["message"]["text"]
            assert result["level"] in ("error", "warning", "note")
            assert result["locations"]

    def test_web_finding_uses_logical_locations_and_synthetic_anchor(self):
        sarif = to_sarif(assessed_findings([_web_finding()]), target="https://shop.example.com")
        result = sarif["runs"][0]["results"][0]
        location = result["locations"][0]
        assert "logicalLocations" in location
        # synthetic physical anchor present (the endpoint URL here)
        anchor = location["physicalLocation"]["artifactLocation"]["uri"]
        assert anchor == "https://shop.example.com/login"
        assert location["logicalLocations"][0]["name"]

    def test_web_finding_without_endpoint_gets_synthetic_uri(self):
        finding = _verified(title="Odd bug", severity="High", vuln_type="Weird", evidence="e")
        sarif = to_sarif(assessed_findings([finding]), target="https://t.example.com")
        anchor = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"]
        assert anchor.startswith("vulnclaw://")

    def test_code_finding_uses_physical_location_and_region(self):
        sarif = to_sarif(assessed_findings([_code_finding()]))
        result = sarif["runs"][0]["results"][0]
        phys = result["locations"][0]["physicalLocation"]
        assert phys["artifactLocation"]["uri"] == "src/config/settings.py"
        assert phys["region"]["startLine"] == 128
        assert phys["region"]["startColumn"] == 5
        # code finding has no synthetic logical location
        assert "logicalLocations" not in result["locations"][0]

    def test_code_location_line_only(self):
        finding = _verified(
            title="Line only", vuln_type="Secret", evidence="e", code_location="a/b.py:7"
        )
        phys = to_sarif(assessed_findings([finding]))["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert phys["artifactLocation"]["uri"] == "a/b.py"
        assert phys["region"] == {"startLine": 7}

    def test_evidence_refs_become_artifact_locations(self):
        sarif = to_sarif(assessed_findings([_web_finding()]))
        result = sarif["runs"][0]["results"][0]
        attachments = result["attachments"]
        uris = {a["artifactLocation"]["uri"] for a in attachments}
        assert uris == {"http/req-9.json", "sandbox/sqli/out.txt"}
        kinds = {a["description"]["text"] for a in attachments}
        assert kinds == {"http_capture", "sandbox_output"}
        # request_id surfaces on the artifactLocation description
        http_att = next(a for a in attachments if a["artifactLocation"]["uri"] == "http/req-9.json")
        assert "req-9" in http_att["artifactLocation"]["description"]["text"]

    def test_subagent_provenance_reaches_sarif_properties(self):
        result = to_sarif(assessed_findings([_web_finding()]))["runs"][0]["results"][0]
        assert result["properties"]["subagent_provenance"]["task_id"] == "b1.t1"

    def test_cwe_populates_taxonomies_and_properties(self):
        sarif = self._sarif()
        run = sarif["runs"][0]
        taxonomy = run["taxonomies"][0]
        assert taxonomy["name"] == "CWE"
        taxa_ids = {t["id"] for t in taxonomy["taxa"]}
        assert taxa_ids == {"CWE-89", "CWE-798"}

        # rule carries cwe in properties + tag
        rule = run["tool"]["driver"]["rules"][0]
        assert rule["properties"]["cwe"] in ("CWE-89", "CWE-798")
        assert any(tag.startswith("external/cwe/") for tag in rule["properties"]["tags"])

        # result references the CWE taxon and echoes cvss/severity in properties
        sqli_result = next(r for r in run["results"] if r["properties"].get("cwe") == "CWE-89")
        assert sqli_result["taxa"][0]["id"] == "CWE-89"
        assert sqli_result["properties"]["cvss"] == 9.8
        assert sqli_result["properties"]["severity"] == "Critical"
        assert sqli_result["properties"]["http_method"] == "POST"

    def test_empty_findings_produce_valid_empty_run(self):
        sarif = to_sarif(assessed_findings([]))
        run = sarif["runs"][0]
        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []
        assert "taxonomies" not in run


class TestWriteArtifacts:
    def test_writes_both_files(self, tmp_path):
        session = _make_mixed_session()
        paths = write_findings_artifacts(assessed_snapshot(session), tmp_path / "findings")

        json_path = paths["findings_json"]
        sarif_path = paths["findings_sarif"]
        assert json_path.exists() and sarif_path.exists()
        assert json_path.name == "findings.json"
        assert sarif_path.name == "findings.sarif"

        doc = json.loads(json_path.read_text(encoding="utf-8"))
        assert doc["summary"]["total"] == 4

        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
        # SARIF only contains the two verified findings.
        assert len(sarif["runs"][0]["results"]) == 2
        result_titles = {r["message"]["text"].split(" — ")[0] for r in sarif["runs"][0]["results"]}
        assert "Bogus XSS" not in result_titles

    async def test_generate_report_emits_findings_dir(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        session = _make_mixed_session()
        await generate_report(assessed_snapshot(session), str(tmp_path / "report.md"))
        assert (tmp_path / "report.artifacts" / "findings" / "findings.json").exists()
        assert (tmp_path / "report.artifacts" / "findings" / "findings.sarif").exists()

    async def test_persistent_cycle_report_emits_findings_dir(self, tmp_path):
        from vulnclaw.report.generator import generate_persistent_cycle_report

        session = _make_mixed_session()
        await generate_persistent_cycle_report(
            assessed_snapshot(session),
            cycle_num=1,
            output_path=str(tmp_path / "cycle.md"),
        )
        assert (tmp_path / "cycle.artifacts" / "findings" / "findings.json").exists()
        assert (tmp_path / "cycle.artifacts" / "findings" / "findings.sarif").exists()
