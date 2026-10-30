import json

import pytest

from app.services.classification.core.service import build_report, classify, get_detail, load_mapping, risk

from .test_dedup import finding


def report(rows, **changes):
    return build_report(
        "mock-analysis",
        rows,
        repository_id="mock-repo",
        commit_sha="mock-commit",
        tool_statuses=dict(semgrep="success", osv="success", gitleaks="success") | changes,
    )


def test_official_mapping():
    mapping = load_mapping()
    assert len(mapping["categories"]) == 10
    result = classify([finding(cwe_ids=["CWE-89"])], mapping)
    assert "A05:2025" in result["owasp_categories"]


def test_unmapped_is_not_guessed():
    result = classify([finding(cwe_ids=["CWE-999999", "invalid"])], load_mapping())
    assert result["cwe_ids"] == []
    assert result["unresolved_cwe_count"] == 2
    assert result["owasp_categories"] == []


@pytest.mark.parametrize(
    "score,level",
    [
        (0, "info"),
        (0.1, "low"),
        (3.9, "low"),
        (4, "medium"),
        (6.9, "medium"),
        (7, "high"),
        (8.9, "high"),
        (9, "critical"),
        (10, "critical"),
    ],
)
def test_cvss_boundaries(score, level):
    assert risk(finding(cvss_score=score, cvss_version="3.1", severity_original="critical"))["level"] == level


def test_missing_risk():
    assert risk(finding())["level"] == "unknown"


def test_report_and_detail():
    result = report(
        [finding(), finding("two"), finding("three", rule_id="different", cvss_score=9.8, cvss_version="3.1")]
    )
    assert result["raw_count"] == 3
    assert result["vulnerability_count"] == 2
    assert result["vulnerabilities"][0]["risk"]["level"] == "critical"
    identifier = result["vulnerabilities"][0]["vulnerability_id"]
    assert get_detail(result, identifier)["risk"]["level"] == "critical"
    with pytest.raises(KeyError):
        get_detail(result, "absent")


def test_empty_failed_run_not_success():
    result = report([], semgrep="failed")
    assert not result["complete"]
    assert result["vulnerability_count"] == 0


def test_sensitive_input_not_in_public_output_or_logs(caplog):
    marker = "mock-secret-never-export"
    row = finding(
        marker,
        tool="gitleaks",
        kind="secret",
        rule_id=marker,
        locations=[dict(path=marker, start_line=1, end_line=1)],
        evidence_refs=[marker],
    )
    result = report([row])
    assert marker not in json.dumps(result)
    assert marker not in json.dumps(get_detail(result, result["vulnerabilities"][0]["vulnerability_id"]))
    assert marker not in caplog.text


def test_multi_category_and_missing_cwe():
    mapping = load_mapping()
    categories = mapping["categories"][:2]
    cwes = [row["cwes"][0] for row in categories]
    result = classify([finding(cwe_ids=cwes)], mapping)
    assert set(row["category"] for row in categories) <= set(result["owasp_categories"])
    assert classify([finding()], mapping)["cwe_status"] == "unmapped"


def test_unknown_last_and_input_order_independent():
    rows = [finding(), finding("second", rule_id="other", severity_original="high")]
    assert report(rows) == report(rows[::-1])
    assert report(rows)["vulnerabilities"][-1]["risk"]["level"] == "unknown"
