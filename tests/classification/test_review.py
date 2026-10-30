"""A 연결 없이 실행하는 경계 조건 및 회귀 테스트."""

import pytest
from pydantic import ValidationError

from app.services.classification.core.dedup import merge
from app.services.classification.core.service import build_report, get_detail, risk

from .test_dedup import finding
from .test_service import report


def test_same_line_different_expressions_are_separate():
    other = finding("two", locations=[dict(path="app.py", start_line=3, end_line=3, start_column=20, end_column=30)])
    assert len(merge("a", [finding(), other])) == 2


def test_missing_columns_do_not_imply_same_expression():
    location = [dict(path="app.py", start_line=3, end_line=3)]
    assert len(merge("a", [finding("a", locations=location), finding("b", locations=location)])) == 2


def test_distinct_vulnerability_ids_do_not_merge():
    assert (
        len(
            merge(
                "a",
                [finding("a", vulnerability_ids=["CVE-2025-0001"]), finding("b", vulnerability_ids=["CVE-2025-0002"])],
            )
        )
        == 2
    )


@pytest.mark.parametrize("path", ["../x", "..\\x", "/etc/passwd", "C:\\key", "\\\\server\\key", ".", "x\x00y", "x\ny"])
def test_unsafe_paths(path):
    with pytest.raises(ValidationError):
        finding(locations=[dict(path=path, start_line=1, end_line=1)])


@pytest.mark.parametrize(
    "columns", [dict(start_column=3), dict(start_column=4, end_column=2), dict(start_column=0, end_column=1)]
)
def test_invalid_columns(columns):
    with pytest.raises(ValidationError):
        finding(locations=[dict(path="app.py", start_line=1, end_line=1, **columns)])


def test_manifest_traversal_rejected():
    from app.services.classification.core.models import Package

    with pytest.raises(ValidationError):
        Package(ecosystem="PyPI", name="x", version="1", manifest="../requirements.txt")


def test_input_status_mutation_cannot_change_report():
    statuses = dict(semgrep="success", osv="success", gitleaks="success")
    result = build_report("a", [], repository_id="r", commit_sha="c", tool_statuses=statuses)
    statuses["semgrep"] = "failed"
    assert result["tool_statuses"]["semgrep"] == "success"


def test_detail_is_a_deep_copy():
    result = report([finding()])
    detail = get_detail(result, result["vulnerabilities"][0]["vulnerability_id"])
    detail["risk"]["level"] = "critical"
    assert result["vulnerabilities"][0]["risk"]["level"] == "unknown"


def test_not_run_with_findings_rejected():
    with pytest.raises(ValueError):
        report([finding()], semgrep="not_run")


def test_whitespace_severity():
    assert risk(finding(severity_original=" HIGH "))["level"] == "high"


def test_partial_run_preserves_findings():
    result = report([finding()], semgrep="partial")
    assert not result["complete"]
    assert result["vulnerability_count"] == 1


def test_analysis_ids_scope_vulnerability_identity():
    assert merge("a", [finding()])[0].vulnerability_id != merge("b", [finding()])[0].vulnerability_id
