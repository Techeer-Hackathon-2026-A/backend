"""[백엔드 C] 분류·평가 테스트 (목 데이터 기반)."""

from app.schemas.finding import Severity
from app.services.classification.pipeline import classify
from app.services.classification.risk import calculate_grade, summarize


def test_dedup_merges_same_fingerprint(mock_findings):
    result = classify(mock_findings)
    secret = [f for f in result if f.fingerprint == "mock-secret-ai-3"]
    assert len(secret) == 1
    assert secret[0].duplicate_count == 2
    assert set(secret[0].merged_tools) == {"gitleaks", "semgrep"}
    assert secret[0].severity == Severity.HIGH


def test_cwe_and_owasp_mapping(mock_findings):
    result = {f.fingerprint: f for f in classify(mock_findings)}
    assert result["mock-sqli-users-24"].cwe == ["CWE-89"]
    assert result["mock-sqli-users-24"].owasp_top10 == "A03:2021-Injection"
    assert result["mock-sca-lodash"].owasp_top10 == "A06:2021-Vulnerable and Outdated Components"


def test_priority_and_test_path_penalty(mock_findings):
    result = classify(mock_findings)
    assert [f.priority for f in result] == list(range(1, len(result) + 1))
    scores = [f.risk_score for f in result]
    assert scores == sorted(scores, reverse=True)
    assert result[0].severity in (Severity.CRITICAL, Severity.HIGH)
    test_file = next(f for f in result if f.location.file_path.startswith("tests/"))
    prod_high = next(f for f in result if f.fingerprint == "mock-sqli-users-24")
    assert test_file.risk_score < prod_high.risk_score


def test_grade_and_summary(mock_findings):
    result = classify(mock_findings)
    assert calculate_grade(result) == "E"
    assert calculate_grade([]) == "A"
    assert summarize(result)["total"] == len(result)
