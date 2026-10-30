"""실제 worker 진입점에서 승인된 2025 정책을 검증한다."""

from app.schemas.finding import Severity
from app.services.classification.pipeline import classify
from app.services.classification.risk import calculate_grade, summarize


def test_missing_columns_and_secrets_are_not_merged(mock_findings):
    result = classify(mock_findings)
    assert len(result) == len(mock_findings)
    assert all(f.duplicate_count == 1 for f in result)


def test_cwe_and_owasp_mapping(mock_findings):
    result = classify(mock_findings)
    sql = next(f for f in result if "CWE-89" in f.cwe)
    assert sql.owasp_top10 == "A05:2025"
    assert all("2021" not in c for f in result for c in f.owasp)
    assert summarize(result)["owasp_version"] == "2025"


def test_priority_no_test_path_penalty(mock_findings):
    result = classify(mock_findings)
    assert [f.priority for f in result] == list(range(1, len(result) + 1))
    assert result[0].severity == Severity.CRITICAL
    assert all("assessment" in f.raw and "sources" in f.raw for f in result)


def test_grade_and_summary(mock_findings):
    result = classify(mock_findings)
    assert calculate_grade(result) == "E"
    assert calculate_grade([]) == "A"
    assert summarize(result)["total"] == len(result)


def test_worker_cvss_priority_and_no_raw_secret(mock_findings):
    source = mock_findings[0].model_copy(deep=True)
    source.cvss_score = 9.8
    source.cvss_version = "3.1"
    source.raw = {"Secret": "mock-sensitive-value"}
    source.location.snippet = "mock-sensitive-value"
    source.title = source.message = "mock-sensitive-value"
    item = classify([source])[0]
    assert item.severity == Severity.CRITICAL
    assert item.risk_score == 98
    assert "mock-sensitive-value" not in item.model_dump_json()


def test_deterministic_input_order(mock_findings):
    assert classify(mock_findings) == classify(mock_findings[::-1])


def test_precise_duplicates_merge_and_cvss_wins_tie(mock_findings):
    first = mock_findings[0].model_copy(deep=True)
    first.location.start_column = 1
    first.location.end_column = 10
    first.severity = Severity.HIGH
    second = first.model_copy(deep=True)
    second.cvss_score = 7.5
    second.cvss_version = "3.1"
    rows = classify([first, second])
    assert len(rows) == 1
    assert rows[0].duplicate_count == 2
    assert rows[0].risk_score == 75
    assert len(rows[0].raw["sources"]) == 2


def test_missing_severity_is_unknown(mock_findings):
    from app.schemas.finding import NormalizedFinding

    data = mock_findings[0].model_dump()
    data.pop("severity")
    result = classify([NormalizedFinding.model_validate(data)])
    assert result[0].severity == Severity.UNKNOWN
    assert calculate_grade(result) == "U"
