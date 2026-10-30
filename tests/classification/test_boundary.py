import json

import pytest

from app.services.classification.core.boundary import process_batch
from app.services.classification.core.catalog import load_catalog
from app.services.classification.core.service import classify, load_mapping

from .test_dedup import finding


def payload():
    return dict(
        schema_version="1.0",
        analysis_id="mock-analysis",
        repository_id="mock-repo",
        commit_sha="a" * 40,
        data_origin="mock",
        tool_statuses=dict(semgrep="success", osv="success", gitleaks="success"),
        findings=[finding(cwe_ids=["CWE-89"]).model_dump(mode="json")],
    )


def test_full_catalog_cwe_outside_owasp_is_preserved():
    catalog, mapping = load_catalog(), load_mapping()
    mapped = {c for row in mapping["categories"] for c in row["cwes"]}
    identifier = next(
        c for c, value in catalog["weaknesses"].items() if c not in mapped and value["status"] != "Deprecated"
    )
    result = classify([finding(cwe_ids=[identifier])], mapping)
    assert result["cwe_ids"] == [identifier]
    assert result["owasp_categories"] == []
    assert result["unresolved_cwe_count"] == 0


def test_deprecated_cwe_is_not_automatically_reassigned():
    catalog = load_catalog()
    identifier = next(c for c, row in catalog["weaknesses"].items() if row["status"] == "Deprecated")
    result = classify([finding(cwe_ids=[identifier])], load_mapping())
    assert result["deprecated_cwe_ids"] == [identifier]
    assert result["cwe_ids"] == []
    assert result["unresolved_cwe_count"] == 0


def test_valid_batch():
    status, result = process_batch(payload())
    assert status == 200
    assert result["data_origin"] == "mock"
    assert result["vulnerabilities"][0]["classification"]["cwe_ids"] == ["CWE-89"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "2.0"),
        ("commit_sha", "mock-commit"),
        ("analysis_id", "../analysis"),
        ("repository_id", ""),
        ("data_origin", "unknown"),
    ],
)
def test_batch_contract_rejects_invalid_metadata(field, value):
    data = payload() | {field: value}
    assert process_batch(data)[0] == 422


def test_duplicate_ids_and_not_run_rejected():
    data = payload()
    data["findings"] *= 2
    assert process_batch(data)[0] == 422
    data = payload()
    data["tool_statuses"]["semgrep"] = "not_run"
    assert process_batch(data)[0] == 422


def test_errors_do_not_expose_secret_in_field_name_or_value(caplog):
    marker = "mock-sensitive-never-export"
    data = payload()
    data["findings"][0][marker] = marker
    status, result = process_batch(data)
    assert status == 422
    assert marker not in json.dumps(result)
    assert marker not in caplog.text


def test_safe_internal_error(monkeypatch, caplog):
    from app.services.classification.core import boundary

    def fail(*args, **kwargs):
        raise RuntimeError("mock-sensitive-exception")

    monkeypatch.setattr(boundary, "build_report", fail)
    status, result = process_batch(payload())
    assert status == 500
    assert "mock-sensitive-exception" not in json.dumps(result) + caplog.text


def test_output_rejects_unexpected_raw_field(monkeypatch, caplog):
    from app.services.classification.core import boundary

    original = boundary.build_report

    def unsafe(*args, **kwargs):
        return original(*args, **kwargs) | {"raw_secret": "mock-sensitive-output"}

    monkeypatch.setattr(boundary, "build_report", unsafe)
    status, result = process_batch(payload())
    assert status == 500
    assert "mock-sensitive-output" not in json.dumps(result) + caplog.text


def test_nested_output_rejects_raw_fields(monkeypatch):
    from app.services.classification.core import boundary

    original = boundary.build_report

    def unsafe(*args, **kwargs):
        report = original(*args, **kwargs)
        report["vulnerabilities"][0]["raw"] = "secret"
        return report

    monkeypatch.setattr(boundary, "build_report", unsafe)
    assert process_batch(payload())[0] == 500


@pytest.mark.parametrize("data", [None, [], "sensitive malformed input", {}, {"findings": None}])
def test_malformed_batch_is_safe(data):
    status, result = process_batch(data)
    assert status == 422
    assert result == {"error": {"code": "INVALID_INPUT", "message": "입력 데이터가 올바르지 않습니다."}}


def test_success_response_excludes_internal_values(caplog):
    data = payload()
    marker = "mock-sensitive-internal"
    data["findings"][0].update(finding_id=marker, rule_id=marker, evidence_refs=[marker])
    data["findings"][0]["locations"][0]["path"] = marker
    status, result = process_batch(data)
    assert status == 200
    assert marker not in json.dumps(result) + caplog.text
