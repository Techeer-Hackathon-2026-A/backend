"""실제 DB/HTTP/worker 연결. 외부 스캐너·Git·Redis는 목으로 대체한다."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest


@pytest.fixture
def stored(client, mock_findings):
    from app.core.database import SessionLocal
    from app.models import Project, Scan
    from app.services.classification.pipeline import classify
    from app.services.classification.risk import calculate_grade, summarize
    from app.workers.tasks import _to_entity

    with SessionLocal() as db:
        project = Project(repo_url="https://github.com/mock/classification", owner="mock", name="classification")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id)
        db.add(scan)
        db.flush()
        rows = classify(mock_findings)
        db.add_all(_to_entity(scan.id, row) for row in rows)
        scan.summary = summarize(rows)
        scan.grade = calculate_grade(rows)
        db.commit()
        return scan.id


def test_existing_http_contract_and_2025(client, stored):
    result = client.get(f"/api/v1/scans/{stored}/report")
    assert result.status_code == 200
    assert set(result.json()) == {
        "scan_id",
        "grade",
        "total",
        "by_severity",
        "by_category",
        "owasp_matrix",
        "top_findings",
    }
    assert all(":2025" in key for key in result.json()["owasp_matrix"])
    rows = client.get(f"/api/v1/scans/{stored}/findings").json()
    assert rows
    sql = next(row for row in rows if "CWE-89" in row["cwe"])
    assert sql["owasp_top10"] == "A05:2025"
    detail = client.get(f"/api/v1/findings/{sql['id']}").json()
    assert "A05:2025" in detail["owasp"]
    assert "raw" not in detail
    assert detail["snippet"] is None


def test_filter_pagination_and_safe_validation(client, stored):
    result = client.get(f"/api/v1/scans/{stored}/findings", params={"owasp": "A05:2025", "limit": 1})
    assert result.status_code == 200
    assert len(result.json()) == 1
    assert result.json()[0]["owasp_top10"] == "A05:2025"
    marker = "mock-sensitive-validation"
    response = client.get(f"/api/v1/scans/{stored}/findings", params={"limit": marker})
    assert response.status_code == 422
    assert marker not in response.text
    assert client.get("/api/v1/scans/99999/findings").status_code == 404
    assert client.get("/api/v1/findings/99999").status_code == 404


def test_non_primary_category_filter(client, stored):
    from app.core.database import SessionLocal
    from app.models import Finding

    with SessionLocal() as db:
        row = db.query(Finding).filter(Finding.scan_id == stored).first()
        row.owasp = ["A01:2025", "A05:2025"]
        row.owasp_top10 = "A01:2025"
        identifier = row.id
        db.commit()
    response = client.get(f"/api/v1/scans/{stored}/findings", params={"owasp": "A05:2025"})
    assert response.status_code == 200
    assert identifier in [row["id"] for row in response.json()]


def test_repository_failure_does_not_log_input(client, monkeypatch, caplog):
    from app.services.classification.repository import SQLReportRepository

    def fail(*args, **kwargs):
        raise RuntimeError("mock-sensitive-db-error")

    monkeypatch.setattr(SQLReportRepository, "finding", fail)
    response = client.get("/api/v1/findings/1")
    assert response.status_code == 500
    assert "mock-sensitive-db-error" not in response.text + caplog.text


def test_a_authorization_dependency_can_guard_all_report_routes(client):
    from fastapi import HTTPException

    from app.api.v1.endpoints.reports import get_report_repository
    from app.main import app

    def denied():
        raise HTTPException(403, "접근 권한이 없습니다")

    app.dependency_overrides[get_report_repository] = denied
    try:
        for path in ["/scans/1/report", "/scans/1/findings", "/findings/1"]:
            assert client.get("/api/v1" + path).status_code == 403
    finally:
        app.dependency_overrides.pop(get_report_repository)


def test_old_secret_row_is_safe_for_http_and_d(client, stored):
    from app.core.database import SessionLocal
    from app.models import Finding
    from app.services.classification.handoff import build_fix_context

    with SessionLocal() as db:
        row = db.query(Finding).filter(Finding.scan_id == stored, Finding.category == "secret").first()
        marker = "mock-sensitive-old-row"
        row.title = row.message = row.snippet = row.rule_id = row.file_path = marker
        row.raw = {"Secret": marker}
        db.commit()
        identifier = row.id
        assert marker not in str(build_fix_context(row))
        assert not build_fix_context(row)["automatic_fix_allowed"]
    response = client.get(f"/api/v1/findings/{identifier}")
    assert response.status_code == 200
    assert marker not in response.text
    assert marker not in client.get(f"/api/v1/scans/{stored}/report").text


@pytest.mark.parametrize("failed_tools", [[], ["semgrep"], ["semgrep", "osv-scanner", "gitleaks"]])
def test_worker_executes_new_pipeline(client, mock_findings, monkeypatch, tmp_path, failed_tools):
    from app.core.database import SessionLocal
    from app.models import Finding, Project, Scan
    from app.workers import tasks

    with SessionLocal() as db:
        project = Project(repo_url="https://github.com/mock/worker", owner="mock", name="worker")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id)
        db.add(scan)
        db.commit()
        identifier = scan.id

    @contextmanager
    def clone(*args, **kwargs):
        yield SimpleNamespace(path=tmp_path, commit_sha="a" * 40, languages=["Python"])

    monkeypatch.setattr(tasks, "cloned_repo", clone)
    errors = {tool: "mock-sensitive-tool-error" for tool in failed_tools}
    findings = [] if len(failed_tools) == 3 else mock_findings
    monkeypatch.setattr(tasks, "run_all_detectors", lambda *args: (findings, errors))
    monkeypatch.setattr(tasks, "set_progress", lambda *args: None)
    assert tasks.scan_repo.run(identifier) == identifier
    with SessionLocal() as db:
        rows = db.query(Finding).filter(Finding.scan_id == identifier).all()
        if len(failed_tools) < 3:
            assert any(row.owasp_top10 == "A05:2025" for row in rows)
        assert all("classification" in row.raw and "assessment" in row.raw for row in rows)
        scan = db.get(Scan, identifier)
        assert scan.summary["complete"] == (not bool(failed_tools))
        assert "mock-sensitive-tool-error" not in str(scan.summary)
        if failed_tools:
            assert scan.grade is None
        assert scan.status.value == ("failed" if len(failed_tools) == 3 else "completed")
