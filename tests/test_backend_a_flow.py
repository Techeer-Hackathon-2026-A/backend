"""[백엔드 A] 스캔 요청·진행률·AI 수정 연결·PR API 흐름 테스트 (Celery·Redis·LLM은 목으로 대체)."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest


@pytest.fixture
def no_queue(monkeypatch):
    """Celery에 실제로 보내지 않고 호출만 기록한다."""
    from app.workers import tasks

    calls = []
    for name in ("scan_repo", "generate_fix_task", "create_pr_task"):
        task = getattr(tasks, name)
        monkeypatch.setattr(task, "delay", lambda *a, _n=name: calls.append((_n, a)) or SimpleNamespace(id="t"))
    monkeypatch.setattr("app.api.v1.endpoints.scans.set_progress", lambda *a, **k: None)
    monkeypatch.setattr("app.api.v1.endpoints.scans.get_progress", lambda *a: None)
    return calls


def test_create_scan_normalizes_and_reuses_running_scan(client, no_queue):
    r1 = client.post("/api/v1/scans", json={"repo_url": "https://github.com/Owner/Repo.git/"})
    assert r1.status_code == 202
    r2 = client.post("/api/v1/scans", json={"repo_url": "https://github.com/Owner/Repo"})
    assert r2.status_code == 200, "진행 중인 같은 스캔은 새로 만들지 않는다"
    assert r2.json()["id"] == r1.json()["id"]
    r3 = client.post("/api/v1/scans", json={"repo_url": "https://github.com/Owner/Repo", "branch": "dev"})
    assert r3.status_code == 202 and r3.json()["id"] != r1.json()["id"]
    assert [c[0] for c in no_queue] == ["scan_repo", "scan_repo"]


@pytest.mark.parametrize(
    "body",
    [
        {"repo_url": "https://gitlab.com/o/r"},
        {"repo_url": "https://github.com/o/r", "branch": "--upload-pack=x"},
    ],
)
def test_create_scan_rejects_bad_input(client, no_queue, body):
    assert client.post("/api/v1/scans", json=body).status_code == 400
    assert no_queue == []


def test_progress_falls_back_to_db_when_redis_empty(client, no_queue):
    from app.core.database import SessionLocal
    from app.models import Scan
    from app.models.enums import ScanStatus

    scan_id = client.post("/api/v1/scans", json={"repo_url": "https://github.com/o/progress"}).json()["id"]
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        scan.status = ScanStatus.FAILED
        scan.error_message = "레포를 찾을 수 없거나 접근 권한이 없습니다."
        db.commit()
    body = client.get(f"/api/v1/scans/{scan_id}/progress").json()
    assert body["status"] == "failed" and body["percent"] == 100
    assert body["message"] == "레포를 찾을 수 없거나 접근 권한이 없습니다."


@pytest.fixture
def scanned(client, mock_findings, monkeypatch, tmp_path):
    """목 탐지 결과로 scan_repo를 끝까지 실행한 스캔."""
    from app.core.database import SessionLocal
    from app.models import Project, Scan
    from app.workers import tasks

    (tmp_path / "app" / "routes").mkdir(parents=True)
    (tmp_path / "app" / "routes" / "users.py").write_text(
        "\n" * 20
        + "@app.get('/users')\ndef get_user(name: str):\n    conn = get_conn()\n"
        + "    cursor = conn.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n    return cursor.fetchall()\n",
        encoding="utf-8",
    )
    with SessionLocal() as db:
        project = Project(repo_url="https://github.com/mock/a-flow", owner="mock", name="a-flow")
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id)
        db.add(scan)
        db.commit()
        scan_id = scan.id

    @contextmanager
    def clone(*args, **kwargs):
        yield SimpleNamespace(path=tmp_path, commit_sha="b" * 40, branch="main", languages=["python"])

    monkeypatch.setattr(tasks, "cloned_repo", clone)
    monkeypatch.setattr(tasks, "run_all_detectors", lambda *a: (mock_findings, {}))
    monkeypatch.setattr(tasks, "set_progress", lambda *a: None)
    tasks.scan_repo.run(scan_id)
    return SimpleNamespace(id=scan_id, clone=clone)


def test_scan_records_default_branch_and_internal_rule_ids(scanned):
    from app.core.database import SessionLocal
    from app.models import Finding, Scan

    with SessionLocal() as db:
        scan = db.get(Scan, scanned.id)
        assert scan.status.value == "completed" and scan.commit_sha == "b" * 40
        assert scan.project.default_branch == "main"
        sqli = db.query(Finding).filter(Finding.scan_id == scanned.id, Finding.file_path == "app/routes/users.py").one()
        assert sqli.rule_id == "redacted", "C 정책: 공개 컬럼에는 룰 ID를 남기지 않는다"
        assert sqli.raw["internal"]["rule_ids"] == [
            "python.lang.security.audit.formatted-sql-query.formatted-sql-query"
        ]


def test_internal_rule_ids_are_not_exposed_by_api(client, scanned):
    findings = client.get(f"/api/v1/scans/{scanned.id}/findings").json()
    for f in findings:
        detail = client.get(f"/api/v1/findings/{f['id']}").text
        assert "formatted-sql-query" not in detail and "internal" not in detail


def test_generate_fix_reads_code_from_reclone(scanned, monkeypatch):
    """C가 snippet을 저장하지 않아도 D의 수정 생성이 동작해야 한다 (통합 버그 회귀 테스트)."""
    from app.core.database import SessionLocal
    from app.models import Finding, Fix
    from app.services.ai import fixer, verifier
    from app.services.ai.fixer import FixResult
    from app.workers import tasks

    seen = {}

    def fake_generate_fix(**kwargs):
        seen.update(kwargs)
        return FixResult(
            original_code="conn.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
            fixed_code='conn.execute("SELECT * FROM users WHERE name = ?", (name,))',
            explanation="파라미터 바인딩으로 바꿨습니다.",
        )

    monkeypatch.setattr(fixer, "generate_fix", fake_generate_fix)
    monkeypatch.setattr(
        verifier, "verify_fix", lambda repo, change, rule_id: SimpleNamespace(verified=True, note=rule_id)
    )

    with SessionLocal() as db:
        sqli = db.query(Finding).filter(Finding.scan_id == scanned.id, Finding.file_path == "app/routes/users.py").one()
        secret = db.query(Finding).filter(Finding.scan_id == scanned.id, Finding.category == "secret").first()
        sqli_id, secret_id = sqli.id, secret.id

    fix_id = tasks.generate_fix_task.run(sqli_id)
    assert fix_id is not None
    assert 'conn.execute(f"SELECT' in seen["snippet"], "재클론한 파일에서 코드 조각을 읽어야 한다"
    assert seen["rule_id"].endswith("formatted-sql-query")
    assert seen["repo_root"] is not None
    with SessionLocal() as db:
        fix = db.get(Fix, fix_id)
        assert fix.verified and fix.verification_note.endswith("formatted-sql-query")

    assert tasks.generate_fix_task.run(secret_id) is None, "시크릿은 자동 수정하지 않는다"


def test_pull_request_api_validation(client, scanned, no_queue):
    from app.core.database import SessionLocal
    from app.models import Finding, Fix

    with SessionLocal() as db:
        finding = db.query(Finding).filter(Finding.scan_id == scanned.id).first()
        fix = Fix(finding_id=finding.id, file_path="a.py", original_code="a", fixed_code="b", explanation="e")
        db.add(fix)
        db.commit()
        fix_id = fix.id

    from tests.conftest import OWNER

    url = f"/api/v1/scans/{scanned.id}/pull-requests"
    assert client.post(url, json={"fix_ids": []}, headers=OWNER).status_code == 400
    assert client.post(url, json={"fix_ids": [999999]}, headers=OWNER).status_code == 400
    missing = "/api/v1/scans/999999/pull-requests"
    assert client.post(missing, json={"fix_ids": [fix_id]}, headers=OWNER).status_code == 404

    created = client.post(url, json={"fix_ids": [fix_id, fix_id]}, headers=OWNER)
    assert created.status_code == 202
    body = created.json()
    assert body["fix_ids"] == [fix_id] and body["status"] == "pending"
    assert body["branch_name"] == f"security-fix/scan-{scanned.id}-{body['id']}"
    assert client.get(f"/api/v1/pull-requests/{body['id']}").json()["id"] == body["id"]
    assert len(client.get(url).json()) == 1
    assert no_queue[-1] == ("create_pr_task", (body["id"],))


def test_create_pr_failure_stores_safe_message(client, scanned, monkeypatch):
    from app.core.database import SessionLocal
    from app.models import Finding, Fix, PullRequest
    from app.services.git import github
    from app.services.git.errors import GitHubApiError
    from app.workers import tasks

    with SessionLocal() as db:
        finding = db.query(Finding).filter(Finding.scan_id == scanned.id).first()
        fix = Fix(finding_id=finding.id, file_path="a.py", original_code="a", fixed_code="b", explanation="e")
        db.add(fix)
        db.flush()
        pr = PullRequest(scan_id=scanned.id, fix_ids=[fix.id], branch_name="security-fix/x")
        db.add(pr)
        db.commit()
        pr_id = pr.id

    monkeypatch.setattr(github, "apply_changes", lambda *a: None)
    monkeypatch.setattr(github, "commit_and_push", lambda *a: None)

    def fail(*a, **k):
        raise GitHubApiError("GITHUB_TOKEN이 설정되지 않아 PR을 만들 수 없습니다.")

    monkeypatch.setattr(github, "create_pull_request", fail)
    with pytest.raises(GitHubApiError):
        tasks.create_pr_task.run(pr_id)
    with SessionLocal() as db:
        pr = db.get(PullRequest, pr_id)
        assert pr.status == "failed"
        assert pr.error_message == "GITHUB_TOKEN이 설정되지 않아 PR을 만들 수 없습니다."
