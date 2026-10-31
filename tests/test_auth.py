"""API 인증·레포 권한: 볼 수 있는 레포의 기록만 보이고, 수정·PR 은 로그인·푸시 권한이 있어야 한다."""

from types import SimpleNamespace

import pytest

from tests.conftest import OWNER, READER


@pytest.fixture
def no_queue(monkeypatch):
    from app.workers import tasks

    for name in ("scan_repo", "generate_fix_task", "create_pr_task"):
        monkeypatch.setattr(getattr(tasks, name), "delay", lambda *a: SimpleNamespace(id="t"))
    monkeypatch.setattr("app.api.v1.endpoints.scans.set_progress", lambda *a, **k: None)
    monkeypatch.setattr("app.api.v1.endpoints.scans.get_progress", lambda *a: None)


def _completed_scan_with_fix(repo: str) -> tuple[int, int, int]:
    """repo('owner/name')의 완료된 스캔·취약점·수정안 하나씩. (scan_id, finding_id, fix_id)"""
    from app.core.database import SessionLocal
    from app.models import Finding, Fix, Project, Scan
    from app.models.enums import ScanStatus

    owner, name = repo.split("/")
    with SessionLocal() as db:
        project = Project(repo_url=f"https://github.com/{repo}", owner=owner, name=name)
        db.add(project)
        db.flush()
        scan = Scan(project_id=project.id, status=ScanStatus.COMPLETED, commit_sha="c" * 40)
        db.add(scan)
        db.flush()
        finding = Finding(
            scan_id=scan.id,
            tool="semgrep",
            category="sast",
            rule_id="r",
            title="t",
            message="m",
            severity="high",
            file_path="a.py",
            start_line=1,
            fingerprint="f",
        )
        db.add(finding)
        db.flush()
        fix = Fix(finding_id=finding.id, file_path="a.py", original_code="secret code", fixed_code="b", explanation="e")
        db.add(fix)
        db.commit()
        return scan.id, finding.id, fix.id


def test_private_repo_is_hidden_from_others(client, no_queue, fake_github):
    fake_github.private.add("acme/secret")
    body = {"repo_url": "https://github.com/acme/secret"}
    assert client.post("/api/v1/scans", json=body).status_code == 404, "익명은 비공개 레포를 스캔할 수 없다"
    assert client.post("/api/v1/scans", json=body, headers=READER).status_code == 404

    scan_id, finding_id, _ = _completed_scan_with_fix("acme/secret")
    for path in (
        f"/api/v1/scans/{scan_id}",
        f"/api/v1/scans/{scan_id}/progress",
        f"/api/v1/scans/{scan_id}/report",
        f"/api/v1/scans/{scan_id}/findings",
        f"/api/v1/scans/{scan_id}/pull-requests",
        f"/api/v1/findings/{finding_id}",
        f"/api/v1/findings/{finding_id}/fixes",
    ):
        assert client.get(path).status_code == 404, path
        assert client.get(path, headers=READER).status_code == 404, path
        assert client.get(path, headers=OWNER).status_code == 200, path


def test_owner_can_scan_private_repo_and_list_is_per_user(client, no_queue, fake_github):
    fake_github.private.add("acme/secret")
    created = client.post("/api/v1/scans", json={"repo_url": "https://github.com/acme/secret"}, headers=OWNER)
    assert created.status_code == 202
    assert [s["id"] for s in client.get("/api/v1/scans", headers=OWNER).json()] == [created.json()["id"]]
    assert client.get("/api/v1/scans", headers=READER).json() == []
    assert client.get("/api/v1/scans").json() == [], "익명에게는 목록을 주지 않는다"


def test_public_repo_is_readable_but_changes_need_login_and_push(client, no_queue):
    scan_id, finding_id, fix_id = _completed_scan_with_fix("acme/open")
    assert client.get(f"/api/v1/scans/{scan_id}/report").status_code == 200

    assert client.post(f"/api/v1/findings/{finding_id}/fixes").status_code == 401
    assert client.post(f"/api/v1/findings/{finding_id}/fixes", headers=READER).status_code == 202

    url = f"/api/v1/scans/{scan_id}/pull-requests"
    assert client.post(url, json={"fix_ids": [fix_id]}).status_code == 401
    assert client.post(url, json={"fix_ids": [fix_id]}, headers=READER).status_code == 403
    assert client.post(url, json={"fix_ids": [fix_id]}, headers=OWNER).status_code == 202


def test_invalid_github_token_is_rejected(client):
    assert client.get("/api/v1/scans", headers={"X-GitHub-Token": "expired"}).status_code == 401


def test_service_key_is_required_when_configured(client, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "backend_api_key", "k" * 32)
    assert client.get("/api/v1/scans").status_code == 401
    assert client.get("/api/v1/scans", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/v1/scans", headers={"Authorization": f"Bearer {'k' * 32}"}).status_code == 200
    assert client.get("/health").status_code == 200


def test_repo_url_rejects_dot_owner():
    from app.services.git.repo import normalize_repo_url

    with pytest.raises(ValueError):
        normalize_repo_url("https://github.com/../repo")
