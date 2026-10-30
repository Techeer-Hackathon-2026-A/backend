"""[백엔드 A] 레포 링크 입력(스캔 요청) · 진행 상태 조회."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.redis_client import get_progress
from app.models import Project, Scan
from app.schemas.api import ScanCreate, ScanOut, ScanProgress
from app.services.git.repo import parse_repo_url

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def create_scan(body: ScanCreate, db: Session = Depends(get_db)) -> Scan:
    from app.workers.tasks import scan_repo

    repo_url = str(body.repo_url).rstrip("/").removesuffix(".git")
    try:
        owner, name = parse_repo_url(repo_url)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e

    project = db.scalar(select(Project).where(Project.repo_url == repo_url))
    if project is None:
        project = Project(repo_url=repo_url, owner=owner, name=name)
        db.add(project)
        db.flush()

    scan = Scan(project_id=project.id, branch=body.branch)
    db.add(scan)
    db.commit()

    task = scan_repo.delay(scan.id)
    scan.celery_task_id = task.id
    db.commit()
    return scan


@router.get("", response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db)) -> list[Scan]:
    return list(db.scalars(select(Scan).order_by(Scan.id.desc()).limit(50)))


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "스캔을 찾을 수 없습니다")
    return scan


@router.get("/{scan_id}/progress", response_model=ScanProgress)
def get_scan_progress(scan_id: int, db: Session = Depends(get_db)) -> ScanProgress:
    """프론트에서 1~2초 간격으로 폴링한다. (TODO(A): 필요하면 SSE/WebSocket으로 전환)"""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "스캔을 찾을 수 없습니다")
    progress = get_progress(scan_id) or {}
    return ScanProgress(scan_id=scan_id, status=scan.status, **progress)
