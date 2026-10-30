"""[백엔드 A] 레포 링크 입력(스캔 요청) · 진행 상태 조회."""

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.redis_client import get_progress, set_progress
from app.models import Project, Scan
from app.models.enums import ScanStatus
from app.schemas.api import ScanCreate, ScanOut, ScanProgress
from app.services.git.repo import normalize_repo_url, parse_repo_url, validate_branch

router = APIRouter(prefix="/scans", tags=["scans"])

ACTIVE_STATUSES = (
    ScanStatus.PENDING,
    ScanStatus.CLONING,
    ScanStatus.DETECTING,
    ScanStatus.CLASSIFYING,
    ScanStatus.FIXING,
)


@router.post("", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def create_scan(body: ScanCreate, response: Response, db: Session = Depends(get_db)) -> Scan:
    """레포 링크로 스캔을 요청한다.

    같은 레포·브랜치의 스캔이 이미 진행 중이면 새로 만들지 않고 진행 중인 스캔을 돌려준다 (200).
    """
    from app.workers.tasks import scan_repo

    try:
        repo_url = normalize_repo_url(str(body.repo_url))
        branch = validate_branch(body.branch.strip() if body.branch else None)
        owner, name = parse_repo_url(repo_url)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e

    project = db.scalar(select(Project).where(Project.repo_url == repo_url))
    if project is None:
        project = Project(repo_url=repo_url, owner=owner, name=name)
        db.add(project)
        db.flush()
    else:
        running = db.scalar(
            select(Scan)
            .where(Scan.project_id == project.id, Scan.branch.is_(branch) if branch is None else Scan.branch == branch)
            .where(Scan.status.in_(ACTIVE_STATUSES))
            .order_by(Scan.id.desc())
        )
        if running is not None:
            response.status_code = status.HTTP_200_OK
            return running

    scan = Scan(project_id=project.id, branch=branch)
    db.add(scan)
    db.commit()
    set_progress(scan.id, ScanStatus.PENDING.value, 0, "대기 중")

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
    """프론트에서 1~2초 간격으로 폴링한다.

    Redis 진행률이 만료되었거나 없으면 DB 상태로 대신 계산한다.
    """
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "스캔을 찾을 수 없습니다")
    progress = get_progress(scan_id) or {}
    if not progress and scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
        progress = {"step": scan.status.value, "percent": 100, "message": scan.error_message or ""}
    if scan.status == ScanStatus.FAILED and scan.error_message:
        progress["message"] = scan.error_message
    return ScanProgress(scan_id=scan_id, status=scan.status, **progress)
