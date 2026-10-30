"""[백엔드 A] 수정 PR 생성 · PR 목록/상세 조회."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Finding, Fix, PullRequest, Scan
from app.models.enums import ScanStatus
from app.schemas.api import PullRequestCreate, PullRequestOut

router = APIRouter(tags=["pull-requests"])

MAX_FIXES_PER_PR = 20


@router.post("/scans/{scan_id}/pull-requests", response_model=PullRequestOut, status_code=status.HTTP_202_ACCEPTED)
def create_pull_request(scan_id: int, body: PullRequestCreate, db: Session = Depends(get_db)) -> PullRequest:
    """사용자가 고른 수정안으로 PR 생성을 요청한다. 실제 작업은 워커(create_pr)가 한다."""
    from app.workers.tasks import create_pr_task

    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "스캔을 찾을 수 없습니다")
    if scan.status != ScanStatus.COMPLETED or not scan.commit_sha:
        raise HTTPException(status.HTTP_409_CONFLICT, "완료된 스캔에서만 PR을 만들 수 있습니다")

    fix_ids = list(dict.fromkeys(body.fix_ids))  # 순서 유지 + 중복 제거
    if not fix_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "수정안을 하나 이상 선택하세요")
    if len(fix_ids) > MAX_FIXES_PER_PR:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"한 PR에는 수정안을 {MAX_FIXES_PER_PR}개까지 넣을 수 있습니다"
        )

    # 다른 스캔의 수정안이 섞이지 않도록 이 스캔에 속한 수정안만 허용
    found = db.scalars(
        select(Fix.id)
        .join(Finding, Fix.finding_id == Finding.id)
        .where(Fix.id.in_(fix_ids), Finding.scan_id == scan_id)
    ).all()
    if len(found) != len(fix_ids):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "이 스캔에 속하지 않거나 존재하지 않는 수정안이 포함되어 있습니다"
        )

    pr = PullRequest(scan_id=scan_id, fix_ids=fix_ids, branch_name=f"security-fix/scan-{scan_id}")
    db.add(pr)
    db.flush()
    pr.branch_name = f"security-fix/scan-{scan_id}-{pr.id}"
    db.commit()
    create_pr_task.delay(pr.id)
    return pr


@router.get("/scans/{scan_id}/pull-requests", response_model=list[PullRequestOut])
def list_pull_requests(scan_id: int, db: Session = Depends(get_db)) -> list[PullRequest]:
    if db.get(Scan, scan_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "스캔을 찾을 수 없습니다")
    return list(db.scalars(select(PullRequest).where(PullRequest.scan_id == scan_id).order_by(PullRequest.id.desc())))


@router.get("/pull-requests/{pull_request_id}", response_model=PullRequestOut)
def get_pull_request(pull_request_id: int, db: Session = Depends(get_db)) -> PullRequest:
    """PR 생성 상태 폴링용 (pending → created | failed)."""
    pr = db.get(PullRequest, pull_request_id)
    if pr is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "PR 기록을 찾을 수 없습니다")
    return pr
