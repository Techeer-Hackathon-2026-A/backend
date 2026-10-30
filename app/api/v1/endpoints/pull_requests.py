"""[백엔드 A] 수정 PR 생성 · PR 목록 조회."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Fix, PullRequest, Scan
from app.schemas.api import PullRequestCreate, PullRequestOut

router = APIRouter(tags=["pull-requests"])


@router.post("/scans/{scan_id}/pull-requests", response_model=PullRequestOut, status_code=status.HTTP_202_ACCEPTED)
def create_pull_request(scan_id: int, body: PullRequestCreate, db: Session = Depends(get_db)) -> PullRequest:
    from app.workers.tasks import create_pr_task

    if db.get(Scan, scan_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "스캔을 찾을 수 없습니다")
    if not body.fix_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "수정안을 하나 이상 선택하세요")
    found = db.scalars(select(Fix.id).where(Fix.id.in_(body.fix_ids))).all()
    if len(found) != len(set(body.fix_ids)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "존재하지 않는 수정안이 포함되어 있습니다")

    pr = PullRequest(scan_id=scan_id, fix_ids=body.fix_ids, branch_name=f"security-fix/scan-{scan_id}")
    db.add(pr)
    db.commit()
    pr.branch_name = f"security-fix/scan-{scan_id}-{pr.id}"
    db.commit()
    create_pr_task.delay(pr.id)
    return pr


@router.get("/scans/{scan_id}/pull-requests", response_model=list[PullRequestOut])
def list_pull_requests(scan_id: int, db: Session = Depends(get_db)) -> list[PullRequest]:
    return list(db.scalars(select(PullRequest).where(PullRequest.scan_id == scan_id).order_by(PullRequest.id.desc())))
