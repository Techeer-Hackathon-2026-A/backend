"""[백엔드 D] AI 수정 코드 생성 요청 · 조회."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import Viewer, get_viewer, require_read
from app.core.database import get_db
from app.models import Finding, Fix
from app.schemas.api import FixOut, TaskAccepted

router = APIRouter(tags=["fixes"])

FINDING_NOT_FOUND = "취약점을 찾을 수 없습니다"


@router.post("/findings/{finding_id}/fixes", response_model=TaskAccepted, status_code=status.HTTP_202_ACCEPTED)
def request_fix(
    finding_id: int, db: Session = Depends(get_db), viewer: Viewer | None = Depends(get_viewer)
) -> TaskAccepted:
    """Claude API 비용이 드는 작업이라 로그인한 사용자만 요청할 수 있다."""
    from app.workers.tasks import generate_fix_task

    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, FINDING_NOT_FOUND)
    require_read(viewer, finding.scan.project, FINDING_NOT_FOUND, login=True)
    task = generate_fix_task.delay(finding_id)
    return TaskAccepted(task_id=task.id)


@router.get("/findings/{finding_id}/fixes", response_model=list[FixOut])
def list_fixes(
    finding_id: int, db: Session = Depends(get_db), viewer: Viewer | None = Depends(get_viewer)
) -> list[Fix]:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, FINDING_NOT_FOUND)
    require_read(viewer, finding.scan.project, FINDING_NOT_FOUND)
    return list(db.scalars(select(Fix).where(Fix.finding_id == finding_id).order_by(Fix.id.desc())))
