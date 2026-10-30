"""[백엔드 C] 보안 분석 리포트 · 취약점 목록 · 취약점 상세 조회."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.api import FindingDetail, FindingOut, SecurityReport
from app.services.classification.http import SafeReportRoute
from app.services.classification.report import stored_report
from app.services.classification.repository import ReportRepository, SQLReportRepository
from app.services.classification.safety import public_entity

router = APIRouter(tags=["reports"], route_class=SafeReportRoute)


def get_report_repository(db: Session = Depends(get_db)) -> ReportRepository:
    """A의 사용자별 접근 제한 저장소로 교체할 수 있는 의존성 경계."""
    return SQLReportRepository(db)


@router.get("/scans/{scan_id}/report", response_model=SecurityReport)
def get_report(scan_id: int, repository: ReportRepository = Depends(get_report_repository)) -> SecurityReport:
    scan = repository.scan(scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "스캔을 찾을 수 없습니다")
    top = repository.findings(scan_id, limit=10)
    return stored_report(scan, top)


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def list_findings(
    scan_id: int,
    severity: str | None = Query(None, description="critical | high | medium | low | info"),
    category: str | None = Query(None, description="sast | sca | secret"),
    owasp: str | None = Query(None, pattern=r"^A(?:0[1-9]|10):2025$", description="예: A05:2025"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    repository: ReportRepository = Depends(get_report_repository),
) -> list[FindingOut]:
    if repository.scan(scan_id) is None:
        raise HTTPException(404, "스캔을 찾을 수 없습니다")
    rows = repository.findings(scan_id, severity=severity, category=category, owasp=owasp, limit=limit, offset=offset)
    return [public_entity(finding, FindingOut) for finding in rows]


@router.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: int, repository: ReportRepository = Depends(get_report_repository)) -> FindingDetail:
    finding = repository.finding(finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "취약점을 찾을 수 없습니다")
    return public_entity(finding, FindingDetail)
