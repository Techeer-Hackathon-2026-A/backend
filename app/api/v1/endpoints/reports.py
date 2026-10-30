"""[백엔드 C] 보안 분석 리포트 · 취약점 목록 · 취약점 상세 조회."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Finding, Scan
from app.schemas.api import FindingDetail, FindingOut, SecurityReport

router = APIRouter(tags=["reports"])


@router.get("/scans/{scan_id}/report", response_model=SecurityReport)
def get_report(scan_id: int, db: Session = Depends(get_db)) -> SecurityReport:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "스캔을 찾을 수 없습니다")
    summary = scan.summary or {}
    top = db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.priority).limit(10))
    return SecurityReport(
        scan_id=scan_id,
        grade=scan.grade,
        total=summary.get("total", 0),
        by_severity=summary.get("by_severity", {}),
        by_category=summary.get("by_category", {}),
        owasp_matrix=summary.get("owasp_matrix", {}),
        top_findings=[FindingOut.model_validate(f) for f in top],
    )


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def list_findings(
    scan_id: int,
    severity: str | None = Query(None, description="critical | high | medium | low | info"),
    category: str | None = Query(None, description="sast | sca | secret"),
    owasp: str | None = Query(None, description="예: A03:2021"),
    db: Session = Depends(get_db),
) -> list[Finding]:
    stmt = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if category:
        stmt = stmt.where(Finding.category == category)
    if owasp:
        stmt = stmt.where(Finding.owasp_top10.startswith(owasp))
    return list(db.scalars(stmt.order_by(Finding.priority)))


@router.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: int, db: Session = Depends(get_db)) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "취약점을 찾을 수 없습니다")
    return finding
