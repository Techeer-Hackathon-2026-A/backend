"""A의 기존 DB 모델을 사용하는 C 조회 어댑터. 테이블 추가 없음."""

from typing import Protocol

from sqlalchemy import String, cast, select
from sqlalchemy.orm import Session

from app.models import Finding, Scan


class ReportRepository(Protocol):
    def scan(self, scan_id: int): ...
    def finding(self, finding_id: int): ...
    def findings(self, scan_id: int, *, severity=None, category=None, owasp=None, limit=None, offset=0): ...


class SQLReportRepository:
    def __init__(self, session: Session):
        self.session = session

    def scan(self, scan_id):
        return self.session.get(Scan, scan_id)

    def finding(self, finding_id):
        return self.session.get(Finding, finding_id)

    def findings(self, scan_id, *, severity=None, category=None, owasp=None, limit=None, offset=0):
        query = select(Finding).where(Finding.scan_id == scan_id)
        if severity:
            query = query.where(Finding.severity == severity)
        if category:
            query = query.where(Finding.category == category)
        if owasp:
            # JSON 배열의 모든 범주를 검색한다. 대표 범주만 검색하지 않는다.
            query = query.where(cast(Finding.owasp, String).contains('"' + owasp + '"', autoescape=True))
        query = query.order_by(Finding.priority, Finding.id).offset(offset)
        if limit is not None:
            query = query.limit(limit)
        return list(self.session.scalars(query))
