"""DB 테이블 정의.

projects 1 ─ N scans 1 ─ N findings 1 ─ N fixes
                    scans 1 ─ N pull_requests
"""

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.enums import FindingStatus, ScanStatus


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Project(TimestampMixin, Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True)
    repo_url: Mapped[str] = mapped_column(String(500), unique=True, index=True)
    owner: Mapped[str] = mapped_column(String(200))
    name: Mapped[str] = mapped_column(String(200))
    default_branch: Mapped[str | None] = mapped_column(String(200))

    scans: Mapped[list["Scan"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Scan(TimestampMixin, Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)
    branch: Mapped[str | None] = mapped_column(String(200))
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    languages: Mapped[list | None] = mapped_column(JSON)
    grade: Mapped[str | None] = mapped_column(String(2))  # A ~ E
    summary: Mapped[dict | None] = mapped_column(JSON)  # 심각도별 개수 등
    error_message: Mapped[str | None] = mapped_column(Text)
    celery_task_id: Mapped[str | None] = mapped_column(String(100))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    pull_requests: Mapped[list["PullRequest"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)

    # 탐지 정보 (B)
    tool: Mapped[str] = mapped_column(String(50))
    category: Mapped[str] = mapped_column(String(20))
    rule_id: Mapped[str] = mapped_column(String(300))
    title: Mapped[str] = mapped_column(String(500))
    message: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20))
    file_path: Mapped[str] = mapped_column(String(1000))
    start_line: Mapped[int] = mapped_column(Integer)
    end_line: Mapped[int | None] = mapped_column(Integer)
    snippet: Mapped[str | None] = mapped_column(Text)
    cwe: Mapped[list] = mapped_column(JSON, default=list)
    owasp: Mapped[list] = mapped_column(JSON, default=list)
    dependency: Mapped[dict | None] = mapped_column(JSON)
    fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    raw: Mapped[dict | None] = mapped_column(JSON)

    # 분류·평가 (C)
    owasp_top10: Mapped[str | None] = mapped_column(String(100))
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_count: Mapped[int] = mapped_column(Integer, default=1)
    merged_tools: Mapped[list] = mapped_column(JSON, default=list)

    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.OPEN)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    fixes: Mapped[list["Fix"]] = relationship(back_populates="finding", cascade="all, delete-orphan")


class Fix(TimestampMixin, Base):
    """AI 수정 제안 (D)."""

    __tablename__ = "fixes"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    file_path: Mapped[str] = mapped_column(String(1000))
    original_code: Mapped[str] = mapped_column(Text)
    fixed_code: Mapped[str] = mapped_column(Text)
    explanation: Mapped[str] = mapped_column(Text)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verification_note: Mapped[str | None] = mapped_column(Text)
    model: Mapped[str | None] = mapped_column(String(100))

    finding: Mapped[Finding] = relationship(back_populates="fixes")


class PullRequest(TimestampMixin, Base):
    """수정 PR 기록 (A)."""

    __tablename__ = "pull_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    fix_ids: Mapped[list] = mapped_column(JSON, default=list)
    branch_name: Mapped[str] = mapped_column(String(300))
    pr_number: Mapped[int | None] = mapped_column(Integer)
    pr_url: Mapped[str | None] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(30), default="pending")  # pending | created | failed
    error_message: Mapped[str | None] = mapped_column(Text)

    scan: Mapped[Scan] = relationship(back_populates="pull_requests")
