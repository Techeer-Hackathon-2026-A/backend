"""API 요청·응답 스키마 (프론트엔드와 합의 대상)."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, HttpUrl

from app.models.enums import FindingStatus, ScanStatus


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------- Scan ----------
class ScanCreate(BaseModel):
    repo_url: HttpUrl
    branch: str | None = None


class ScanOut(ORMModel):
    id: int
    project_id: int
    status: ScanStatus
    branch: str | None
    commit_sha: str | None
    grade: str | None
    summary: dict | None
    error_message: str | None
    created_at: datetime
    finished_at: datetime | None


class ScanProgress(BaseModel):
    scan_id: int
    status: ScanStatus
    step: str | None = None
    percent: int = 0
    message: str = ""


# ---------- Finding ----------
class FindingOut(ORMModel):
    id: int
    scan_id: int
    tool: str
    category: str
    rule_id: str
    title: str
    severity: str
    file_path: str
    start_line: int
    cwe: list[str]
    owasp_top10: str | None
    risk_score: float
    priority: int
    status: FindingStatus


class FindingDetail(FindingOut):
    message: str
    end_line: int | None
    snippet: str | None
    owasp: list[str]
    dependency: dict | None
    merged_tools: list[str]


# ---------- Report ----------
class SecurityReport(BaseModel):
    scan_id: int
    grade: str | None
    total: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    owasp_matrix: dict[str, int]  # {"A05:2025": 3, ...}
    top_findings: list[FindingOut]


# ---------- Fix / PR ----------
class FixOut(ORMModel):
    id: int
    finding_id: int
    file_path: str
    original_code: str
    fixed_code: str
    explanation: str
    verified: bool
    created_at: datetime


class PullRequestCreate(BaseModel):
    fix_ids: list[int]


class PullRequestOut(ORMModel):
    id: int
    scan_id: int
    branch_name: str
    pr_number: int | None
    pr_url: str | None
    status: str
    created_at: datetime
    fix_ids: list[int] = []
    error_message: str | None = None


class TaskAccepted(BaseModel):
    task_id: str
    message: str = "accepted"
