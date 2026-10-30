"""B·C 계약 초안에 따른 독립 입력 모델. 실제 B 연결은 하지 않는다."""

from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Tool = Literal["semgrep", "osv", "gitleaks"]
RunStatus = Literal["success", "failed", "partial", "not_run"]


class SafeModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True, frozen=True)


class Location(SafeModel):
    path: str = Field(min_length=1)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_column: int | None = Field(default=None, ge=1)
    end_column: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def check_location(self):
        path = self.path.replace("\\", "/")
        if path.startswith("/") or ":" in path or ".." in PurePosixPath(path).parts:
            raise ValueError("저장소 상대 경로가 필요합니다")
        if self.end_line < self.start_line:
            raise ValueError("행 범위가 잘못되었습니다")
        if any(ord(c) < 32 for c in path) or path in ("", "."):
            raise ValueError("파일 경로가 잘못되었습니다")
        if (self.start_column is None) != (self.end_column is None):
            raise ValueError("열 범위는 함께 지정해야 합니다")
        if self.start_line == self.end_line and self.start_column is not None and self.end_column < self.start_column:
            raise ValueError("열 범위가 잘못되었습니다")
        return self


class Package(SafeModel):
    ecosystem: str = Field(min_length=1)
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    manifest: str = Field(min_length=1)

    @model_validator(mode="after")
    def check_manifest(self):
        Location(path=self.manifest, start_line=1, end_line=1)
        if any(not v.strip() for v in (self.ecosystem, self.name, self.version)):
            raise ValueError("패키지 식별 정보가 비어 있습니다")
        return self


class Finding(SafeModel):
    finding_id: str = Field(min_length=1)
    tool: Literal["semgrep", "osv", "gitleaks"]
    kind: Literal["code", "dependency", "secret"]
    rule_id: str = Field(min_length=1)
    locations: tuple[Location, ...] = ()
    vulnerability_ids: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    package: Package | None = None
    severity_original: str | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10, allow_inf_nan=False)
    cvss_version: Literal["2.0", "3.0", "3.1", "4.0"] | None = None
    evidence_refs: tuple[str, ...] = ()

    @model_validator(mode="after")
    def check_kind(self):
        if not self.finding_id.strip() or not self.rule_id.strip():
            raise ValueError("탐지 식별자는 공백일 수 없습니다")
        if any(not v.strip() for v in self.vulnerability_ids):
            raise ValueError("취약점 식별자는 공백일 수 없습니다")
        if self.kind in ("code", "secret") and not self.locations:
            raise ValueError("탐지 위치가 필요합니다")
        if self.kind == "dependency" and (not self.package or not self.vulnerability_ids):
            raise ValueError("패키지와 취약점 식별자가 필요합니다")
        if (self.cvss_score is None) != (self.cvss_version is None):
            raise ValueError("CVSS 점수와 버전을 함께 지정해야 합니다")
        return self


class ToolStatuses(SafeModel):
    semgrep: RunStatus
    osv: RunStatus
    gitleaks: RunStatus


class AnalysisBatch(SafeModel):
    schema_version: Literal["1.0"]
    analysis_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    repository_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    commit_sha: str = Field(pattern=r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
    data_origin: Literal["mock", "scanner"]
    tool_statuses: ToolStatuses
    findings: tuple[Finding, ...]

    @model_validator(mode="after")
    def check_consistency(self):
        if len({f.finding_id for f in self.findings}) != len(self.findings):
            raise ValueError("분석 내 탐지 ID가 중복되었습니다")
        statuses = self.tool_statuses.model_dump()
        if any(statuses[f.tool] == "not_run" for f in self.findings):
            raise ValueError("미실행 도구 결과가 포함되었습니다")
        return self
