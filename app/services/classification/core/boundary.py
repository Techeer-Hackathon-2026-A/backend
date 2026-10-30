"""A가 연결할 입력/출력 경계. 예외와 원문은 응답·로그에 전달하지 않는다."""

from typing import Annotated, Literal

from pydantic import Field, ValidationError

from .models import AnalysisBatch, SafeModel, Tool, ToolStatuses
from .service import build_report

Level = Literal["critical", "high", "medium", "low", "info", "unknown"]
CVSSVersion = Literal["2.0", "3.0", "3.1", "4.0"]
CWEId = Annotated[str, Field(pattern=r"^CWE-[1-9][0-9]*$")]
Category = Annotated[str, Field(pattern=r"^A(?:0[1-9]|10):2025$")]


class RiskEvidence(SafeModel):
    level: Level
    score: float | None = Field(ge=0, le=10, allow_inf_nan=False)
    cvss_version: CVSSVersion | None
    basis: Literal["provided_cvss", "tool_severity", "missing"]


class ToolRisk(RiskEvidence):
    tool: Tool


class PublicRisk(RiskEvidence):
    policy_version: Literal["2025-mock-v3"]
    evidence: list[ToolRisk]


class Classification(SafeModel):
    cwe_ids: list[CWEId]
    unresolved_cwe_count: int = Field(ge=0)
    cwe_status: Literal["verified", "unmapped"]
    owasp_categories: list[Category]
    owasp_version: Literal["2025"]
    mapping_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    cwe_catalog_version: str = Field(pattern=r"^\d+(?:\.\d+)*$")
    deprecated_cwe_ids: list[CWEId]


class PublicVulnerability(SafeModel):
    vulnerability_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    title: Literal["탐지된 보안 취약점"]
    kind: Literal["code", "dependency", "secret"]
    tools: list[Tool]
    source_count: int = Field(ge=1)
    merge_reason: Literal[
        "패키지·버전·manifest 및 취약점 식별자 집합 일치",
        "동일 도구·규칙·취약점 식별자 및 행·열 위치 일치",
        "열 정보 부족으로 개별 유지",
        "안전한 시크릿 지문 계약 전 개별 유지",
    ]
    classification: Classification
    risk: PublicRisk


class PublicReport(SafeModel):
    analysis_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    repository_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    commit_sha: str = Field(pattern=r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
    data_origin: Literal["mock", "scanner"]
    owasp_version: Literal["2025"]
    policy_version: Literal["2025-mock-v3"]
    tool_statuses: ToolStatuses
    complete: bool
    raw_count: int = Field(ge=0)
    vulnerability_count: int = Field(ge=0)
    severity_counts: dict[Level, int]
    cwe_counts: dict[CWEId, int]
    owasp_counts: dict[Category, int]
    unmapped_owasp_count: int = Field(ge=0)
    tool_counts: dict[Tool, int]
    vulnerabilities: list[PublicVulnerability]


def error_response(code):
    # 오류의 위치·메시지·문맥·예외 문자열도 입력값을 포함할 수 있어 반환하지 않는다.
    definitions = {
        "INVALID_INPUT": (422, "입력 데이터가 올바르지 않습니다."),
        "INTERNAL_ERROR": (500, "결과를 처리할 수 없습니다."),
    }
    status, message = definitions[code]
    return status, {"error": {"code": code, "message": message}}


def process_batch(payload):
    """HTTP와 독립적인 (상태 코드, JSON 본문) 반환. A의 인증·인가 후 호출한다."""
    try:
        batch = AnalysisBatch.model_validate(payload)
    except ValidationError:
        return error_response("INVALID_INPUT")
    try:
        report = build_report(
            batch.analysis_id,
            list(batch.findings),
            repository_id=batch.repository_id,
            commit_sha=batch.commit_sha,
            tool_statuses=batch.tool_statuses.model_dump(),
        )
        report["data_origin"] = batch.data_origin
        return 200, PublicReport.model_validate(report).model_dump(mode="json")
    except Exception:
        # 원문·예외 객체는 로깅하지 않는다. 고정 오류 코드로만 관측해야 한다.
        return error_response("INTERNAL_ERROR")
