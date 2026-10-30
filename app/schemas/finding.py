"""공통 결과 스키마 (팀 전체 합의 대상).

탐지(B) → 분류·평가(C) → AI 수정(D) → PR(A)이 모두 이 형식을 주고받는다.
필드를 바꿀 때는 반드시 팀 전체에 공유할 것.
"""

from enum import Enum

from pydantic import BaseModel, Field


class Category(str, Enum):
    SAST = "sast"  # 코드 취약점 (Semgrep)
    SCA = "sca"  # 라이브러리 취약점 (OSV-Scanner)
    SECRET = "secret"  # 시크릿·하드코딩 (Gitleaks)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Location(BaseModel):
    file_path: str = Field(..., description="레포 루트 기준 상대 경로")
    start_line: int
    end_line: int | None = None
    snippet: str | None = Field(None, description="취약점 주변 코드 몇 줄 (시크릿은 마스킹 필수)")


class DependencyInfo(BaseModel):
    """SCA 결과 전용."""

    package: str
    ecosystem: str  # npm, PyPI, Maven ...
    installed_version: str
    fixed_version: str | None = None
    vuln_ids: list[str] = []  # CVE-..., GHSA-...


class NormalizedFinding(BaseModel):
    """[B 작성] 탐지 도구 결과를 정규화한 형태."""

    tool: str  # semgrep | osv-scanner | gitleaks
    category: Category
    rule_id: str
    title: str
    message: str
    severity: Severity
    location: Location
    cwe: list[str] = []  # ["CWE-89"]
    owasp: list[str] = []  # ["A03:2021"]
    dependency: DependencyInfo | None = None
    fingerprint: str = Field(..., description="중복 판단용 해시 (tool 무관하게 같은 문제면 같은 값 지향)")
    raw: dict = Field(default_factory=dict, description="도구 원본 결과 (디버깅용)")


class ClassifiedFinding(NormalizedFinding):
    """[C 작성] 분류·평가가 끝난 형태. DB findings 테이블에 저장된다."""

    owasp_top10: str | None = None  # 대표 카테고리 1개, 예: "A03:2021-Injection"
    risk_score: float = 0.0  # 0 ~ 100
    priority: int = 0  # 1이 가장 먼저 고칠 것
    duplicate_count: int = 1  # 통합된 탐지 개수
    merged_tools: list[str] = []


class FixSuggestion(BaseModel):
    """[D 작성] AI 수정 결과."""

    finding_id: int
    file_path: str
    original_code: str
    fixed_code: str
    explanation: str
    verified: bool = False  # 재스캔 결과 문제가 사라졌는지
    verification_note: str | None = None
