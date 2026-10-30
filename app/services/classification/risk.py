"""[백엔드 C] 위험도 산정·우선순위 정렬·등급 계산.

CVSS 우선 평가 결과를 사용한다. 경로 감점이나 도구별 가중치는 적용하지 않는다.
"""

from collections import Counter

from app.schemas.finding import ClassifiedFinding, Severity


def risk_score(f: ClassifiedFinding) -> float:
    """기존 API의 0~100 표시 값. 우선순위는 등급을 기준으로 한다."""
    return f.risk_score


def prioritize(findings: list[ClassifiedFinding]) -> list[ClassifiedFinding]:
    from app.services.classification.core.service import LEVEL_RANK

    ordered = sorted(findings, key=lambda f: (LEVEL_RANK[f.severity.value], f.fingerprint))
    for index, finding in enumerate(ordered, 1):
        finding.priority = index
    return ordered


def calculate_grade(findings: list[ClassifiedFinding]) -> str:
    """SonarQube 방식 참고: 가장 심각한 이슈 기준 A~E."""
    severities = {f.severity for f in findings}
    if Severity.CRITICAL in severities:
        return "E"
    if Severity.HIGH in severities:
        return "D"
    if Severity.MEDIUM in severities:
        return "C"
    if Severity.LOW in severities:
        return "B"
    return "U" if Severity.UNKNOWN in severities else "A"


def summarize(findings: list[ClassifiedFinding]) -> dict:
    return {
        "total": len(findings),
        "raw_total": sum(f.duplicate_count for f in findings),
        "owasp_version": "2025",
        "by_cwe": dict(Counter(c for f in findings for c in f.cwe)),
        "by_severity": dict(Counter(f.severity.value for f in findings)),
        "by_category": dict(Counter(f.category.value for f in findings)),
        "owasp_matrix": dict(Counter(category for f in findings for category in f.owasp)),
    }
