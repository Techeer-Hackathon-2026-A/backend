"""[백엔드 C] 위험도 산정·우선순위 정렬·등급 계산.

등급은 LLM이 아니라 정해진 공식으로 계산한다 (같은 코드 → 같은 등급).
TODO(C): 가중치 튜닝, 테스트 코드 경로 감점 등
"""

from collections import Counter

from app.schemas.finding import SEVERITY_WEIGHT, Category, ClassifiedFinding, Severity

CATEGORY_BONUS = {Category.SECRET: 1.2, Category.SAST: 1.0, Category.SCA: 0.9}
TEST_PATH_HINTS = ("test", "tests", "__tests__", "spec", "fixtures", "examples")


def risk_score(f: ClassifiedFinding) -> float:
    score = SEVERITY_WEIGHT[f.severity] * 10 * CATEGORY_BONUS[f.category]
    if f.duplicate_count > 1:  # 여러 도구가 동시에 잡으면 신뢰도 ↑
        score *= 1.1
    if any(h in f.location.file_path.lower().split("/") for h in TEST_PATH_HINTS):
        score *= 0.5
    return round(min(score, 100.0), 1)


def prioritize(findings: list[ClassifiedFinding]) -> list[ClassifiedFinding]:
    for f in findings:
        f.risk_score = risk_score(f)
    ordered = sorted(findings, key=lambda f: (-f.risk_score, f.location.file_path, f.location.start_line))
    for i, f in enumerate(ordered, start=1):
        f.priority = i
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
    return "A"


def summarize(findings: list[ClassifiedFinding]) -> dict:
    return {
        "total": len(findings),
        "by_severity": dict(Counter(f.severity.value for f in findings)),
        "by_category": dict(Counter(f.category.value for f in findings)),
        "owasp_matrix": dict(Counter(f.owasp_top10 for f in findings if f.owasp_top10)),
    }
