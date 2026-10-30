"""[백엔드 C] 분류·평가 파이프라인: 중복 통합 → CWE/OWASP 매핑 → 위험도·우선순위."""

from app.schemas.finding import ClassifiedFinding, NormalizedFinding
from app.services.classification.dedup import deduplicate
from app.services.classification.mapping import apply_mapping
from app.services.classification.risk import prioritize


def classify(findings: list[NormalizedFinding]) -> list[ClassifiedFinding]:
    classified = deduplicate(findings)
    apply_mapping(classified)
    return prioritize(classified)
