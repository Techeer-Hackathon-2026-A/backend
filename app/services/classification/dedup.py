"""[백엔드 C] 중복 탐지 통합.

같은 fingerprint(같은 파일·줄·약점)는 하나로 합치고, 가장 높은 심각도를 남긴다.
"""

from app.schemas.finding import SEVERITY_WEIGHT, ClassifiedFinding, NormalizedFinding


def deduplicate(findings: list[NormalizedFinding]) -> list[ClassifiedFinding]:
    merged: dict[str, ClassifiedFinding] = {}
    for f in findings:
        existing = merged.get(f.fingerprint)
        if existing is None:
            merged[f.fingerprint] = ClassifiedFinding(**f.model_dump(), merged_tools=[f.tool])
            continue

        existing.duplicate_count += 1
        if f.tool not in existing.merged_tools:
            existing.merged_tools.append(f.tool)
        existing.cwe = sorted(set(existing.cwe) | set(f.cwe))
        existing.owasp = sorted(set(existing.owasp) | set(f.owasp))
        if SEVERITY_WEIGHT[f.severity] > SEVERITY_WEIGHT[existing.severity]:
            existing.severity = f.severity
        # TODO(C): 줄 번호가 1~2줄 차이 나는 근접 탐지도 합칠지 결정
    return list(merged.values())
