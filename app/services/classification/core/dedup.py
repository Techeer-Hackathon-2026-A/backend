"""정보가 부족하면 통합하지 않는 보수적인 중복 통합."""

import json
from dataclasses import dataclass
from hashlib import sha256

from .models import Finding


@dataclass(frozen=True)
class Group:
    vulnerability_id: str
    sources: tuple[Finding, ...]
    reason: str


def merge(analysis_id: str, findings: list[Finding]) -> list[Group]:
    if len({f.finding_id for f in findings}) != len(findings):
        raise ValueError("분석 내 finding_id는 고유해야 합니다")
    buckets = {}
    for f in findings:
        locations = tuple(
            sorted((p.path, p.start_line, p.end_line, p.start_column or 0, p.end_column or 0) for p in f.locations)
        )
        if f.kind == "dependency":
            # 별칭의 진위가 검증되지 않았으므로 식별자 집합이 정확히 같을 때만 통합한다.
            key = (f.kind, f.package.model_dump_json(), tuple(sorted(set(f.vulnerability_ids))))
            reason = "패키지·버전·manifest 및 취약점 식별자 집합 일치"
        elif f.kind == "code":
            # 도구 간 규칙 동등성 표가 없으므로 같은 도구·규칙만 통합한다.
            # 열 정보가 없으면 같은 행의 서로 다른 표현식을 구분할 수 없다.
            precision = () if all(p.start_column is not None for p in f.locations) else (f.finding_id,)
            key = (f.kind, f.tool, f.rule_id, locations, tuple(sorted(set(f.vulnerability_ids))), precision)
            reason = (
                "동일 도구·규칙·취약점 식별자 및 행·열 위치 일치" if not precision else "열 정보 부족으로 개별 유지"
            )
        else:
            key = (f.kind, f.finding_id)
            reason = "안전한 시크릿 지문 계약 전 개별 유지"
        buckets.setdefault(key, (reason, []))[1].append(f)
    result = []
    for key, (reason, sources) in buckets.items():
        identity = json.dumps([analysis_id, key], ensure_ascii=True)
        result.append(
            Group(sha256(identity.encode()).hexdigest(), tuple(sorted(sources, key=lambda f: f.finding_id)), reason)
        )
    return sorted(result, key=lambda group: group.vulnerability_id)
