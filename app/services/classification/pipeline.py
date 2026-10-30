"""[백엔드 C] 분류·평가 파이프라인: 중복 통합 → CWE/OWASP 매핑 → 위험도·우선순위."""

from hashlib import sha256

from app.schemas.finding import ClassifiedFinding, NormalizedFinding

# 새 분석 묶음 계약용 진입점. 기존 worker의 classify(list) 계약은 유지한다.
from app.services.classification.core.boundary import process_batch as process_batch
from app.services.classification.core.catalog import load_catalog
from app.services.classification.core.dedup import merge
from app.services.classification.core.models import Finding as CoreFinding
from app.services.classification.core.service import LEVEL_RANK, compile_mapping, evaluate, load_mapping
from app.services.classification.core.service import classify as classify_cwe
from app.services.classification.mapping import normalize_cwe
from app.services.classification.safety import safe_snapshot


def classify(findings: list[NormalizedFinding]) -> list[ClassifiedFinding]:
    originals = {}
    adapted = []
    occurrences = {}
    for finding in findings:
        # 원본 추적에는 원문 대신 콘텐츠 해시를 사용한다.
        digest = sha256(finding.model_dump_json().encode()).hexdigest()
        number = occurrences.get(digest, 0)
        occurrences[digest] = number + 1
        identifier = f"{digest}-{number}"
        originals[identifier] = finding
        package = None
        ids = ()
        if finding.dependency:
            dep = finding.dependency
            package = dict(
                ecosystem=dep.ecosystem,
                name=dep.package,
                version=dep.installed_version,
                manifest=finding.location.file_path,
            )
            ids = tuple(dep.vuln_ids)
        adapted.append(
            CoreFinding(
                finding_id=identifier,
                tool="osv" if finding.tool == "osv-scanner" else finding.tool,
                kind={"sast": "code", "sca": "dependency", "secret": "secret"}[finding.category.value],
                rule_id=finding.rule_id,
                locations=[
                    dict(
                        path=finding.location.file_path,
                        start_line=finding.location.start_line,
                        end_line=finding.location.end_line or finding.location.start_line,
                        start_column=finding.location.start_column,
                        end_column=finding.location.end_column,
                    )
                ],
                package=package,
                vulnerability_ids=ids,
                cwe_ids=normalize_cwe(finding.cwe),
                cvss_score=finding.cvss_score,
                cvss_version=finding.cvss_version,
                severity_original=finding.severity.value,
            )
        )
    mapping, catalog = load_mapping(), load_catalog()
    lookup = compile_mapping(mapping)
    result = []
    for group in merge("worker", adapted):
        mapped = classify_cwe(group.sources, mapping, index=lookup, catalog=catalog)
        assessment = evaluate(group.sources)
        sources = [originals[f.finding_id] for f in group.sources]
        data = safe_snapshot(sources[0])
        data.update(cwe=mapped["cwe_ids"], owasp=mapped["owasp_categories"], severity=assessment["level"])
        # 기존 JSON 컬럼에 근거와 비식별 원본을 저장해 DB 마이그레이션을 피한다.
        data["raw"] = dict(
            classification=mapped,
            assessment=assessment,
            merge_reason=group.reason,
            sources=[
                dict(source_id=sha256(f.model_dump_json().encode()).hexdigest(), finding=safe_snapshot(f))
                for f in sources
            ],
        )
        data["fingerprint"] = group.vulnerability_id
        score = assessment["score"]
        risk_score = (
            score * 10
            if score is not None
            else {"critical": 90, "high": 70, "medium": 40, "low": 10, "info": 0, "unknown": 0}[assessment["level"]]
        )
        result.append(
            ClassifiedFinding(
                **data,
                owasp_top10=next(iter(mapped["owasp_categories"]), None),
                risk_score=risk_score,
                duplicate_count=len(sources),
                merged_tools=sorted({f.tool for f in sources}),
            )
        )
    result.sort(key=lambda f: (LEVEL_RANK[f.severity.value], f.fingerprint))
    for index, finding in enumerate(result, 1):
        finding.priority = index
    return result
