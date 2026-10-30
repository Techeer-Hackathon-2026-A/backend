"""목 데이터와 실제 저장소 어댑터에서 공통으로 호출할 분류·평가 서비스."""

import json
from collections import Counter
from copy import deepcopy
from pathlib import Path

from .catalog import load_catalog
from .dedup import merge

POLICY_VERSION = "2025-mock-v3"
LEVELS = ("critical", "high", "medium", "low", "info", "unknown")
LEVEL_RANK = {level: rank for rank, level in enumerate(LEVELS)}


def compile_mapping(mapping):
    """CWE별 범주 검색 인덱스를 리포트당 한 번만 구성한다."""
    index = {}
    for row in mapping["categories"]:
        for cwe in row["cwes"]:
            index.setdefault(cwe, set()).add(row["category"])
    return index


def load_mapping():
    data = json.loads((Path(__file__).parent / "data/owasp2025.json").read_text(encoding="utf-8-sig"))
    if data["version"] != "2025" or len(data["categories"]) != 10:
        raise RuntimeError("OWASP 매핑 자료가 불완전합니다")
    return data


def classify(findings, mapping, *, index=None, catalog=None):
    supplied = {c for f in findings for c in f.cwe_ids}
    if catalog is None:
        catalog = load_catalog()
    if index is None:
        index = compile_mapping(mapping)
    entries = catalog["weaknesses"]
    verified = sorted(c for c in supplied if c in entries and entries[c]["status"] != "Deprecated")
    deprecated = sorted(c for c in supplied if c in entries and entries[c]["status"] == "Deprecated")
    unresolved = len(supplied - entries.keys())
    categories = sorted({category for c in verified for category in index.get(c, ())})
    return dict(
        cwe_ids=verified,
        unresolved_cwe_count=unresolved,
        cwe_status="verified" if verified else "unmapped",
        owasp_categories=categories,
        owasp_version="2025",
        mapping_revision=mapping["revision"],
        cwe_catalog_version=catalog["version"],
        deprecated_cwe_ids=deprecated,
    )


def risk(finding):
    score = finding.cvss_score
    if score is not None:
        if finding.cvss_version == "2.0":
            level = "high" if score >= 7 else "medium" if score >= 4 else "low"
        else:
            level = (
                "critical"
                if score >= 9
                else "high"
                if score >= 7
                else "medium"
                if score >= 4
                else "low"
                if score > 0
                else "info"
            )
        return dict(level=level, score=score, cvss_version=finding.cvss_version, basis="provided_cvss")
    aliases = {"error": "high", "warning": "medium", "informational": "info"}
    original = (finding.severity_original or "").strip().lower()
    level = aliases.get(original, original)
    return dict(
        level=level if level in LEVELS else "unknown",
        score=None,
        cvss_version=None,
        basis="tool_severity" if level in LEVELS else "missing",
    )


def evaluate(findings):
    values = [risk(f) for f in findings]
    # 버전 간 CVSS 숫자로 동점을 해소하지 않는다.
    best = min(
        values, key=lambda r: (LEVEL_RANK[r["level"]], r["score"] is None, r["cvss_version"] or "", -(r["score"] or 0))
    )
    return best | {
        "policy_version": POLICY_VERSION,
        "evidence": [dict(tool=f.tool, **value) for f, value in zip(findings, values, strict=False)],
    }


def build_report(analysis_id, findings, *, repository_id, commit_sha, tool_statuses):
    """입력 문자열/원본을 공개 모델에 복사하지 않는다. A에서 접근 권한을 검사해야 한다."""
    statuses = {"success", "failed", "partial", "not_run"}
    if set(tool_statuses) != {"semgrep", "osv", "gitleaks"} or any(s not in statuses for s in tool_statuses.values()):
        raise ValueError("모든 도구의 실행 상태가 필요합니다")
    if any(not isinstance(v, str) or not v.strip() for v in (analysis_id, repository_id, commit_sha)):
        raise ValueError("분석·저장소·커밋 식별자가 필요합니다")
    if any(tool_statuses[f.tool] == "not_run" for f in findings):
        raise ValueError("미실행 도구의 탐지 결과가 포함되어 있습니다")
    mapping = load_mapping()
    index = compile_mapping(mapping)
    catalog = load_catalog()
    groups = merge(analysis_id, findings)
    items = []
    for group in groups:
        classification = classify(group.sources, mapping, index=index, catalog=catalog)
        assessment = evaluate(group.sources)
        items.append(
            dict(
                vulnerability_id=group.vulnerability_id,
                title="탐지된 보안 취약점",
                kind=group.sources[0].kind,
                tools=sorted({f.tool for f in group.sources}),
                source_count=len(group.sources),
                merge_reason=group.reason,
                classification=classification,
                risk=assessment,
            )
        )
    items.sort(key=lambda i: (LEVEL_RANK[i["risk"]["level"]], i["vulnerability_id"]))
    severity_counts = Counter(i["risk"]["level"] for i in items)
    return dict(
        analysis_id=analysis_id,
        repository_id=repository_id,
        commit_sha=commit_sha,
        data_origin="provided_findings",
        owasp_version="2025",
        policy_version=POLICY_VERSION,
        tool_statuses=dict(tool_statuses),
        complete=all(s == "success" for s in tool_statuses.values()),
        raw_count=len(findings),
        vulnerability_count=len(items),
        severity_counts={level: severity_counts[level] for level in LEVELS},
        cwe_counts=dict(Counter(c for i in items for c in i["classification"]["cwe_ids"])),
        owasp_counts=dict(Counter(c for i in items for c in i["classification"]["owasp_categories"])),
        unmapped_owasp_count=sum(not i["classification"]["owasp_categories"] for i in items),
        tool_counts=dict(Counter(f.tool for f in findings)),
        vulnerabilities=items,
    )


def get_detail(report, vulnerability_id):
    for item in report["vulnerabilities"]:
        if item["vulnerability_id"] == vulnerability_id:
            # 호출자가 리포트를 변경하지 못하도록 복사한다.
            return deepcopy(item)
    raise KeyError("취약점을 찾을 수 없습니다")
