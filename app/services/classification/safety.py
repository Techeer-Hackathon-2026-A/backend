"""공개·DB·D 경계에서 원본을 직접 전달하지 않는다."""

import re
from functools import lru_cache

from pydantic import ValidationError

from app.schemas.finding import Category
from app.services.classification.core.boundary import PublicRisk
from app.services.classification.core.catalog import load_catalog
from app.services.classification.core.service import compile_mapping, load_mapping


@lru_cache(maxsize=1)
def _trusted():
    return frozenset(load_catalog()["weaknesses"]), compile_mapping(load_mapping())


def safe_snapshot(finding):
    data = finding.model_dump(mode="json")
    data["raw"] = {}
    # 제목·메시지·규칙·스니펫은 임의 문자열이므로 공개 경계에서 제외한다.
    data.update(title="탐지된 보안 취약점", message="보안 분석 결과", rule_id="redacted")
    data["location"]["snippet"] = None
    data["fingerprint"] = "redacted"
    catalog, lookup = _trusted()
    data["cwe"] = [c for c in finding.cwe if c in catalog]
    data["owasp"] = sorted({category for c in data["cwe"] for category in lookup.get(c, ())})
    if finding.category == Category.SECRET:
        data["location"]["file_path"] = "[redacted]"
        data["dependency"] = None
    return data


def public_entity(entity, model):
    """과거 DB 레코드에도 적용하는 응답 allowlist 및 정제."""
    values = {name: getattr(entity, name) for name in model.model_fields}
    values.update(title="탐지된 보안 취약점", rule_id="redacted")
    if "message" in values:
        values["message"] = "보안 분석 결과"
        values["snippet"] = None
        try:
            assessment = PublicRisk.model_validate((entity.raw or {}).get("assessment", {}))
            values["message"] = (
                f"위험도: {assessment.level}; 근거: {assessment.basis}; "
                f"CVSS 버전: {assessment.cvss_version}; 점수: {assessment.score}; "
                f"정책: {assessment.policy_version}; OWASP: 2025"
            )
        except ValidationError:
            pass
    if entity.category == "secret":
        values["file_path"] = "[redacted]"
        if "dependency" in values:
            values["dependency"] = None
    catalog, lookup = _trusted()
    values["cwe"] = [c for c in values["cwe"] if c in catalog]
    # 조회 시점에 재분류하지 않는다. 과거 스캔은 저장 당시의 버전을 유지한다.
    stored = getattr(entity, "owasp", []) or []
    categories = sorted(
        {
            category
            for category in stored
            if isinstance(category, str) and re.fullmatch(r"A(?:0[1-9]|10):202[15]", category)
        }
    )
    representative = values.get("owasp_top10")
    if representative:
        match = re.match(r"^(A(?:0[1-9]|10):202[15])(?:-|$)", representative)
        representative = match[1] if match else None
    values["owasp_top10"] = representative if representative in categories else next(iter(categories), None)
    if "owasp" in values:
        values["owasp"] = categories
        # 공급망 메타데이터의 자유 문자열도 공개하지 않는다.
        values["dependency"] = None
        values["merged_tools"] = [
            tool for tool in values["merged_tools"] if tool in ("semgrep", "osv-scanner", "gitleaks")
        ]
    return model.model_validate(values)
