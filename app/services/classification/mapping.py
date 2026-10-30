"""공식 CWE 사전과 OWASP 2025 매핑."""

import re

from app.services.classification.core.catalog import load_catalog
from app.services.classification.core.service import compile_mapping, load_mapping


def normalize_cwe(values):
    result = set()
    for value in values:
        match = re.fullmatch(r"(?:CWE-)?([1-9][0-9]*)(?::.*)?", value.strip(), re.IGNORECASE)
        if match:
            result.add("CWE-" + match[1])
    return sorted(result)


def apply_mapping(findings):
    catalog = load_catalog()["weaknesses"]
    lookup = compile_mapping(load_mapping())
    for finding in findings:
        finding.cwe = [c for c in normalize_cwe(finding.cwe) if c in catalog and catalog[c]["status"] != "Deprecated"]
        finding.owasp = sorted({category for c in finding.cwe for category in lookup.get(c, ())})
        finding.owasp_top10 = next(iter(finding.owasp), None)


def classify_owasp(finding):
    apply_mapping([finding])
    return finding.owasp_top10
