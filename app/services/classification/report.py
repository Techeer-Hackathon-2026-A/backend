"""기존 SecurityReport 형식의 공개 리포트 생성."""

from app.schemas.api import FindingOut, SecurityReport
from app.services.classification.core.service import LEVELS
from app.services.classification.safety import public_entity


def stored_report(scan, top_findings):
    summary = scan.summary or {}
    categories = {f"A{number:02d}:{year}" for number in range(1, 11) for year in (2021, 2025)}

    def counts(name, allowed):
        import re

        result = {}
        for key, value in summary.get(name, {}).items():
            safe_key = key
            if name == "owasp_matrix" and isinstance(key, str):
                match = re.match(r"^(A(?:0[1-9]|10):202[15])(?:-|$)", key)
                safe_key = match[1] if match else None
            if safe_key in allowed and isinstance(value, int) and value >= 0:
                result[safe_key] = result.get(safe_key, 0) + value
        return result

    total = summary.get("total", 0)
    return SecurityReport(
        scan_id=scan.id,
        grade=scan.grade if scan.grade in {"A", "B", "C", "D", "E", "U", None} else None,
        total=total if isinstance(total, int) and total >= 0 else 0,
        by_severity=counts("by_severity", set(LEVELS)),
        by_category=counts("by_category", {"sast", "sca", "secret"}),
        owasp_matrix=counts("owasp_matrix", categories),
        top_findings=[public_entity(finding, FindingOut) for finding in top_findings],
    )
