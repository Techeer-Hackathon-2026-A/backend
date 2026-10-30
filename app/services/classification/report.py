"""기존 SecurityReport 형식의 공개 리포트 생성."""

from app.schemas.api import FindingOut, SecurityReport
from app.services.classification.core.service import LEVELS
from app.services.classification.safety import public_entity


def stored_report(scan, top_findings):
    summary = scan.summary or {}
    categories = {f"A{number:02d}:2025" for number in range(1, 11)}

    def counts(name, allowed):
        return {
            key: value
            for key, value in summary.get(name, {}).items()
            if key in allowed and isinstance(value, int) and value >= 0
        }

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
