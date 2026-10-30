"""[백엔드 B] SAST: Semgrep (OWASP Top 10 / CWE 룰셋)."""

from pathlib import Path

from app.schemas.finding import Category, Location, NormalizedFinding, Severity
from app.services.detection.base import Detector
from app.services.detection.normalizer import make_fingerprint
from app.services.git.repo import EXCLUDED_DIRS

SEVERITY_MAP = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}

# 커스텀 룰(바이브 코딩 특화)은 rules/ 폴더에 추가
# 시크릿은 Gitleaks가 담당 (Semgrep 결과에는 마스킹이 안 되므로 p/secrets는 넣지 않는다)
RULESETS = ["p/owasp-top-ten", "p/cwe-top-25"]


class SemgrepDetector(Detector):
    name = "semgrep"

    def command(self, repo: Path) -> list[str]:
        cmd = ["semgrep", "scan", "--json", "--output", str(self.output_file), "--metrics=off", "--quiet"]
        for ruleset in RULESETS:
            cmd += ["--config", ruleset]
        for d in EXCLUDED_DIRS:
            cmd += ["--exclude", d]
        return [*cmd, str(repo)]

    def parse(self, data: dict, repo: Path) -> list[NormalizedFinding]:
        findings = []
        for r in data.get("results", []):
            meta = r.get("extra", {}).get("metadata", {})
            path = str(Path(r["path"]).relative_to(repo)) if Path(r["path"]).is_absolute() else r["path"]
            cwe = [c.split(":")[0].strip() for c in _as_list(meta.get("cwe"))]
            findings.append(
                NormalizedFinding(
                    tool=self.name,
                    category=Category.SAST,
                    rule_id=r["check_id"],
                    title=r["check_id"].split(".")[-1],
                    message=r.get("extra", {}).get("message", ""),
                    severity=SEVERITY_MAP.get(r.get("extra", {}).get("severity", ""), Severity.MEDIUM),
                    location=Location(file_path=path, start_line=r["start"]["line"], end_line=r["end"]["line"]),
                    cwe=cwe,
                    owasp=[o.split(" ")[0] for o in _as_list(meta.get("owasp"))],
                    fingerprint=make_fingerprint(path, r["start"]["line"], cwe[0] if cwe else r["check_id"]),
                    raw=r,
                )
            )
        return findings


def _as_list(value) -> list[str]:
    if not value:
        return []
    return value if isinstance(value, list) else [value]
