"""[백엔드 B] 시크릿·하드코딩 탐지: Gitleaks."""

from pathlib import Path

from app.schemas.finding import Category, Location, NormalizedFinding, Severity
from app.services.detection.base import Detector
from app.services.detection.normalizer import make_fingerprint, mask_secret


class GitleaksDetector(Detector):
    name = "gitleaks"

    def command(self, repo: Path) -> list[str]:
        # --no-git: 현재 파일 기준 탐지 (얕은 클론이라 히스토리는 없음)
        return [
            "gitleaks",
            "detect",
            "--source",
            str(repo),
            "--no-git",
            "--no-banner",
            "--report-format",
            "json",
            "--report-path",
            str(self.output_file),
            "--exit-code",
            "0",
        ]

    def parse(self, data: list, repo: Path) -> list[NormalizedFinding]:
        findings = []
        for r in data or []:
            path = r.get("File", "")
            path = str(Path(path).relative_to(repo)) if Path(path).is_absolute() else path
            secret = r.get("Secret", "")
            raw = {k: v for k, v in r.items() if k not in ("Secret", "Match")}  # 원본 키 값은 저장하지 않는다
            findings.append(
                NormalizedFinding(
                    tool=self.name,
                    category=Category.SECRET,
                    rule_id=r.get("RuleID", "generic-secret"),
                    title=f"하드코딩된 시크릿: {r.get('RuleID')}",
                    message=r.get("Description", ""),
                    severity=Severity.HIGH,
                    location=Location(
                        file_path=path,
                        start_line=r.get("StartLine", 1),
                        end_line=r.get("EndLine"),
                        snippet=mask_secret(r.get("Match", ""), secret),
                    ),
                    cwe=["CWE-798"],  # Use of Hard-coded Credentials
                    owasp=["A07:2021"],
                    fingerprint=make_fingerprint(path, r.get("StartLine", 1), "CWE-798"),
                    raw=raw,
                )
            )
        return findings
