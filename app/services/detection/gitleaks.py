"""[백엔드 B] 시크릿·하드코딩 탐지: Gitleaks.

- --redact: 결과 파일 단계부터 실제 키 값을 가린다 (임시 폴더에도 원본이 남지 않게)
- 파싱 단계에서도 mask_secret 으로 한 번 더 마스킹 (--redact 누락 대비)
- raw 에서 Secret·Match 는 제외
"""

from pathlib import Path

from app.schemas.finding import Category, Location, NormalizedFinding, Severity
from app.services.detection.base import Detector
from app.services.detection.normalizer import make_fingerprint, mask_secret, to_relative

SECRET_CWE = "CWE-798"  # Use of Hard-coded Credentials


class GitleaksDetector(Detector):
    name = "gitleaks"

    def command(self, repo: Path) -> list[str]:
        # --no-git: 현재 파일 기준 탐지 (얕은 클론이라 히스토리는 없음)
        # v8.19+ 에서는 `gitleaks dir` 이 권장이지만 detect --no-git 도 계속 동작한다
        return [
            "gitleaks",
            "detect",
            "--source",
            str(repo),
            "--no-git",
            "--no-banner",
            "--redact",
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
            path = to_relative(r.get("File", ""), repo)
            start = r.get("StartLine") or 1
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
                        start_line=start,
                        end_line=r.get("EndLine") or start,
                        snippet=mask_secret(r.get("Match", ""), secret),
                    ),
                    cwe=[SECRET_CWE],
                    owasp=["A07:2021"],
                    fingerprint=make_fingerprint(path, start, SECRET_CWE),
                    raw=raw,
                )
            )
        return findings
