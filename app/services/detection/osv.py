"""[백엔드 B] SCA: OSV-Scanner (라이브러리 취약점)."""

from pathlib import Path

from app.schemas.finding import Category, DependencyInfo, Location, NormalizedFinding, Severity
from app.services.detection.base import Detector
from app.services.detection.normalizer import make_fingerprint


def _severity_from_cvss(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


class OsvDetector(Detector):
    name = "osv-scanner"

    def command(self, repo: Path) -> list[str]:
        # v2 기준. v1이면 ["osv-scanner", "--format", "json", "--output", ..., "-r", repo]
        return ["osv-scanner", "scan", "source", "-r", "--format", "json", "--output", str(self.output_file), str(repo)]

    def parse(self, data: dict, repo: Path) -> list[NormalizedFinding]:
        findings = []
        for result in data.get("results", []):
            source = result.get("source", {}).get("path", "")
            lockfile = str(Path(source).relative_to(repo)) if Path(source).is_absolute() else source
            for pkg in result.get("packages", []):
                info = pkg.get("package", {})
                max_score = _max_cvss(pkg.get("groups", []))
                for vuln in pkg.get("vulnerabilities", []):
                    vuln_ids = [vuln["id"], *vuln.get("aliases", [])]
                    findings.append(
                        NormalizedFinding(
                            tool=self.name,
                            category=Category.SCA,
                            rule_id=vuln["id"],
                            title=f"{info.get('name')} {info.get('version')} 취약점",
                            message=vuln.get("summary") or vuln.get("details", "")[:500],
                            severity=_severity_from_cvss(max_score),
                            location=Location(file_path=lockfile, start_line=1),
                            cwe=vuln.get("database_specific", {}).get("cwe_ids", []),
                            owasp=["A06:2021"],  # Vulnerable and Outdated Components
                            dependency=DependencyInfo(
                                package=info.get("name", ""),
                                ecosystem=info.get("ecosystem", ""),
                                installed_version=info.get("version", ""),
                                fixed_version=_fixed_version(vuln),
                                vuln_ids=vuln_ids,
                            ),
                            fingerprint=make_fingerprint(lockfile, 0, f"{info.get('name')}:{vuln['id']}"),
                            raw=vuln,
                        )
                    )
        return findings


def _max_cvss(groups: list[dict]) -> float | None:
    scores = [float(g["max_severity"]) for g in groups if g.get("max_severity")]
    return max(scores) if scores else None


def _fixed_version(vuln: dict) -> str | None:
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None
