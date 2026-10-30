"""[백엔드 B] SCA: OSV-Scanner (라이브러리 취약점).

설계
- 패키지 하나 = Finding 하나. 취약점(GHSA/CVE)이 여러 개여도 버전 하나만 올리면 되므로 묶는다.
  (취약점별로 나누면 같은 줄에 PR 이 여러 개 생겨 서로 충돌한다)
- 위치는 lock 파일이 아니라 수정 대상인 매니페스트(package.json, requirements.txt ...)의 해당 줄.
  매니페스트에서 못 찾으면 lock 파일에서 패키지명이 나오는 줄, 그것도 없으면 1번 줄.
- fixed_version = 모든 취약점을 해결하는 최소 버전. 하나라도 수정 버전이 없으면 None (자동 수정 대상 아님).

주의: OSV-Scanner 는 lock 파일 기준으로 검사한다.
  package.json 만 있고 package-lock.json 이 없으면 아무것도 잡히지 않는다.
  Python 은 requirements.txt 에 == 로 버전이 고정되어 있어야 한다.
"""

import re
from pathlib import Path

from app.schemas.finding import SEVERITY_WEIGHT, Category, DependencyInfo, Location, NormalizedFinding, Severity
from app.services.detection.base import Detector
from app.services.detection.normalizer import find_line, make_fingerprint, to_relative

SCA_CWE = "CWE-1395"  # Dependency on Vulnerable Third-Party Component

# lock 파일 → 같은 폴더의 매니페스트
MANIFEST_FOR = {
    "package-lock.json": "package.json",
    "yarn.lock": "package.json",
    "pnpm-lock.yaml": "package.json",
    "poetry.lock": "pyproject.toml",
    "uv.lock": "pyproject.toml",
    "Pipfile.lock": "Pipfile",
    "Cargo.lock": "Cargo.toml",
    "go.sum": "go.mod",
    "Gemfile.lock": "Gemfile",
    "composer.lock": "composer.json",
}

# GHSA database_specific.severity 표기
GHSA_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


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
    # 0: 취약점 없음, 1: 취약점 있음, 128: 검사할 lock 파일이 없음 (정상 상황)
    ok_exit_codes = (0, 1, 128)
    failure_hint = "OSV-Scanner 는 api.osv.dev 접속이 필요합니다"

    def command(self, repo: Path) -> list[str]:
        # v2 기준. v1이면 ["osv-scanner", "--format", "json", "--output", ..., "-r", repo]
        return ["osv-scanner", "scan", "source", "-r", "--format", "json", "--output", str(self.output_file), str(repo)]

    def parse(self, data: dict, repo: Path) -> list[NormalizedFinding]:
        findings = []
        for result in data.get("results", []) or []:
            lockfile = to_relative((result.get("source") or {}).get("path", ""), repo)
            for pkg in result.get("packages", []) or []:
                info = pkg.get("package") or {}
                name, version, ecosystem = info.get("name", ""), info.get("version", ""), info.get("ecosystem", "")
                vulns = pkg.get("vulnerabilities") or []
                if not name or not vulns:
                    continue

                file_path, line = _locate(repo, lockfile, name)
                vuln_ids = _unique(i for v in vulns for i in [v.get("id"), *(v.get("aliases") or [])])
                cwes = _unique(c for v in vulns for c in (v.get("database_specific") or {}).get("cwe_ids") or [])
                summaries = [f"{v.get('id')}: {v.get('summary') or (v.get('details') or '')[:200]}" for v in vulns]

                findings.append(
                    NormalizedFinding(
                        tool=self.name,
                        category=Category.SCA,
                        rule_id=vulns[0].get("id", "osv"),
                        title=f"{name} {version} 취약점 {len(vulns)}건",
                        message="\n".join(summaries[:10])[:2000],
                        severity=_package_severity(vulns, pkg.get("groups") or []),
                        location=Location(file_path=file_path, start_line=line, end_line=line),
                        cwe=cwes or [SCA_CWE],
                        owasp=["A06:2021"],  # Vulnerable and Outdated Components
                        dependency=DependencyInfo(
                            package=name,
                            ecosystem=ecosystem,
                            installed_version=version,
                            fixed_version=_fixed_version(vulns, name, version),
                            vuln_ids=vuln_ids,
                        ),
                        # 같은 패키지·같은 버전이면 같은 지문 (lock 파일이 여러 개여도 매니페스트 기준으로 합쳐짐)
                        fingerprint=make_fingerprint(file_path, 0, f"{ecosystem}:{name}:{version}"),
                        raw={"lockfile": lockfile, "vuln_count": len(vulns), "vulnerabilities": vulns},
                    )
                )
        return findings


# ---------------------------------------------------------------- helpers
def _unique(items) -> list[str]:
    seen: list[str] = []
    for i in items:
        if i and i not in seen:
            seen.append(i)
    return seen


def _locate(repo: Path, lockfile: str, name: str) -> tuple[str, int]:
    """수정 대상 파일과 줄 번호."""
    folder = str(Path(lockfile).parent) if Path(lockfile).parent != Path(".") else ""
    candidates = []
    manifest = MANIFEST_FOR.get(Path(lockfile).name)
    if manifest:
        candidates.append(f"{folder}/{manifest}" if folder else manifest)
    candidates.append(lockfile)
    for cand in candidates:
        needle = f'"{name}"' if cand.endswith(".json") else name
        line = find_line(repo, cand, needle)
        if line:
            return cand, line
    return lockfile, 1


def _package_severity(vulns: list[dict], groups: list[dict]) -> Severity:
    """패키지의 취약점 중 가장 높은 심각도. GHSA 표기 → CVSS 점수 순으로 본다."""
    candidates: list[Severity] = []
    for v in vulns:
        s = str((v.get("database_specific") or {}).get("severity", "")).upper()
        if s in GHSA_SEVERITY:
            candidates.append(GHSA_SEVERITY[s])
    for g in groups:
        try:
            candidates.append(_severity_from_cvss(float(g.get("max_severity"))))
        except (TypeError, ValueError):
            continue
    if not candidates:
        return Severity.MEDIUM
    return max(candidates, key=lambda s: SEVERITY_WEIGHT[s])


def _vkey(v: str) -> tuple:
    """버전 비교 키. '4.17.21' → (4, 17, 21, 1). 프리릴리스(-beta 등)는 같은 숫자의 정식보다 낮게."""
    main, _, pre = str(v).lstrip("v=^~").partition("-")
    nums = tuple(int(x) for x in re.findall(r"\d+", main))
    return (*nums, 0 if pre else 1)


def _fixed_version(vulns: list[dict], name: str, current: str) -> str | None:
    """모든 취약점을 해결하는 최소 버전.

    취약점마다 '현재 버전보다 높은 fixed 중 최솟값'을 구하고, 그중 최댓값을 고른다.
    수정 버전이 없는 취약점이 하나라도 있으면 None.
    """
    if not current:
        return None
    cur = _vkey(current)
    per_vuln: list[str] = []
    for v in vulns:
        fixes = []
        for affected in v.get("affected") or []:
            if (affected.get("package") or {}).get("name") not in (None, name):
                continue  # 다른 패키지의 범위는 무시
            for rng in affected.get("ranges") or []:
                for event in rng.get("events") or []:
                    fixed = event.get("fixed")
                    if fixed and _vkey(fixed) > cur:
                        fixes.append(fixed)
        if not fixes:
            return None
        per_vuln.append(min(fixes, key=_vkey))
    return max(per_vuln, key=_vkey) if per_vuln else None
