"""[백엔드 B] 탐지 결과 파서 테스트 (도구 원본 JSON 샘플 기반)."""

from pathlib import Path

from app.schemas.finding import Category, Severity
from app.services.detection.gitleaks import GitleaksDetector
from app.services.detection.normalizer import mask_secret, to_relative
from app.services.detection.osv import OsvDetector, _fixed_version
from app.services.detection.semgrep import SemgrepDetector

REPO = Path("/tmp/scan_x/repo").resolve()


def test_semgrep_parse():
    data = {
        "results": [
            {
                "check_id": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
                "path": str(REPO / "app" / "db.py"),
                "start": {"line": 10},
                "end": {"line": 10},
                "extra": {
                    "message": "SQL injection",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-89: SQL Injection"], "owasp": ["A03:2021 - Injection"]},
                },
            }
        ]
    }
    [f] = SemgrepDetector(Path("/tmp/out")).parse(data, REPO)
    assert f.category == Category.SAST
    assert f.location.file_path == str(Path("app/db.py"))
    assert f.cwe == ["CWE-89"]
    assert f.owasp == ["A03:2021"]


def test_gitleaks_parse_masks_secret():
    secret = "sk-proj-abcdefghijklmnop1234"
    data = [
        {
            "RuleID": "openai-api-key",
            "Description": "OpenAI key",
            "File": str(REPO / "src" / "ai.ts"),
            "StartLine": 3,
            "EndLine": 3,
            "Secret": secret,
            "Match": f'const KEY = "{secret}";',
        }
    ]
    [f] = GitleaksDetector(Path("/tmp/out")).parse(data, REPO)
    assert f.location.file_path == str(Path("src/ai.ts"))
    assert secret not in (f.location.snippet or "")
    assert "Secret" not in f.raw and "Match" not in f.raw


def test_mask_secret():
    assert mask_secret("key=abcd12345678wxyz", "abcd12345678wxyz") == "key=abcd****wxyz"
    assert mask_secret("pw=short123", "short123") == "pw=****"  # 짧은 키는 전부 가림
    assert mask_secret('k="REDACTED"', "REDACTED") == 'k="REDACTED"'  # --redact 결과는 그대로


def test_error_from_stderr_skips_warnings():
    from app.services.detection.base import Detector

    stderr = (
        "/x/dependencies.py:4: UserWarning: pkg_resources is deprecated as an API.\n"
        "  from pkg_resources import (\n"
        "Traceback (most recent call last):\n"
        "requests.exceptions.ProxyError: HTTPSConnectionPool(host='semgrep.dev', port=443)\n"
    )
    detail = Detector._error_from_stderr(stderr)
    assert "ProxyError" in detail and "pkg_resources" not in detail


def test_gitleaks_command_uses_redact():
    assert "--redact" in GitleaksDetector(Path("/tmp/out")).command(REPO)


def test_to_relative_handles_symlinked_tmp(tmp_path):
    real = tmp_path / "real"
    (real / "app").mkdir(parents=True)
    (real / "app" / "x.py").write_text("x = 1\n")
    link = tmp_path / "link"
    link.symlink_to(real)
    # 도구는 실제 경로로, 레포 경로는 링크로 받은 경우 (macOS /var ↔ /private/var)
    assert to_relative(str(real / "app" / "x.py"), link) == "app/x.py"
    assert to_relative("./app/x.py", link) == "app/x.py"


# ------------------------------------------------------------------ OSV
def _osv_repo(tmp_path: Path) -> Path:
    (tmp_path / "package.json").write_text(
        '{\n  "name": "demo",\n  "dependencies": {\n    "express": "^4.17.1",\n    "lodash": "^4.17.15"\n  }\n}\n'
    )
    (tmp_path / "package-lock.json").write_text('{"packages": {"node_modules/lodash": {"version": "4.17.15"}}}')
    return tmp_path


def _osv_data(repo: Path) -> dict:
    def vuln(vid, cve, fixed, sev, cwes):
        return {
            "id": vid,
            "aliases": [cve],
            "summary": f"{vid} summary",
            "affected": [
                {
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
                },
                # 다른 패키지 범위가 섞여 있어도 무시해야 함
                {"package": {"name": "lodash-es"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]},
            ],
            "database_specific": {"severity": sev, "cwe_ids": cwes},
        }

    return {
        "results": [
            {
                "source": {"path": str(repo / "package-lock.json"), "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
                        "vulnerabilities": [
                            vuln("GHSA-p6mc-m468-83gw", "CVE-2020-8203", "4.17.19", "HIGH", ["CWE-1321"]),
                            vuln("GHSA-35jh-r3h4-6jhm", "CVE-2021-23337", "4.17.21", "HIGH", ["CWE-77", "CWE-94"]),
                            vuln("GHSA-29mw-wpgm-hmr9", "CVE-2020-28500", "4.17.21", "MODERATE", ["CWE-1333"]),
                        ],
                        "groups": [{"ids": ["GHSA-35jh-r3h4-6jhm"], "max_severity": "7.2"}],
                    }
                ],
            }
        ]
    }


def test_osv_groups_vulns_per_package(tmp_path):
    repo = _osv_repo(tmp_path)
    findings = OsvDetector(Path("/tmp/out")).parse(_osv_data(repo), repo)
    assert len(findings) == 1  # 취약점 3개 → 패키지 1건
    [f] = findings
    assert f.category == Category.SCA
    assert f.severity == Severity.HIGH
    assert f.title == "lodash 4.17.15 취약점 3건"
    assert {"CVE-2020-8203", "CVE-2021-23337", "GHSA-29mw-wpgm-hmr9"} <= set(f.dependency.vuln_ids)
    assert f.owasp == ["A06:2021"]


def test_osv_points_to_manifest_line(tmp_path):
    repo = _osv_repo(tmp_path)
    [f] = OsvDetector(Path("/tmp/out")).parse(_osv_data(repo), repo)
    assert f.location.file_path == "package.json"  # lock 파일이 아니라 매니페스트
    assert f.location.start_line == 5  # "lodash" 가 있는 줄
    assert f.raw["lockfile"] == "package-lock.json"


def test_osv_fixed_version_covers_all_vulns(tmp_path):
    repo = _osv_repo(tmp_path)
    [f] = OsvDetector(Path("/tmp/out")).parse(_osv_data(repo), repo)
    assert f.dependency.fixed_version == "4.17.21"  # 4.17.19 는 일부만 해결, 다른 패키지의 9.9.9 는 무시


def test_osv_fixed_version_none_when_unfixable():
    vulns = [{"affected": [{"package": {"name": "x"}, "ranges": [{"events": [{"introduced": "0"}]}]}]}]
    assert _fixed_version(vulns, "x", "1.0.0") is None


def test_osv_no_lockfile_exit_code_is_ok():
    assert 128 in OsvDetector(Path("/tmp/out")).ok_exit_codes


def test_osv_bad_cvss_does_not_crash(tmp_path):
    repo = _osv_repo(tmp_path)
    data = _osv_data(repo)
    pkg = data["results"][0]["packages"][0]
    pkg["groups"] = [{"max_severity": ""}, {"max_severity": "n/a"}]
    for v in pkg["vulnerabilities"]:
        v["database_specific"] = {}
    [f] = OsvDetector(Path("/tmp/out")).parse(data, repo)
    assert f.severity == Severity.MEDIUM
    assert f.cwe == ["CWE-1395"]
