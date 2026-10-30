"""[백엔드 B] 탐지 결과 파서 테스트 (도구 원본 JSON 샘플 기반)."""

from pathlib import Path

from app.schemas.finding import Category
from app.services.detection.gitleaks import GitleaksDetector
from app.services.detection.normalizer import mask_secret
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
