"""[백엔드 D] 수정 코드 검증.

수정 코드를 적용한 파일에 같은 탐지 룰을 다시 돌려 문제가 사라졌는지 확인한다.
"""

import ast
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.services.git.github import FileChange, apply_changes


@dataclass
class VerificationResult:
    verified: bool
    note: str


def _syntax_ok(path: Path) -> tuple[bool, str]:
    """언어별 최소 문법 검사. TODO(D): JS/TS는 node --check 또는 tsc 등 추가"""
    if path.suffix == ".py":
        try:
            ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as e:
            return False, f"문법 오류: {e}"
    return True, ""


def verify_fix(repo: Path, change: FileChange, rule_id: str) -> VerificationResult:
    """repo는 해당 커밋으로 새로 클론한 임시 폴더여야 한다."""
    try:
        apply_changes(repo, [change])
    except ValueError as e:
        return VerificationResult(False, str(e))

    target = repo / change.file_path
    ok, note = _syntax_ok(target)
    if not ok:
        return VerificationResult(False, note)

    # Semgrep 룰이면 같은 룰로 해당 파일만 재스캔
    if "." in rule_id:
        proc = subprocess.run(
            [
                "semgrep",
                "scan",
                "--json",
                "--metrics=off",
                "--quiet",
                "--config",
                "p/owasp-top-ten",
                "--config",
                "p/cwe-top-25",
                str(target),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        results = json.loads(proc.stdout or "{}").get("results", [])
        if any(r.get("check_id") == rule_id for r in results):
            return VerificationResult(False, "재스캔 결과 같은 취약점이 여전히 탐지됨")
        return VerificationResult(True, "재스캔 결과 해당 취약점이 사라짐")

    return VerificationResult(True, "문법 검사 통과 (재스캔 미지원 룰)")
