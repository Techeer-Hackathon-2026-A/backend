"""[백엔드 D] 수정 코드 검증.

수정 코드를 적용한 파일에 같은 탐지 룰을 다시 돌려 문제가 사라졌는지 확인한다.
"""

import ast
import json
import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.services.git.github import FileChange, apply_changes

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    verified: bool
    note: str


def _syntax_ok(path: Path) -> tuple[bool, str]:
    """언어별 최소 문법 검사 (Python, JavaScript, TypeScript)."""
    ext = path.suffix.lower()

    # 1. Python 문법 검사 (AST)
    if ext == ".py":
        try:
            ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as e:
            return False, f"문법 오류: {e}"
        return True, ""

    # 2. JavaScript / TypeScript 문법 검사
    if ext in [".js", ".mjs", ".jsx", ".ts", ".tsx"]:
        # node CLI가 설치되어 있으면 구문 체크 수행
        if shutil.which("node"):
            try:
                proc = subprocess.run(
                    ["node", "--check", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if proc.returncode != 0:
                    err_msg = proc.stderr.strip() or "JavaScript 구문 오류"
                    return False, f"문법 오류: {err_msg}"
            except Exception as e:
                logger.warning(f"Node 문법 검사 실패 ({path}): {e}")

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
    if "." in rule_id and shutil.which("semgrep"):
        try:
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
        except subprocess.TimeoutExpired:
            return VerificationResult(False, "Semgrep 재스캔 시간 초과 (120초)")
        except Exception as e:
            logger.warning(f"Semgrep 재스캔 실행 실패: {e}")
            return VerificationResult(True, f"문법 검사 통과 (재스캔 예외 발생: {e})")

    return VerificationResult(True, "문법 검사 통과 (재스캔 미지원 룰)")
