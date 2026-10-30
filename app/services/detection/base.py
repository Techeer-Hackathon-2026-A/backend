"""[백엔드 B] 탐지 도구 어댑터 공통 인터페이스.

새 도구를 붙일 때는 Detector를 상속해 run()과 parse()만 구현하면 된다.
"""

import json
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path

from app.core.config import get_settings
from app.schemas.finding import NormalizedFinding


class DetectorError(Exception):
    pass


class Detector(ABC):
    name: str

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_file = output_dir / f"{self.name}.json"

    @abstractmethod
    def command(self, repo: Path) -> list[str]:
        """실행할 CLI 명령. 결과는 self.output_file에 JSON으로 저장되게 한다."""

    @abstractmethod
    def parse(self, data: dict | list, repo: Path) -> list[NormalizedFinding]:
        """도구 원본 JSON → 공통 스키마."""

    # 일부 도구는 "취약점 발견" 시 exit code 1을 반환하므로 성공으로 본다.
    ok_exit_codes: tuple[int, ...] = (0, 1)
    # 실패 시 에러 메시지에 덧붙일 안내 (도구별로 덮어쓴다)
    failure_hint: str = ""

    def _error_from_output(self) -> str:
        """결과 JSON 의 errors 항목에서 원인을 꺼낸다. 없으면 빈 문자열."""
        try:
            data = json.loads(self.output_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return ""
        errors = data.get("errors") if isinstance(data, dict) else None
        if not errors:
            return ""
        msgs = [str(e.get("message") or e.get("type") or e) if isinstance(e, dict) else str(e) for e in errors[:3]]
        return " / ".join(msgs)[:500]

    @staticmethod
    def _error_from_stderr(text: str) -> str:
        """stderr 에서 경고(Deprecation/UserWarning 등) 줄을 빼고 마지막 의미 있는 줄들만 남긴다."""
        lines = [
            ln
            for ln in (text or "").splitlines()
            if ln.strip() and "Warning" not in ln and not ln.lstrip().startswith("from pkg_resources")
        ]
        return "\n".join(lines[-3:])[-500:]

    def run(self, repo: Path) -> list[NormalizedFinding]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(
                self.command(repo), capture_output=True, text=True, timeout=get_settings().tool_timeout_sec
            )
        except FileNotFoundError as e:
            raise DetectorError(f"{self.name} 실행 파일을 찾을 수 없습니다") from e
        except subprocess.TimeoutExpired as e:
            raise DetectorError(f"{self.name} 시간 초과") from e

        if proc.returncode not in self.ok_exit_codes:
            detail = (
                self._error_from_output()
                or self._error_from_stderr(proc.stderr)
                or self._error_from_stderr(proc.stdout)
                or "(에러 메시지 없음)"
            )
            hint = f" | {self.failure_hint}" if self.failure_hint else ""
            raise DetectorError(f"{self.name} 실패 (exit {proc.returncode}): {detail}{hint}")
        if not self.output_file.exists() or self.output_file.stat().st_size == 0:
            return []
        return self.parse(json.loads(self.output_file.read_text(encoding="utf-8")), repo)
