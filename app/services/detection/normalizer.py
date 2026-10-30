"""[백엔드 B] 탐지 결과 정규화 공통 유틸 + 전체 탐지 실행."""

import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from app.schemas.finding import Category, NormalizedFinding

logger = logging.getLogger(__name__)

SNIPPET_CONTEXT_LINES = 3


def make_fingerprint(file_path: str, line: int, key: str) -> str:
    """같은 파일·같은 줄·같은 약점(CWE)이면 도구가 달라도 같은 값이 되도록 만든다."""
    return hashlib.sha256(f"{file_path}:{line}:{key}".encode()).hexdigest()[:32]


def mask_secret(text: str, secret: str) -> str:
    if not secret or len(secret) < 8:
        return text.replace(secret, "****") if secret else text
    masked = f"{secret[:4]}****{secret[-4:]}"
    return text.replace(secret, masked)


def attach_snippets(findings: list[NormalizedFinding], repo: Path) -> None:
    """임시 폴더가 삭제되기 전에 주변 코드를 잘라 저장한다. (시크릿은 이미 마스킹됨)"""
    cache: dict[str, list[str]] = {}
    for f in findings:
        if f.category == Category.SECRET or f.location.snippet:
            continue
        path = repo / f.location.file_path
        if not path.is_file():
            continue
        if f.location.file_path not in cache:
            try:
                cache[f.location.file_path] = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
        lines = cache[f.location.file_path]
        start = max(f.location.start_line - 1 - SNIPPET_CONTEXT_LINES, 0)
        end = min((f.location.end_line or f.location.start_line) + SNIPPET_CONTEXT_LINES, len(lines))
        f.location.snippet = "\n".join(lines[start:end])


def run_all_detectors(repo: Path, output_dir: Path) -> tuple[list[NormalizedFinding], dict[str, str]]:
    """탐지 도구 3종을 병렬 실행한다. 한 도구가 실패해도 나머지 결과는 살린다.

    반환: (정규화된 결과, {도구명: 에러 메시지})
    """
    from app.services.detection.gitleaks import GitleaksDetector
    from app.services.detection.osv import OsvDetector
    from app.services.detection.semgrep import SemgrepDetector

    detectors = [SemgrepDetector(output_dir), OsvDetector(output_dir), GitleaksDetector(output_dir)]
    findings: list[NormalizedFinding] = []
    errors: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=len(detectors)) as pool:
        futures = {pool.submit(d.run, repo): d.name for d in detectors}
        for future, name in futures.items():
            try:
                findings.extend(future.result())
            except Exception as e:  # noqa: BLE001
                logger.exception("detector %s failed", name)
                errors[name] = str(e)

    attach_snippets(findings, repo)
    return findings, errors
