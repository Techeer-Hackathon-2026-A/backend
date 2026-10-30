"""[백엔드 D] AI 수정 코드 생성."""

import hashlib
import json
import logging
from pathlib import Path

from pydantic import BaseModel

from app.core.config import get_settings
from app.core.redis_client import get_redis
from app.services.ai.client import ask_json
from app.services.ai.prompts import FIX_SYSTEM, build_fix_prompt
from app.services.git.repo import EXTENSION_LANGUAGE

logger = logging.getLogger(__name__)

CACHE_TTL_SEC = 60 * 60 * 24 * 7  # 7일


class FixResult(BaseModel):
    original_code: str
    fixed_code: str
    explanation: str


def _cache_key(rule_id: str, snippet: str) -> str:
    """rule_id와 스니펫 해시를 결합한 Redis 캐시 키 생성."""
    snippet_hash = hashlib.sha256(snippet.strip().encode("utf-8")).hexdigest()[:16]
    return f"ai_fix:{rule_id}:{snippet_hash}"


def _expand_context(
    file_path: str,
    start_line: int,
    snippet: str,
    repo_root: Path | None = None,
    context_lines: int = 10,
) -> str:
    """스니펫이 너무 짧을 때, 원본 파일이 존재하면 전후 라인을 읽어 맥락을 확장한다."""
    target_path = (repo_root / file_path) if repo_root else Path(file_path)
    if not target_path.exists() or not target_path.is_file():
        return snippet

    try:
        lines = target_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        total_lines = len(lines)
        if total_lines == 0:
            return snippet

        # 스니펫 줄 수가 이미 충분하면(5줄 이상) 그대로 사용
        snippet_lines = snippet.strip().splitlines()
        if len(snippet_lines) >= 5:
            return snippet

        # 1-indexed -> 0-indexed 변환
        target_idx = max(0, start_line - 1)
        begin_idx = max(0, target_idx - context_lines)
        end_idx = min(total_lines, target_idx + len(snippet_lines) + context_lines)

        expanded = "\n".join(lines[begin_idx:end_idx])
        return expanded if expanded.strip() else snippet
    except Exception as e:
        logger.warning(f"맥락 확장 실패 ({file_path}): {e}")
        return snippet


def generate_fix(
    *,
    rule_id: str,
    title: str,
    message: str,
    cwe: list[str],
    file_path: str,
    start_line: int,
    snippet: str,
    repo_root: Path | None = None,
) -> FixResult:
    """취약점 하나에 대한 수정 코드를 만든다.

    1. Redis 캐시 확인 (동일한 rule_id + snippet 조합은 캐시 재사용)
    2. 스니펫이 짧으면 파일에서 전후 맥락 확장
    3. Claude API 호출 및 결과 반환
    """
    # 1. Redis 캐시 확인
    cache_key = _cache_key(rule_id, snippet)
    try:
        redis_client = get_redis()
        cached = redis_client.get(cache_key)
        if cached:
            logger.info(f"AI 수정 캐시 적중: {cache_key}")
            return FixResult.model_validate_json(cached)
    except Exception as e:
        logger.warning(f"Redis 캐시 조회 건너뜀: {e}")
        redis_client = None

    # 2. 맥락 확장
    rich_snippet = _expand_context(file_path, start_line, snippet, repo_root=repo_root)

    # 3. 프롬프트 생성 및 Claude API 호출
    prompt = build_fix_prompt(
        rule_id=rule_id,
        title=title,
        message=message,
        cwe=cwe,
        file_path=file_path,
        start_line=start_line,
        language=EXTENSION_LANGUAGE.get(Path(file_path).suffix.lower()),
        snippet=rich_snippet,
    )
    result = ask_json(get_settings().llm_fix_model, FIX_SYSTEM, prompt, FixResult)

    # 4. Redis 캐시 저장
    if redis_client:
        try:
            redis_client.set(cache_key, result.model_dump_json(), ex=CACHE_TTL_SEC)
        except Exception as e:
            logger.warning(f"Redis 캐시 저장 실패: {e}")

    return result
