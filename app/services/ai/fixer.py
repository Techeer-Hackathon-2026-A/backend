"""[백엔드 D] AI 수정 코드 생성."""

from pathlib import Path

from pydantic import BaseModel

from app.core.config import get_settings
from app.services.ai.client import ask_json
from app.services.ai.prompts import FIX_SYSTEM, build_fix_prompt
from app.services.git.repo import EXTENSION_LANGUAGE


class FixResult(BaseModel):
    original_code: str
    fixed_code: str
    explanation: str


def generate_fix(
    *, rule_id: str, title: str, message: str, cwe: list[str], file_path: str, start_line: int, snippet: str
) -> FixResult:
    """취약점 하나에 대한 수정 코드를 만든다.

    TODO(D): 스니펫이 짧아 맥락이 부족하면 함수 전체를 잘라서 보내기
    TODO(D): 같은 rule_id + snippet 조합은 Redis 캐시로 재사용
    """
    prompt = build_fix_prompt(
        rule_id=rule_id,
        title=title,
        message=message,
        cwe=cwe,
        file_path=file_path,
        start_line=start_line,
        language=EXTENSION_LANGUAGE.get(Path(file_path).suffix.lower()),
        snippet=snippet,
    )
    return ask_json(get_settings().llm_fix_model, FIX_SYSTEM, prompt, FixResult)
