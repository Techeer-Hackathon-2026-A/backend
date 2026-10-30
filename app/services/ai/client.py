"""[백엔드 D] Claude API 클라이언트 래퍼.

주의: 최신 모델은 temperature / top_p / top_k를 넣으면 400 에러가 난다. 넣지 말 것.
"""

import json
import re
from functools import lru_cache
from typing import TypeVar

from anthropic import Anthropic
from pydantic import BaseModel, ValidationError

from app.core.config import get_settings

T = TypeVar("T", bound=BaseModel)


@lru_cache
def get_client() -> Anthropic:
    return Anthropic(api_key=get_settings().anthropic_api_key or None)


def _extract_json(text: str) -> str:
    """```json ... ``` 코드 블록이 섞여 와도 JSON 부분만 뽑는다."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    return match.group(0) if match else text


def ask_json(model: str, system: str, prompt: str, schema: type[T], max_tokens: int = 4000, retries: int = 1) -> T:
    """프롬프트를 보내고 결과를 Pydantic 모델로 검증해 돌려준다. 파싱 실패 시 재시도."""
    last_error: Exception | None = None
    for _ in range(retries + 1):
        resp = get_client().messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(block.text for block in resp.content if block.type == "text")
        try:
            return schema.model_validate_json(_extract_json(text))
        except (ValidationError, json.JSONDecodeError) as e:
            last_error = e
    raise ValueError(f"LLM 응답 파싱 실패: {last_error}")
