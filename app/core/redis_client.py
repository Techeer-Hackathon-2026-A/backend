"""Redis 헬퍼: 스캔 진행률처럼 사라져도 되는 임시 정보만 저장한다.

분석 결과는 절대 여기에 두지 않고 PostgreSQL에 저장한다.
"""

import json
import logging
from functools import lru_cache

import redis

from app.core.config import get_settings

PROGRESS_TTL_SEC = 60 * 60 * 24

logger = logging.getLogger(__name__)


@lru_cache
def get_redis() -> redis.Redis:
    return redis.Redis.from_url(get_settings().redis_url, decode_responses=True)


def _progress_key(scan_id: int) -> str:
    return f"scan:{scan_id}:progress"


def set_progress(scan_id: int, step: str, percent: int, message: str = "") -> None:
    """진행률은 부가 정보라 Redis 장애로 스캔 자체가 실패하지 않게 한다."""
    payload = {"step": step, "percent": percent, "message": message}
    try:
        get_redis().set(_progress_key(scan_id), json.dumps(payload, ensure_ascii=False), ex=PROGRESS_TTL_SEC)
    except redis.RedisError:
        logger.warning("progress write skipped for scan %s (redis unavailable)", scan_id)


def get_progress(scan_id: int) -> dict | None:
    try:
        raw = get_redis().get(_progress_key(scan_id))
    except redis.RedisError:
        return None
    return json.loads(raw) if raw else None
