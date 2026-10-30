from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "scanner",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="Asia/Seoul",
    task_track_started=True,
    task_time_limit=15 * 60,  # 하드 타임아웃
    task_soft_time_limit=12 * 60,
    worker_prefetch_multiplier=1,  # 무거운 작업이라 하나씩 가져간다
    result_expires=60 * 60 * 24,
)
