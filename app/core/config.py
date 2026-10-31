from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """환경 변수 설정. 값은 .env 파일에서 읽는다 (.env.example 참고)."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    app_name: str = "Code Security Scanner API"
    environment: str = "local"
    cors_origins: list[str] = ["http://localhost:5173"]
    # 설정하면 /api/v1 요청마다 Authorization: Bearer <키> 가 있어야 한다 (프론트 서버만 부르게)
    backend_api_key: str = ""

    # Infra
    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5432/scanner"
    redis_url: str = "redis://localhost:6379/0"

    # GitHub (백엔드 A)
    github_token: str = ""

    # Claude API (백엔드 D)
    anthropic_api_key: str = ""
    llm_triage_model: str = "claude-haiku-5-5"
    llm_fix_model: str = "claude-sonnet-5-5"
    llm_max_calls_per_scan: int = 30

    # Scan limits (백엔드 A, B)
    scan_workdir: str = "/tmp/scans"
    max_repo_size_mb: int = 500
    clone_timeout_sec: int = 120
    tool_timeout_sec: int = 300


@lru_cache
def get_settings() -> Settings:
    return Settings()
