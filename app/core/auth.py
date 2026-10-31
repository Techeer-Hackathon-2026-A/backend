"""API 인증 · 레포 권한 확인.

- 서비스 키: BACKEND_API_KEY 를 설정하면 모든 /api/v1 요청에 `Authorization: Bearer <키>`가 있어야 한다.
  프론트 서버만 백엔드를 부르게 하려는 것이다.
- 사용자: 프론트 서버가 로그인한 사용자의 GitHub 토큰을 `X-GitHub-Token` 으로 넘긴다. 없으면 익명.
- 클론·푸시는 서버 토큰(GITHUB_TOKEN)이 하지만, 볼 수 있는지·고칠 수 있는지는 요청한 사람이
  GitHub 에서 가진 권한으로만 정한다. 익명은 공개 레포만 볼 수 있고 수정·PR 은 할 수 없다.

GitHub 응답은 프로세스 메모리에만 잠깐 캐시한다 (Redis 에 두면 Redis 를 쓸 수 있는 누구나 권한을 위조할 수 있다).
"""

import hashlib
import hmac
import time
from dataclasses import dataclass

import httpx
from fastapi import Header, HTTPException, status

from app.core.config import get_settings

GITHUB_API = "https://api.github.com"
CACHE_TTL_SEC = 120
_CACHE_MAX = 10_000

_cache: dict[str, tuple[float, object]] = {}


@dataclass(frozen=True)
class Viewer:
    id: int
    login: str
    token: str


@dataclass(frozen=True)
class RepoAccess:
    private: bool
    push: bool


def verify_service_key(authorization: str | None = Header(None)) -> None:
    """라우터 전체에 거는 의존성. 키를 설정하지 않았으면(로컬 개발) 검사하지 않는다."""
    key = get_settings().backend_api_key
    if not key:
        return
    if not authorization or not hmac.compare_digest(authorization.encode(), f"Bearer {key}".encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "인증이 필요합니다")


def _cached(key: str, load):
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    value = load()
    if len(_cache) >= _CACHE_MAX:
        _cache.clear()
    _cache[key] = (now + CACHE_TTL_SEC, value)
    return value


def _token_key(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _github_get(path: str, token: str) -> dict | None:
    """성공하면 JSON, 토큰이 무효이거나 볼 수 없으면 None. GitHub 장애·한도 초과는 503."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = httpx.get(f"{GITHUB_API}{path}", headers=headers, timeout=10)
    except httpx.HTTPError as e:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "GitHub 에 연결할 수 없습니다") from e
    if resp.status_code == 429 or (resp.status_code == 403 and resp.headers.get("x-ratelimit-remaining") == "0"):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "GitHub 요청 한도를 넘었습니다. 잠시 뒤 시도하세요")
    if resp.status_code in (401, 403, 404):
        return None
    if not resp.is_success:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "GitHub 에 연결할 수 없습니다")
    return resp.json()


def get_viewer(x_github_token: str | None = Header(None)) -> Viewer | None:
    """FastAPI 의존성: 요청한 GitHub 사용자. 토큰이 없으면 익명(None), 무효면 401."""
    if not x_github_token:
        return None

    def load():
        user = _github_get("/user", x_github_token)
        return {"id": user["id"], "login": user["login"]} if user else None

    user = _cached(f"user:{_token_key(x_github_token)}", load)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "GitHub 로그인이 만료되었습니다. 다시 로그인하세요")
    return Viewer(id=user["id"], login=user["login"], token=x_github_token)


def repo_access(viewer: Viewer | None, owner: str, name: str) -> RepoAccess | None:
    """viewer 가 GitHub 에서 이 레포를 볼 수 있으면 권한, 아니면 None. 익명은 공개 레포만 본다."""
    if owner in (".", "..") or name in (".", ".."):
        return None
    token = viewer.token if viewer else ""

    def load():
        # 익명 조회도 서버 토큰으로 해서 GitHub 요청 한도를 아낀다. 비공개 여부만 쓰고 서버 토큰의 권한은 쓰지 않는다
        repo = _github_get(f"/repos/{owner}/{name}", token or get_settings().github_token)
        if repo is None:
            return None
        return {"private": bool(repo.get("private", True)), "push": bool((repo.get("permissions") or {}).get("push"))}

    data = _cached(f"repo:{_token_key(token) if token else 'anon'}:{owner}/{name}".lower(), load)
    if data is None or (viewer is None and data["private"]):
        return None
    return RepoAccess(private=data["private"], push=viewer is not None and data["push"])


def require_read(viewer: Viewer | None, project, not_found: str, *, login: bool = False) -> RepoAccess:
    """볼 수 없는 레포의 기록은 있는지조차 알리지 않도록 404로 답한다. login 이면 익명은 401."""
    if login and viewer is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "GitHub 로 로그인해야 합니다")
    access = repo_access(viewer, project.owner, project.name)
    if access is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, not_found)
    return access


def require_push(viewer: Viewer | None, project, not_found: str) -> RepoAccess:
    """PR 은 서버 토큰으로 올라가므로, 요청한 사람이 그 레포에 푸시할 수 있을 때만 허용한다."""
    access = require_read(viewer, project, not_found, login=True)
    if not access.push:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "이 레포에 푸시 권한이 있어야 PR 을 만들 수 있습니다")
    return access
