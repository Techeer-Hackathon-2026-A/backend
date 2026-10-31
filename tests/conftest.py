import json
import os
from pathlib import Path

import pytest

# 테스트는 PostgreSQL·Redis 없이 SQLite로 돌린다
os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")

MOCKS = Path(__file__).parent.parent / "mocks"

# 가짜 GitHub 사용자: 토큰 → (id, login, 푸시 가능 여부)
USERS = {"owner-token": (1, "owner", True), "reader-token": (2, "reader", False)}
OWNER = {"X-GitHub-Token": "owner-token"}
READER = {"X-GitHub-Token": "reader-token"}


@pytest.fixture(autouse=True)
def fake_github(monkeypatch):
    """GitHub 대신 답한다. 레포는 기본적으로 공개, private 에 넣은 'owner/name' 은 owner-token 만 볼 수 있다."""
    from types import SimpleNamespace

    from app.core import auth

    state = SimpleNamespace(private=set())

    def github_get(path, token):
        user = USERS.get(token)
        if path == "/user":
            return {"id": user[0], "login": user[1]} if user else None
        repo = path.removeprefix("/repos/").lower()
        if repo in state.private and token != "owner-token":
            return None
        return {"private": repo in state.private, "permissions": {"push": bool(user and user[2])}}

    auth._cache.clear()
    monkeypatch.setattr(auth, "_github_get", github_get)
    yield state
    auth._cache.clear()


@pytest.fixture
def mock_findings():
    from app.schemas.finding import NormalizedFinding

    data = json.loads((MOCKS / "normalized_findings.json").read_text(encoding="utf-8"))
    return [NormalizedFinding.model_validate(d) for d in data]


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c
    from app.core.database import engine

    engine.dispose()
    Path("test.db").unlink(missing_ok=True)
