import json
import os
from pathlib import Path

import pytest

# 테스트는 PostgreSQL·Redis 없이 SQLite로 돌린다
os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")

MOCKS = Path(__file__).parent.parent / "mocks"


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
