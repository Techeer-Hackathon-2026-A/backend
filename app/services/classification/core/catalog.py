"""공식 MITRE 사전 스냅샷에서 Weakness 식별자를 검증한다."""

import json
from pathlib import Path


def load_catalog():
    data = json.loads((Path(__file__).parent / "data/cwe.json").read_text(encoding="utf-8"))
    if not data.get("weaknesses") or not data.get("version"):
        raise RuntimeError("CWE 사전이 불완전합니다")
    return data
