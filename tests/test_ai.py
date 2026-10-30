"""[백엔드 D] AI 수정 코드 생성 및 검증 단위 테스트."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from app.services.ai.fixer import FixResult, _cache_key, _expand_context, generate_fix
from app.services.ai.verifier import VerificationResult, _syntax_ok, verify_fix
from app.services.git.github import FileChange


def test_expand_context(tmp_path: Path):
    """스니펫이 짧을 때 파일에서 전후 문맥을 정상적으로 확장하는지 테스트."""
    test_file = tmp_path / "sample.py"
    test_file.write_text(
        "\n".join([f"line_{i} = {i}" for i in range(1, 30)]),
        encoding="utf-8",
    )

    # 1~2줄짜리 짧은 스니펫
    short_snippet = "line_15 = 15"
    expanded = _expand_context(
        str(test_file),
        start_line=15,
        snippet=short_snippet,
        context_lines=5,
    )

    # 확장된 내용에 이전/이후 라인이 포함되어야 함
    assert "line_10" in expanded
    assert "line_15" in expanded
    assert "line_20" in expanded


def test_syntax_ok_python(tmp_path: Path):
    """Python AST 문법 검사 성공/실패 테스트."""
    valid_file = tmp_path / "valid.py"
    valid_file.write_text("def hello():\n    return 'world'\n", encoding="utf-8")
    ok, note = _syntax_ok(valid_file)
    assert ok is True
    assert note == ""

    invalid_file = tmp_path / "invalid.py"
    invalid_file.write_text("def broken_syntax(:\n", encoding="utf-8")
    ok, note = _syntax_ok(invalid_file)
    assert ok is False
    assert "문법 오류" in note


def test_generate_fix_with_mock_llm():
    """Claude API를 모킹하여 수정 코드가 정상 반환되는지 테스트."""
    mock_result = FixResult(
        original_code="eval(user_input)",
        fixed_code="ast.literal_eval(user_input)",
        explanation="안전하지 않은 eval 대신 ast.literal_eval을 사용하도록 수정했습니다.",
    )

    with patch("app.services.ai.fixer.ask_json", return_value=mock_result), patch(
        "app.services.ai.fixer.get_redis", return_value=None
    ):
        result = generate_fix(
            rule_id="python.lang.security.audit.eval-detected",
            title="Use of eval",
            message="eval is insecure",
            cwe=["CWE-95"],
            file_path="src/main.py",
            start_line=10,
            snippet="eval(user_input)",
        )

        assert result.original_code == "eval(user_input)"
        assert result.fixed_code == "ast.literal_eval(user_input)"
        assert "ast.literal_eval" in result.explanation


def test_generate_fix_redis_cache_hit():
    """Redis 캐시가 존재할 때 LLM을 호출하지 않고 캐시를 반환하는지 테스트."""
    mock_cached_result = FixResult(
        original_code="const q = query",
        fixed_code="const q = sanitize(query)",
        explanation="캐시된 수정 설명입니다.",
    )

    mock_redis = MagicMock()
    mock_redis.get.return_value = mock_cached_result.model_dump_json()

    with patch("app.services.ai.fixer.get_redis", return_value=mock_redis), patch(
        "app.services.ai.fixer.ask_json"
    ) as mock_ask:
        result = generate_fix(
            rule_id="js.sql-injection",
            title="SQL Injection",
            message="Avoid raw query",
            cwe=["CWE-89"],
            file_path="src/db.js",
            start_line=5,
            snippet="const q = query",
        )

        # Redis에서 꺼내왔으므로 ask_json이 실행되지 않아야 함
        mock_ask.assert_not_called()
        assert result.fixed_code == "const q = sanitize(query)"
        assert result.explanation == "캐시된 수정 설명입니다."


def test_verify_fix_syntax_failure(tmp_path: Path):
    """문법 오류가 있는 패치는 검증 실패(verified=False) 처리되는지 테스트."""
    target_file = tmp_path / "app.py"
    target_file.write_text("def test():\n    pass\n", encoding="utf-8")

    # 깨진 문법으로 치환 시도
    change = FileChange(
        file_path="app.py",
        original_code="    pass",
        fixed_code="    pass broken_syntax (",
    )

    res = verify_fix(tmp_path, change, rule_id="test.rule")
    assert res.verified is False
    assert "문법 오류" in res.note



def test_verify_fix_ignores_same_rule_elsewhere_in_file(tmp_path: Path):
    """같은 파일의 다른 위치에 남은 동일 취약점 때문에 올바른 수정이 탈락하면 안 된다."""
    import json as _json

    target = tmp_path / "db.py"
    target.write_text("a = 1\nbad_call(x)\nb = 2\nc = 3\nbad_call(y)\n", encoding="utf-8")
    change = FileChange(file_path="db.py", original_code="bad_call(x)", fixed_code="good_call(x)")

    def fake_run(cmd, **kwargs):
        # 수정 후 5번째 줄(다른 위치)에만 같은 룰이 남아 있음
        out = {"results": [{"check_id": "p.rule", "start": {"line": 5}, "end": {"line": 5}}]}
        return MagicMock(stdout=_json.dumps(out), returncode=0)

    with patch("app.services.ai.verifier.shutil.which", return_value="/bin/semgrep"), patch(
        "app.services.ai.verifier.subprocess.run", side_effect=fake_run
    ):
        assert verify_fix(tmp_path, change, rule_id="p.rule").verified

    target.write_text("a = 1\nbad_call(x)\n", encoding="utf-8")

    def fake_run_same_line(cmd, **kwargs):
        out = {"results": [{"check_id": "p.rule", "start": {"line": 2}, "end": {"line": 2}}]}
        return MagicMock(stdout=_json.dumps(out), returncode=0)

    with patch("app.services.ai.verifier.shutil.which", return_value="/bin/semgrep"), patch(
        "app.services.ai.verifier.subprocess.run", side_effect=fake_run_same_line
    ):
        assert not verify_fix(tmp_path, change, rule_id="p.rule").verified
