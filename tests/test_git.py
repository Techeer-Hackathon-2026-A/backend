"""[백엔드 A] 클론·시크릿 가리기·브랜치/커밋/푸시 테스트. 네트워크 없이 로컬 git 저장소로 검증한다."""

import subprocess
from pathlib import Path

import pytest

from app.services.git.errors import GitOperationError, RepoNotFoundError, redact, safe_message
from app.services.git.github import FileChange, apply_changes, commit_and_push
from app.services.git.repo import cloned_repo, normalize_repo_url, read_lines, validate_branch


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def origin(tmp_path):
    """main 브랜치에 커밋 2개가 있는 원격 역할의 bare 저장소."""
    work = tmp_path / "work"
    work.mkdir()
    git(work, "init", "-q", "-b", "main")
    git(work, "config", "user.email", "t@example.com")
    git(work, "config", "user.name", "t")
    (work / "app.py").write_text("import os\n\ndef run(cmd):\n    os.system(cmd)\n", encoding="utf-8")
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", "first")
    first = git(work, "rev-parse", "HEAD")
    (work / "README.md").write_text("hello\n", encoding="utf-8")
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", "second")
    bare = tmp_path / "origin.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(work), str(bare)], check=True)
    git(bare, "config", "uploadpack.allowAnySHA1InWant", "true")
    return {"url": f"file://{bare}", "bare": bare, "first": first, "head": git(work, "rev-parse", "HEAD")}


@pytest.fixture(autouse=True)
def _workdir(tmp_path, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "scan_workdir", str(tmp_path / "scans"))


# ---------- 시크릿 가리기 ----------
def test_redact_url_credentials_and_tokens(monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "github_token", "my-configured-token")
    text = (
        "fatal: https://x-access-token:abc123@github.com/o/r.git not found; "
        "token ghp_abcdefghijklmnopqrstuvwxyz0123456789 my-configured-token"
    )
    out = redact(text)
    assert "abc123" not in out and "ghp_" not in out and "my-configured-token" not in out
    assert "https://****@github.com" in out


def test_safe_message_hides_unexpected_errors():
    assert safe_message(RuntimeError("secret detail"), "분석 처리 실패") == "분석 처리 실패"
    assert safe_message(RepoNotFoundError("레포를 찾을 수 없습니다"), "x") == "레포를 찾을 수 없습니다"


# ---------- 입력 검증 ----------
@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/owner/repo", "https://github.com/owner/repo"),
        ("https://github.com/owner/repo.git", "https://github.com/owner/repo"),
        ("https://github.com/owner/repo/", "https://github.com/owner/repo"),
    ],
)
def test_normalize_repo_url(url, expected):
    assert normalize_repo_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://gitlab.com/o/r",
        "http://github.com/o/r",
        "https://github.com/o",
        "https://github.com/o/r/tree/main",
        "https://user:pw@github.com/o/r",
        "file:///etc/passwd",
    ],
)
def test_normalize_repo_url_rejects(url):
    with pytest.raises(ValueError):
        normalize_repo_url(url)


@pytest.mark.parametrize("branch", ["-u", "a..b", "main;rm -rf /", "x" * 300])
def test_validate_branch_rejects(branch):
    with pytest.raises(ValueError):
        validate_branch(branch)


def test_validate_branch_accepts():
    assert validate_branch("feature/login-fix") == "feature/login-fix"
    assert validate_branch("") is None


# ---------- 클론 ----------
def test_clone_default_branch(origin, tmp_path):
    with cloned_repo(origin["url"]) as repo:
        path = repo.path
        assert repo.commit_sha == origin["head"]
        assert repo.branch == "main"
        assert repo.languages == ["python"]
        assert (path / "app.py").exists()
    assert not path.exists(), "클론한 코드는 블록이 끝나면 삭제되어야 한다"


def test_clone_specific_commit(origin):
    with cloned_repo(origin["url"], branch="main", commit_sha=origin["first"]) as repo:
        assert repo.commit_sha == origin["first"]
        assert not (repo.path / "README.md").exists()
        assert repo.branch == "main"


def test_clone_deleted_even_on_error(origin, tmp_path):
    with pytest.raises(RuntimeError), cloned_repo(origin["url"]) as repo:
        path = repo.path
        raise RuntimeError("boom")
    assert not path.exists()


def test_clone_missing_repo_raises_safe_error(tmp_path):
    with pytest.raises((RepoNotFoundError, GitOperationError)), cloned_repo(f"file://{tmp_path}/nope.git"):
        pass


def test_clone_rejects_bad_sha(origin):
    with pytest.raises(GitOperationError), cloned_repo(origin["url"], commit_sha="--upload-pack=evil"):
        pass


def test_read_lines_blocks_path_traversal(origin):
    with cloned_repo(origin["url"]) as repo:
        assert "os.system" in read_lines(repo.path, "app.py", 4)
        assert read_lines(repo.path, "../../../etc/passwd", 1) is None


# ---------- 수정 적용·커밋·푸시 ----------
def test_apply_changes_and_push_branch(origin):
    with cloned_repo(origin["url"], branch="main", commit_sha=origin["head"]) as repo:
        apply_changes(
            repo.path,
            [FileChange("app.py", "    os.system(cmd)", "    subprocess.run(cmd.split(), check=True)")],
        )
        commit_and_push(repo.path, "security-fix/scan-1-1", "fix(security): test")
    log = git(origin["bare"], "log", "--format=%an|%s", "security-fix/scan-1-1", "-1")
    assert log == "security-bot|fix(security): test"
    content = git(origin["bare"], "show", "security-fix/scan-1-1:app.py")
    assert "subprocess.run" in content and "os.system" not in content


def test_apply_changes_rejects_traversal_and_missing_code(origin):
    with cloned_repo(origin["url"]) as repo:
        with pytest.raises(ValueError):
            apply_changes(repo.path, [FileChange("../outside.py", "a", "b")])
        with pytest.raises(ValueError):
            apply_changes(repo.path, [FileChange("app.py", "not in file", "b")])


def test_commit_without_changes_fails(origin):
    with cloned_repo(origin["url"]) as repo, pytest.raises(GitOperationError):
        commit_and_push(repo.path, "security-fix/empty", "nothing")


def test_clone_empty_repo_gives_clear_message(tmp_path):
    bare = tmp_path / "empty.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    with pytest.raises(RepoNotFoundError, match="비어 있습니다"), cloned_repo(f"file://{bare}"):
        pass
