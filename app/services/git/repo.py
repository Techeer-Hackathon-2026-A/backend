"""[백엔드 A] 레포 클론 및 분석 대상 수집.

코드는 스캔 동안만 임시 폴더에 존재하고, with 블록이 끝나면 자동 삭제된다.
git 에러 메시지는 토큰이 섞일 수 있으므로 errors.redact()를 거친 UserFacingError로만 밖에 내보낸다.
"""

import os
import re
import subprocess
import tempfile
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from app.core.config import get_settings
from app.services.git.errors import (
    CloneTimeoutError,
    GitOperationError,
    RepoNotFoundError,
    RepoTooLargeError,
    redact,
)

__all__ = [
    "EXCLUDED_DIRS",
    "EXTENSION_LANGUAGE",
    "ClonedRepo",
    "RepoTooLargeError",
    "cloned_repo",
    "detect_languages",
    "normalize_repo_url",
    "parse_repo_url",
    "read_lines",
]

# 분석할 필요 없는 폴더 (탐지 도구에도 같은 목록을 넘긴다)
EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".next",
    "out",
    "__pycache__",
    ".venv",
    "venv",
    "target",
    "coverage",
}

EXTENSION_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".swift": "swift",
    ".c": "c",
    ".cpp": "cpp",
}

_NAME = r"[A-Za-z0-9_.-]+"
_GITHUB_URL = re.compile(rf"^https://github\.com/({_NAME})/({_NAME}?)(?:\.git)?/?$")
_SHA = re.compile(r"^[0-9a-f]{7,40}$")
_BRANCH = re.compile(r"^(?!-)[A-Za-z0-9._/-]{1,200}$")


@dataclass
class ClonedRepo:
    path: Path
    commit_sha: str
    branch: str | None  # 실제로 체크아웃된 브랜치 (기본 브랜치로 클론했으면 그 이름)
    languages: list[str] = field(default_factory=list)


def normalize_repo_url(repo_url: str) -> str:
    """https://github.com/owner/repo 형태로 정규화한다. GitHub 공개 URL만 허용한다."""
    match = _GITHUB_URL.match(repo_url.strip())
    if not match or match[2] in ("", ".", ".."):
        raise ValueError("https://github.com/owner/repo 형식의 GitHub 레포 주소만 지원합니다.")
    return f"https://github.com/{match[1]}/{match[2].removesuffix('.git')}"


def parse_repo_url(repo_url: str) -> tuple[str, str]:
    """https://github.com/owner/name(.git) -> (owner, name)"""
    parts = urlparse(repo_url).path.strip("/").removesuffix(".git").split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError("올바른 GitHub 레포 주소가 아닙니다.")
    return parts[0], parts[1]


def validate_branch(branch: str | None) -> str | None:
    if branch is None or branch == "":
        return None
    if not _BRANCH.match(branch) or ".." in branch:
        raise ValueError("브랜치 이름이 올바르지 않습니다.")
    return branch


def _authed_url(repo_url: str) -> str:
    """비공개 레포용 토큰 주입. 이 URL은 절대 로그나 DB에 남기지 않는다."""
    token = get_settings().github_token
    if not token or not repo_url.startswith("https://"):
        return repo_url
    return repo_url.replace("https://", f"https://x-access-token:{token}@", 1)


def _git(*args: str, cwd: Path | None = None, timeout: int | None = None) -> str:
    """git 실행. 실패하면 시크릿을 가린 GitOperationError로 변환한다."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}  # 인증 실패 시 입력 대기 방지
    cmd = ["git", *(["-C", str(cwd)] if cwd else []), *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=True)
    except subprocess.TimeoutExpired as e:
        raise CloneTimeoutError("레포를 가져오는 데 시간이 너무 오래 걸립니다.") from e
    except subprocess.CalledProcessError as e:
        stderr = redact(e.stderr or "")
        if any(s in stderr for s in ("not found", "Repository not found", "Authentication failed", "could not read")):
            raise RepoNotFoundError("레포를 찾을 수 없거나 접근 권한이 없습니다.") from None
        if "Remote branch" in stderr or "couldn't find remote ref" in stderr:
            raise RepoNotFoundError("브랜치 또는 커밋을 찾을 수 없습니다.") from None
        raise GitOperationError(
            f"git {args[0]} 실패: {stderr.strip().splitlines()[-1] if stderr.strip() else ''}"
        ) from None
    return proc.stdout


def _dir_size_mb(path: Path) -> float:
    total = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d != ".git"]
        total += sum((Path(root) / f).stat().st_size for f in files if not (Path(root) / f).is_symlink())
    return total / (1024 * 1024)


def detect_languages(path: Path) -> list[str]:
    counter: Counter[str] = Counter()
    for _root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for f in files:
            lang = EXTENSION_LANGUAGE.get(Path(f).suffix.lower())
            if lang:
                counter[lang] += 1
    return [lang for lang, _ in counter.most_common()]


def read_lines(repo: Path, rel_path: str, start: int, end: int | None = None, context: int = 3) -> str | None:
    """클론된 레포에서 지정한 줄 주변 코드를 읽는다. 레포 밖 경로는 거부한다."""
    target = (repo / rel_path).resolve()
    if not target.is_file() or not target.is_relative_to(repo.resolve()):
        return None
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    begin = max(start - 1 - context, 0)
    finish = min((end or start) + context, len(lines))
    return "\n".join(lines[begin:finish]) or None


@contextmanager
def cloned_repo(repo_url: str, branch: str | None = None, commit_sha: str | None = None) -> Iterator[ClonedRepo]:
    """레포를 임시 폴더에 얕게 클론하고, 블록이 끝나면(에러가 나도) 삭제한다.

    - commit_sha가 있으면 그 커밋 하나만 받아 온다 (수정 검증·PR 생성 시 재클론용).
      branch도 같이 주면 PR 작업을 위해 그 브랜치 이름으로 체크아웃한다.
    - 없으면 branch(없으면 기본 브랜치)의 최신 커밋을 받아 온다.
    """
    settings = get_settings()
    os.makedirs(settings.scan_workdir, exist_ok=True)
    branch = validate_branch(branch)
    if commit_sha and not _SHA.match(commit_sha):
        raise GitOperationError("커밋 해시가 올바르지 않습니다.")

    with tempfile.TemporaryDirectory(prefix="scan_", dir=settings.scan_workdir) as workdir:
        repo_dir = Path(workdir) / "repo"
        timeout = settings.clone_timeout_sec

        if commit_sha:
            # 특정 커밋만 depth 1로 가져온다 (전체 히스토리 클론보다 훨씬 빠름)
            repo_dir.mkdir()
            _git("init", "-q", cwd=repo_dir)
            _git("remote", "add", "origin", _authed_url(repo_url), cwd=repo_dir)
            _git("fetch", "-q", "--depth", "1", "--no-tags", "origin", commit_sha, cwd=repo_dir, timeout=timeout)
            _git("checkout", "-q", "FETCH_HEAD", cwd=repo_dir)
            current_branch = branch
        else:
            cmd = ["clone", "-q", "--depth", "1", "--no-tags", "--single-branch"]
            if branch:
                cmd += ["--branch", branch]
            _git(*cmd, _authed_url(repo_url), str(repo_dir), timeout=timeout)
            current_branch = _git("rev-parse", "--abbrev-ref", "HEAD", cwd=repo_dir).strip()

        if _dir_size_mb(repo_dir) > settings.max_repo_size_mb:
            raise RepoTooLargeError(f"레포 크기가 {settings.max_repo_size_mb}MB를 초과합니다.")

        sha = _git("rev-parse", "HEAD", cwd=repo_dir).strip()
        yield ClonedRepo(
            path=repo_dir,
            commit_sha=sha,
            branch=current_branch if current_branch != "HEAD" else None,
            languages=detect_languages(repo_dir),
        )
