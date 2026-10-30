"""[백엔드 A] 레포 클론 및 분석 대상 수집.

코드는 스캔 동안만 임시 폴더에 존재하고, with 블록이 끝나면 자동 삭제된다.
"""

import os
import subprocess
import tempfile
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from app.core.config import get_settings

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


class RepoTooLargeError(Exception):
    pass


@dataclass
class ClonedRepo:
    path: Path
    commit_sha: str
    branch: str | None
    languages: list[str] = field(default_factory=list)


def parse_repo_url(repo_url: str) -> tuple[str, str]:
    """https://github.com/owner/name(.git) -> (owner, name)"""
    parts = urlparse(repo_url).path.strip("/").removesuffix(".git").split("/")
    if len(parts) < 2:
        raise ValueError(f"올바른 GitHub 레포 주소가 아닙니다: {repo_url}")
    return parts[0], parts[1]


def _authed_url(repo_url: str) -> str:
    """비공개 레포용 토큰 주입. 이 URL은 절대 로그나 DB에 남기지 않는다."""
    token = get_settings().github_token
    if not token or not repo_url.startswith("https://"):
        return repo_url
    return repo_url.replace("https://", f"https://x-access-token:{token}@", 1)


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


@contextmanager
def cloned_repo(repo_url: str, branch: str | None = None, commit_sha: str | None = None) -> Iterator[ClonedRepo]:
    """레포를 임시 폴더에 클론하고, 블록이 끝나면(에러가 나도) 삭제한다.

    commit_sha를 주면 해당 커밋으로 체크아웃한다 (수정 검증, PR 생성 시 재클론용).
    """
    settings = get_settings()
    os.makedirs(settings.scan_workdir, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="scan_", dir=settings.scan_workdir) as workdir:
        repo_dir = Path(workdir) / "repo"
        cmd = ["git", "clone", "--no-tags"]
        if not commit_sha:
            cmd += ["--depth", "1"]
        if branch:
            cmd += ["--branch", branch]
        cmd += [_authed_url(repo_url), str(repo_dir)]
        subprocess.run(cmd, check=True, capture_output=True, timeout=settings.clone_timeout_sec)

        if commit_sha:
            subprocess.run(["git", "-C", str(repo_dir), "checkout", commit_sha], check=True, capture_output=True)

        if _dir_size_mb(repo_dir) > settings.max_repo_size_mb:
            raise RepoTooLargeError(f"레포 크기가 {settings.max_repo_size_mb}MB를 초과합니다.")

        sha = subprocess.check_output(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True).strip()
        yield ClonedRepo(path=repo_dir, commit_sha=sha, branch=branch, languages=detect_languages(repo_dir))
