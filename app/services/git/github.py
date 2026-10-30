"""[백엔드 A] 수정 브랜치 생성·커밋·푸시 및 PR 생성."""

from dataclasses import dataclass
from pathlib import Path

import httpx

from app.core.config import get_settings
from app.services.git.errors import GitHubApiError, GitOperationError, redact
from app.services.git.repo import _git as _run_git

GITHUB_API = "https://api.github.com"
BOT_NAME = "security-bot"
BOT_EMAIL = "security-bot@users.noreply.github.com"


@dataclass
class FileChange:
    file_path: str  # 레포 루트 기준 상대 경로
    original_code: str
    fixed_code: str


@dataclass
class CreatedPR:
    number: int
    url: str


def _git(repo: Path, *args: str) -> str:
    return _run_git(*args, cwd=repo, timeout=get_settings().clone_timeout_sec)


def _safe_target(repo: Path, rel_path: str) -> Path:
    target = (repo / rel_path).resolve()
    if not target.is_relative_to(repo.resolve()) or not target.is_file():
        raise ValueError(f"수정할 파일을 찾을 수 없습니다: {rel_path}")
    return target


def apply_changes(repo: Path, changes: list[FileChange]) -> None:
    """수정 코드를 파일에 반영한다. 원본 코드 조각을 찾아 바꾸는 방식.

    같은 파일에 여러 수정이 있으면 순서대로 적용된다. 레포 밖 경로는 거부한다.
    """
    for change in changes:
        target = _safe_target(repo, change.file_path)
        content = target.read_text(encoding="utf-8")
        if not change.original_code or change.original_code not in content:
            raise ValueError(f"원본 코드를 찾을 수 없습니다: {change.file_path}")
        target.write_text(content.replace(change.original_code, change.fixed_code, 1), encoding="utf-8")


def commit_and_push(repo: Path, branch_name: str, message: str) -> None:
    _git(repo, "checkout", "-q", "-b", branch_name)
    _git(repo, "add", "-A")
    if not _git(repo, "status", "--porcelain").strip():
        raise GitOperationError("적용할 변경 사항이 없습니다.")
    _git(repo, "-c", f"user.name={BOT_NAME}", "-c", f"user.email={BOT_EMAIL}", "commit", "-q", "-m", message)
    _git(repo, "push", "-q", "origin", f"HEAD:refs/heads/{branch_name}")


def _headers(require_token: bool = True) -> dict[str, str]:
    token = get_settings().github_token
    if require_token and not token:
        raise GitHubApiError("GITHUB_TOKEN이 설정되지 않아 PR을 만들 수 없습니다.")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _raise_for_github(resp: httpx.Response, action: str) -> None:
    if resp.is_success:
        return
    try:
        detail = resp.json().get("message", "")
        errors = resp.json().get("errors") or []
        if errors and isinstance(errors[0], dict):
            detail = f"{detail} ({errors[0].get('message', '')})"
    except ValueError:
        detail = ""
    raise GitHubApiError(redact(f"GitHub {action} 실패 ({resp.status_code}) {detail}".strip()))


def create_pull_request(owner: str, name: str, head: str, base: str, title: str, body: str) -> CreatedPR:
    resp = httpx.post(
        f"{GITHUB_API}/repos/{owner}/{name}/pulls",
        headers=_headers(),
        json={"title": title, "head": head, "base": base, "body": body},
        timeout=30,
    )
    _raise_for_github(resp, "PR 생성")
    data = resp.json()
    return CreatedPR(number=data["number"], url=data["html_url"])


def get_default_branch(owner: str, name: str) -> str:
    resp = httpx.get(f"{GITHUB_API}/repos/{owner}/{name}", headers=_headers(require_token=False), timeout=15)
    _raise_for_github(resp, "레포 조회")
    return resp.json()["default_branch"]
