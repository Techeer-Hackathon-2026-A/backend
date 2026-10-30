"""[백엔드 A] 수정 브랜치 생성·커밋·푸시 및 PR 생성."""

import subprocess
from dataclasses import dataclass
from pathlib import Path

import httpx

from app.core.config import get_settings

GITHUB_API = "https://api.github.com"


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
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout


def apply_changes(repo: Path, changes: list[FileChange]) -> None:
    """수정 코드를 파일에 반영한다. 원본 코드 조각을 찾아 바꾸는 방식."""
    for change in changes:
        target = repo / change.file_path
        content = target.read_text(encoding="utf-8")
        if change.original_code not in content:
            raise ValueError(f"원본 코드를 찾을 수 없습니다: {change.file_path}")
        target.write_text(content.replace(change.original_code, change.fixed_code, 1), encoding="utf-8")


def commit_and_push(repo: Path, branch_name: str, message: str) -> None:
    _git(repo, "checkout", "-b", branch_name)
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c",
        "user.name=security-bot",
        "-c",
        "user.email=security-bot@users.noreply.github.com",
        "commit",
        "-m",
        message,
    )
    _git(repo, "push", "origin", branch_name)


def create_pull_request(owner: str, name: str, head: str, base: str, title: str, body: str) -> CreatedPR:
    token = get_settings().github_token
    resp = httpx.post(
        f"{GITHUB_API}/repos/{owner}/{name}/pulls",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        json={"title": title, "head": head, "base": base, "body": body},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return CreatedPR(number=data["number"], url=data["html_url"])


def get_default_branch(owner: str, name: str) -> str:
    token = get_settings().github_token
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = httpx.get(f"{GITHUB_API}/repos/{owner}/{name}", headers=headers, timeout=15)
    resp.raise_for_status()
    return resp.json()["default_branch"]
