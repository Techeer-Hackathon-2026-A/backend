"""[백엔드 A] 사용자에게 보여줘도 안전한 에러와 시크릿 가리기.

외부 명령(git)의 에러 메시지에는 토큰이 섞인 URL이 들어갈 수 있으므로,
DB·로그·API 응답에 남기기 전에 반드시 redact()를 거친다.
"""

import re

from app.core.config import get_settings

# https://user:token@host, x-access-token:..., ghp_/gho_/github_pat_ 형태의 토큰
_URL_CREDENTIALS = re.compile(r"(https?://)[^/\s@]+@")
_GITHUB_TOKENS = re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")


def redact(text: str) -> str:
    """문자열에서 자격 증명을 가린다."""
    if not text:
        return text
    token = get_settings().github_token
    if token:
        text = text.replace(token, "****")
    text = _URL_CREDENTIALS.sub(r"\1****@", text)
    return _GITHUB_TOKENS.sub("****", text)


class UserFacingError(Exception):
    """사용자에게 그대로 보여줘도 되는 에러. message에는 시크릿이 없어야 한다."""

    code = "error"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class RepoNotFoundError(UserFacingError):
    code = "repo_not_found"


class RepoTooLargeError(UserFacingError):
    code = "repo_too_large"


class CloneTimeoutError(UserFacingError):
    code = "clone_timeout"


class GitOperationError(UserFacingError):
    code = "git_error"


class GitHubApiError(UserFacingError):
    code = "github_api_error"


def safe_message(exc: BaseException, default: str) -> str:
    """DB에 저장할 에러 메시지. 예상한 에러면 그 메시지를, 아니면 기본 문구를 반환한다."""
    if isinstance(exc, UserFacingError):
        return redact(exc.message)[:500]
    return default
