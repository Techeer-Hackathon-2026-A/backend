"""Celery 작업 정의.

원칙: 작업에는 ID만 주고받고, 데이터는 전부 DB에서 읽고 쓴다.
코드는 DB에 저장하지 않는다. 수정·검증·PR이 코드를 필요로 하면 스캔한 커밋을 다시 클론해서 읽는다.

| 작업            | 실행 시점             | 담당       |
|----------------|----------------------|-----------|
| scan_repo      | 스캔 요청             | A (흐름), B·C (내부 단계) |
| generate_fix   | 수정안 요청            | D (흐름 연결: A) |
| create_pr      | PR 생성 요청           | A         |
"""

import hashlib
import logging
import re
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.core.redis_client import set_progress
from app.models import Finding, Fix, PullRequest, Scan
from app.models.enums import FindingStatus, ScanStatus
from app.schemas.finding import ClassifiedFinding, NormalizedFinding
from app.services.classification.pipeline import classify
from app.services.classification.risk import calculate_grade, summarize
from app.services.detection.normalizer import run_all_detectors
from app.services.git.errors import safe_message
from app.services.git.repo import cloned_repo
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

# 도구가 정한 룰 ID만 내부 추적용으로 보관한다 (사용자 코드 문자열은 저장하지 않음)
_RULE_ID = re.compile(r"^[A-Za-z0-9_.:/-]{1,300}$")


def _update_scan(db, scan: Scan, status: ScanStatus, percent: int, message: str = "") -> None:
    scan.status = status
    db.commit()
    set_progress(scan.id, status.value, percent, message)


def _source_id(finding: NormalizedFinding) -> str:
    # C의 pipeline이 raw["sources"][].source_id 에 쓰는 것과 같은 방식
    return hashlib.sha256(finding.model_dump_json().encode()).hexdigest()


def _internal_meta(f: ClassifiedFinding, originals: dict[str, NormalizedFinding]) -> dict:
    """수정 검증에 필요한 원본 룰 ID를 공개되지 않는 raw.internal 에 남긴다."""
    rule_ids = []
    for source in (f.raw or {}).get("sources", []):
        original = originals.get(source.get("source_id"))
        if original and _RULE_ID.match(original.rule_id) and original.rule_id not in rule_ids:
            rule_ids.append(original.rule_id)
    return {"rule_ids": rule_ids}


def _to_entity(scan_id: int, f: ClassifiedFinding, originals: dict[str, NormalizedFinding] | None = None) -> Finding:
    raw = dict(f.raw or {})
    if originals is not None:
        raw["internal"] = _internal_meta(f, originals)
    return Finding(
        scan_id=scan_id,
        tool=f.tool,
        category=f.category.value,
        rule_id=f.rule_id,
        title=f.title,
        message=f.message,
        severity=f.severity.value,
        file_path=f.location.file_path,
        start_line=f.location.start_line,
        end_line=f.location.end_line,
        snippet=f.location.snippet,
        cwe=f.cwe,
        owasp=f.owasp,
        dependency=f.dependency.model_dump() if f.dependency else None,
        fingerprint=f.fingerprint,
        raw=raw,
        owasp_top10=f.owasp_top10,
        risk_score=f.risk_score,
        priority=f.priority,
        duplicate_count=f.duplicate_count,
        merged_tools=f.merged_tools,
    )


@celery_app.task(name="scan_repo")
def scan_repo(scan_id: int) -> int:
    db = SessionLocal()
    scan = db.get(Scan, scan_id)
    try:
        # 1. 클론 (A)
        _update_scan(db, scan, ScanStatus.CLONING, 10, "레포 클론 중")
        with cloned_repo(scan.project.repo_url, scan.branch) as repo:
            scan.commit_sha = repo.commit_sha
            scan.languages = repo.languages
            checked_out = getattr(repo, "branch", None)
            if scan.branch is None and checked_out:
                scan.project.default_branch = checked_out

            # 2. 탐지 (B)
            _update_scan(db, scan, ScanStatus.DETECTING, 30, "Semgrep · OSV-Scanner · Gitleaks 실행 중")
            normalized, tool_errors = run_all_detectors(repo.path, repo.path.parent / "results")

        # 3. 분류·평가 (C) — 코드가 필요 없으므로 임시 폴더 삭제 후 진행
        _update_scan(db, scan, ScanStatus.CLASSIFYING, 70, "중복 통합 · OWASP 분류 · 위험도 산정 중")
        classified = classify(normalized)
        originals = {_source_id(f): f for f in normalized}
        db.add_all(_to_entity(scan.id, f, originals) for f in classified)

        scan.grade = None if tool_errors else calculate_grade(classified)
        scan.summary = {
            **summarize(classified),
            "tool_errors": {name: "도구 실행 실패" for name in tool_errors},
            "complete": not bool(tool_errors),
        }
        scan.finished_at = datetime.now(UTC)
        final_status = ScanStatus.FAILED if len(tool_errors) >= 3 else ScanStatus.COMPLETED
        if final_status == ScanStatus.FAILED:
            scan.error_message = "탐지 도구가 모두 실패했습니다."
        _update_scan(db, scan, final_status, 100, "일부 도구 실패" if tool_errors else "완료")
        return scan_id
    except Exception as e:
        logger.error("scan %s failed: %s", scan_id, type(e).__name__)
        db.rollback()
        scan.error_message = safe_message(e, "분석 처리 실패")
        scan.finished_at = datetime.now(UTC)
        _update_scan(db, scan, ScanStatus.FAILED, 100, "실패")
        raise
    finally:
        db.close()


def _pick_rule_id(finding: Finding) -> str:
    """재스캔 검증에 쓸 룰 ID. Semgrep 룰(점으로 구분된 ID)을 우선한다."""
    rule_ids = ((finding.raw or {}).get("internal") or {}).get("rule_ids") or []
    semgrep_rules = [r for r in rule_ids if "." in r]
    return (semgrep_rules or rule_ids or [finding.rule_id])[0]


@celery_app.task(name="generate_fix")
def generate_fix_task(finding_id: int) -> int | None:
    """[D] 취약점 하나에 대한 수정 코드 생성 → 검증 → DB 저장.

    DB에는 코드가 없으므로(C 정책) 스캔한 커밋을 다시 클론해서 해당 위치의 코드를 읽는다.
    """
    from app.services.ai.fixer import generate_fix
    from app.services.ai.verifier import verify_fix
    from app.services.git.github import FileChange
    from app.services.git.repo import read_lines

    db = SessionLocal()
    try:
        finding = db.get(Finding, finding_id)
        if finding is None:
            return None
        if finding.category == "secret":
            # 시크릿은 코드 수정이 아니라 키 폐기·교체가 필요하므로 자동 수정하지 않는다
            logger.info("finding %s: secret은 자동 수정 대상이 아님", finding_id)
            return None
        scan = finding.scan
        if not scan.commit_sha:
            return None

        rule_id = _pick_rule_id(finding)
        with cloned_repo(scan.project.repo_url, commit_sha=scan.commit_sha) as repo:
            snippet = read_lines(repo.path, finding.file_path, finding.start_line, finding.end_line)
            if not snippet:
                logger.info("finding %s: 코드 위치를 읽을 수 없음", finding_id)
                return None
            result = generate_fix(
                rule_id=rule_id,
                title=finding.title,
                message=f"{finding.tool}가 탐지한 취약점 ({', '.join(finding.cwe) or 'CWE 미상'})",
                cwe=finding.cwe,
                file_path=finding.file_path,
                start_line=finding.start_line,
                snippet=snippet,
                repo_root=repo.path,
            )
            change = FileChange(finding.file_path, result.original_code, result.fixed_code)
            verification = verify_fix(repo.path, change, rule_id)

        fix = Fix(
            finding_id=finding.id,
            file_path=finding.file_path,
            original_code=result.original_code,
            fixed_code=result.fixed_code,
            explanation=result.explanation,
            verified=verification.verified,
            verification_note=verification.note,
            model=get_settings().llm_fix_model,
        )
        db.add(fix)
        db.commit()
        return fix.id
    except Exception as e:
        logger.error("generate_fix %s failed: %s", finding_id, type(e).__name__)
        raise
    finally:
        db.close()


def _pr_body(scan: Scan, fixes: list[Fix]) -> str:
    rows = []
    for f in fixes:
        cwe = ", ".join(f.finding.cwe) or "-"
        check = "✅ 재스캔 통과" if f.verified else "⚠️ 미검증"
        rows.append(f"| `{f.file_path}:{f.finding.start_line}` | {cwe} | {f.finding.severity} | {check} |")
    details = "\n\n".join(f"### `{f.file_path}`\n{f.explanation}" for f in fixes)
    return (
        "보안 분석 결과를 바탕으로 자동 생성된 수정 PR입니다.\n\n"
        f"- 분석 커밋: `{scan.commit_sha[:7]}`\n"
        f"- 수정 건수: {len(fixes)}\n\n"
        "| 위치 | CWE | 심각도 | 검증 |\n|---|---|---|---|\n" + "\n".join(rows) + "\n\n"
        "## 수정 내용\n\n" + details + "\n\n"
        "> 자동 생성된 수정이므로 머지 전에 반드시 리뷰와 테스트를 진행해 주세요."
    )


@celery_app.task(name="create_pr")
def create_pr_task(pull_request_id: int) -> int:
    """[A] 선택한 수정안들을 스캔한 커밋 위에 브랜치로 커밋하고 PR을 생성한다."""
    from app.services.git.github import (
        FileChange,
        apply_changes,
        commit_and_push,
        create_pull_request,
        get_default_branch,
    )
    from app.services.git.repo import parse_repo_url

    db = SessionLocal()
    pr = db.get(PullRequest, pull_request_id)
    try:
        scan = pr.scan
        by_id = {f.id: f for f in db.query(Fix).filter(Fix.id.in_(pr.fix_ids)).all()}
        fixes = [by_id[i] for i in pr.fix_ids if i in by_id]
        owner, name = parse_repo_url(scan.project.repo_url)
        base = scan.branch or scan.project.default_branch or get_default_branch(owner, name)

        with cloned_repo(scan.project.repo_url, branch=base, commit_sha=scan.commit_sha) as repo:
            apply_changes(repo.path, [FileChange(f.file_path, f.original_code, f.fixed_code) for f in fixes])
            commit_and_push(Path(repo.path), pr.branch_name, f"fix(security): 취약점 {len(fixes)}건 자동 수정")

        created = create_pull_request(
            owner, name, pr.branch_name, base, f"[Security] 취약점 {len(fixes)}건 수정", _pr_body(scan, fixes)
        )
        pr.pr_number, pr.pr_url, pr.status = created.number, created.url, "created"
        for f in fixes:
            f.finding.status = FindingStatus.FIXED
        db.commit()
        return pr.id
    except Exception as e:
        logger.error("create_pr %s failed: %s", pull_request_id, type(e).__name__)
        db.rollback()
        pr.status = "failed"
        pr.error_message = safe_message(e, "PR 생성 중 오류가 발생했습니다.")
        if isinstance(e, ValueError):  # apply_changes: 원본 코드를 찾지 못함 등
            pr.error_message = str(e)[:500]
        db.commit()
        raise
    finally:
        db.close()
