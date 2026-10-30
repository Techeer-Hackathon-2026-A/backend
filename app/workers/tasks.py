"""Celery 작업 정의.

원칙: 작업에는 ID만 주고받고, 데이터는 전부 DB에서 읽고 쓴다.

| 작업            | 실행 시점             | 담당       |
|----------------|----------------------|-----------|
| scan_repo      | 스캔 요청             | A (흐름), B·C (내부 단계) |
| generate_fix   | 수정안 요청            | D         |
| create_pr      | PR 생성 요청           | A         |
"""

import logging
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.core.redis_client import set_progress
from app.models import Finding, Fix, PullRequest, Scan
from app.models.enums import FindingStatus, ScanStatus
from app.schemas.finding import ClassifiedFinding
from app.services.classification.pipeline import classify
from app.services.classification.risk import calculate_grade, summarize
from app.services.detection.normalizer import run_all_detectors
from app.services.git.repo import cloned_repo
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


def _update_scan(db, scan: Scan, status: ScanStatus, percent: int, message: str = "") -> None:
    scan.status = status
    db.commit()
    set_progress(scan.id, status.value, percent, message)


def _to_entity(scan_id: int, f: ClassifiedFinding) -> Finding:
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
        raw=f.raw,
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

            # 2. 탐지 (B)
            _update_scan(db, scan, ScanStatus.DETECTING, 30, "Semgrep · OSV-Scanner · Gitleaks 실행 중")
            normalized, tool_errors = run_all_detectors(repo.path, repo.path.parent / "results")

        # 3. 분류·평가 (C) — 코드가 필요 없으므로 임시 폴더 삭제 후 진행
        _update_scan(db, scan, ScanStatus.CLASSIFYING, 70, "중복 통합 · OWASP 분류 · 위험도 산정 중")
        classified = classify(normalized)
        db.add_all(_to_entity(scan.id, f) for f in classified)

        scan.grade = None if tool_errors else calculate_grade(classified)
        scan.summary = {
            **summarize(classified),
            "tool_errors": {name: "도구 실행 실패" for name in tool_errors},
            "complete": not bool(tool_errors),
        }
        scan.finished_at = datetime.now(UTC)
        final_status = ScanStatus.FAILED if len(tool_errors) >= 3 else ScanStatus.COMPLETED
        _update_scan(db, scan, final_status, 100, "일부 도구 실패" if tool_errors else "완료")
        return scan_id
    except Exception:
        logger.error("scan %s failed", scan_id)
        db.rollback()
        scan.error_message = "분석 처리 실패"
        scan.finished_at = datetime.now(UTC)
        _update_scan(db, scan, ScanStatus.FAILED, 100, "실패")
        raise
    finally:
        db.close()


@celery_app.task(name="generate_fix")
def generate_fix_task(finding_id: int) -> int | None:
    """[D] 취약점 하나에 대한 수정 코드 생성 → 검증 → DB 저장."""
    from app.services.ai.fixer import generate_fix
    from app.services.ai.verifier import verify_fix
    from app.services.git.github import FileChange

    db = SessionLocal()
    try:
        finding = db.get(Finding, finding_id)
        if finding is None or not finding.snippet:
            return None
        result = generate_fix(
            rule_id=finding.rule_id,
            title=finding.title,
            message=finding.message,
            cwe=finding.cwe,
            file_path=finding.file_path,
            start_line=finding.start_line,
            snippet=finding.snippet,
        )
        change = FileChange(finding.file_path, result.original_code, result.fixed_code)
        scan = finding.scan
        with cloned_repo(scan.project.repo_url, commit_sha=scan.commit_sha) as repo:
            verification = verify_fix(repo.path, change, finding.rule_id)

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
    finally:
        db.close()


@celery_app.task(name="create_pr")
def create_pr_task(pull_request_id: int) -> int:
    """[A] 선택한 수정안들을 브랜치에 커밋하고 PR을 생성한다."""
    from app.services.git.github import FileChange, apply_changes, commit_and_push, create_pull_request
    from app.services.git.repo import parse_repo_url

    db = SessionLocal()
    pr = db.get(PullRequest, pull_request_id)
    try:
        scan = pr.scan
        fixes = db.query(Fix).filter(Fix.id.in_(pr.fix_ids)).all()
        owner, name = parse_repo_url(scan.project.repo_url)
        base = scan.branch or scan.project.default_branch or "main"

        with cloned_repo(scan.project.repo_url, branch=scan.branch, commit_sha=scan.commit_sha) as repo:
            apply_changes(repo.path, [FileChange(f.file_path, f.original_code, f.fixed_code) for f in fixes])
            commit_and_push(Path(repo.path), pr.branch_name, f"fix(security): {len(fixes)}건 취약점 자동 수정")

        body = "\n".join(
            f"- **{f.finding.title}** (`{f.file_path}:{f.finding.start_line}`) — {f.explanation}" for f in fixes
        )
        created = create_pull_request(owner, name, pr.branch_name, base, f"[Security] 취약점 {len(fixes)}건 수정", body)
        pr.pr_number, pr.pr_url, pr.status = created.number, created.url, "created"
        for f in fixes:
            f.finding.status = FindingStatus.FIXED
        db.commit()
        return pr.id
    except Exception as e:
        db.rollback()
        pr.status, pr.error_message = "failed", str(e)[:2000]
        db.commit()
        raise
    finally:
        db.close()
