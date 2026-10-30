# Backend — AI 코드 보안 분석 플랫폼

GitHub 레포를 연결하면 코드 취약점(SAST)·라이브러리 취약점(SCA)·시크릿 유출을 탐지하고,
OWASP Top 10 / CWE 기준으로 분류·평가한 뒤, AI가 수정 코드를 만들어 PR까지 생성하는 서비스의 백엔드입니다.

## 기술 스택

| 영역 | 스택 |
|---|---|
| 서버 | Python 3.12 · FastAPI · Pydantic v2 · SQLAlchemy 2.0 |
| 작업 큐 | Celery + Redis |
| DB | PostgreSQL 16 |
| SAST | Semgrep (`p/owasp-top-ten`, `p/cwe-top-25`) |
| SCA | OSV-Scanner |
| 시크릿 | Gitleaks |
| LLM | Claude API (`claude-sonnet-5-5` 수정 코드, `claude-haiku-5-5` 대량 판정) |

## 아키텍처

```
[Frontend] ──HTTP──▶ [FastAPI] ──작업 메시지──▶ [Redis] ──▶ [Celery Worker]
                         │                                      │
                         │◀──────── 진행률 (Redis) ──────────────┤
                         │                                      ├─ 1. 클론 (임시 폴더)          A
                         ▼                                      ├─ 2. Semgrep·OSV·Gitleaks    B
                   [PostgreSQL] ◀────── 분석 결과 저장 ──────────┤─ 3. 분류·평가               C
                                                                ├─ 4. AI 수정·검증 (요청 시)   D
                                                                └─ 5. 브랜치·커밋·PR (요청 시) A
```

- **Redis**: 작업 메시지, 작업 상태, 진행률처럼 사라져도 되는 임시 정보만
- **PostgreSQL**: 프로젝트·스캔·취약점·수정안·PR 등 실제 결과 전부
- **코드는 저장하지 않음**: 스캔 동안만 임시 폴더에 클론하고 끝나면 삭제, DB에는 취약점 주변 코드 몇 줄만 저장 (시크릿은 마스킹)
- **Celery 작업에는 ID만** 주고받고, 데이터는 전부 DB에서 읽고 쓴다

## 빠른 시작

### Docker (권장)

```bash
cp .env.example .env          # GITHUB_TOKEN, ANTHROPIC_API_KEY 입력
docker compose up --build
```

- API 문서(Swagger): http://localhost:8000/docs
- 헬스 체크: http://localhost:8000/health

### 로컬 개발 (분석 도구 없이 API·분류 로직만 개발할 때)

```bash
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
docker compose up -d db redis # DB·Redis만 컨테이너로
uvicorn app.main:app --reload
celery -A app.workers.celery_app worker --loglevel=info --pool=solo   # 다른 터미널 (Windows는 --pool=solo 필수)
```

### 테스트 · 린트

```bash
pytest                        # PostgreSQL·Redis 없이 SQLite로 실행됨
ruff check . && ruff format .
```

## 폴더 구조

```
app/
├── main.py                      # FastAPI 진입점
├── core/
│   ├── config.py                # 환경 변수 (.env)
│   ├── database.py              # SQLAlchemy 엔진·세션
│   └── redis_client.py          # 진행률 저장
├── api/v1/endpoints/
│   ├── scans.py                 # A  스캔 요청 · 진행 상태
│   ├── reports.py               # C  리포트 · 취약점 목록/상세
│   ├── fixes.py                 # D  AI 수정 요청 · 조회
│   └── pull_requests.py         # A  PR 생성 · 목록
├── models/entities.py           # DB 테이블
├── schemas/
│   ├── finding.py               # ★ 공통 결과 스키마 (팀 전체 합의 대상)
│   └── api.py                   # API 요청·응답 (프론트 합의 대상)
├── services/
│   ├── git/          # A  repo.py (클론·언어 감지) · github.py (브랜치·커밋·PR)
│   ├── detection/    # B  base.py (어댑터) · semgrep.py · osv.py · gitleaks.py · normalizer.py
│   ├── classification/ # C  dedup.py · mapping.py (CWE/OWASP) · risk.py · pipeline.py
│   └── ai/           # D  client.py · prompts.py · fixer.py · verifier.py
└── workers/
    ├── celery_app.py
    └── tasks.py                 # scan_repo · generate_fix · create_pr
mocks/normalized_findings.json   # 탐지 결과 목 데이터 (C·D 선개발용)
tests/
```

## 데이터 흐름 (공통 스키마)

```
도구 원본 JSON ──B──▶ NormalizedFinding ──C──▶ ClassifiedFinding ──▶ DB findings
                                                                       │
                                                       D ──▶ Fix ──A──▶ PullRequest
```

`app/schemas/finding.py`가 팀 간 계약입니다. 필드를 바꿀 때는 반드시 팀 전체에 공유하세요.

## API

| Method | Path | 설명 | 담당 |
|---|---|---|---|
| POST | `/api/v1/scans` | 레포 링크로 스캔 요청 | A |
| GET | `/api/v1/scans` | 스캔 목록 | A |
| GET | `/api/v1/scans/{scan_id}` | 스캔 상태·요약 | A |
| GET | `/api/v1/scans/{scan_id}/progress` | 실시간 진행률 (폴링) | A |
| GET | `/api/v1/scans/{scan_id}/report` | 보안 분석 리포트 (등급, OWASP 매트릭스) | C |
| GET | `/api/v1/scans/{scan_id}/findings` | 취약점 목록 (`severity`, `category`, `owasp` 필터) | C |
| GET | `/api/v1/findings/{finding_id}` | 취약점 상세 | C |
| POST | `/api/v1/findings/{finding_id}/fixes` | AI 수정 코드 생성 요청 | D |
| GET | `/api/v1/findings/{finding_id}/fixes` | 수정안 조회 | D |
| POST | `/api/v1/scans/{scan_id}/pull-requests` | 선택한 수정안으로 PR 생성 | A |
| GET | `/api/v1/scans/{scan_id}/pull-requests` | PR 목록 | A |

스캔 상태: `pending → cloning → detecting → classifying → completed` (실패 시 `failed`)

## 역할 분담

| 담당 | 이름 | 범위 | 주요 파일 |
|---|---|---|---|
| 백엔드 A (기반·Git) | 박소연 | 서버 뼈대, 클론, 진행률, 브랜치·커밋·PR | `core/`, `services/git/`, `endpoints/scans.py`, `endpoints/pull_requests.py`, `workers/` |
| 백엔드 B (탐지) | 민지원 | Semgrep·OSV-Scanner·Gitleaks 연동, 결과 정규화 | `services/detection/` |
| 백엔드 C (분류·평가) | 김장군 | 중복 통합, CWE 매핑, OWASP 분류, 위험도·등급, 리포트 API | `services/classification/`, `endpoints/reports.py` |
| 백엔드 D (AI) | 이광해 | AI 수정 코드 생성, 수정 검증 | `services/ai/`, `endpoints/fixes.py` |

### 기능 목록 (P1)

| 기능 | 주 기능 | 담당 | 선행 작업 |
|---|---|---|---|
| 레포 링크 입력 | 1. 레포 연동·분석 준비 | A | API 명세 |
| 레포 전체 클론 및 분석 대상 수집 | 1. 레포 연동·분석 준비 | A | 서버 뼈대 |
| OWASP 룰셋 코드 탐지 | 2. 룰 기반 탐지 | B | 공통 스키마 |
| 시크릿 유출 탐지 | 2. 룰 기반 탐지 | B | 공통 스키마 |
| 의존성 취약점 탐지 | 2. 룰 기반 탐지 | B | 공통 스키마 |
| 탐지 결과 정규화 | 2. 룰 기반 탐지 | B | 탐지 3종 |
| 분석 진행 상태 실시간 표시 | 2. 룰 기반 탐지 | A | 서버 뼈대 |
| 중복 탐지 통합 | 3. 분류·평가 | C | 공통 스키마 (목 데이터로 선개발) |
| CWE 매핑 | 3. 분류·평가 | C | 공통 스키마 |
| OWASP Top 10 분류 | 3. 분류·평가 | C | CWE 매핑 |
| 위험도 산정·우선순위 정렬 | 3. 분류·평가 | C | 중복 통합, OWASP 분류 |
| 보안 분석 리포트 | 3. 분류·평가 | C | 위험도 산정 |
| 취약점 상세 조회 | 4. 자동 수정·PR | C | 리포트 API, AI 수정 |
| AI 수정 코드 생성 | 4. 자동 수정·PR | D | 정규화 (목 데이터로 선개발) |
| 수정 코드 검증 | 4. 자동 수정·PR | D | AI 수정 코드 생성 |
| 수정 브랜치 생성·커밋 | 4. 자동 수정·PR | A | 클론, AI 수정 |
| 수정 PR 자동 생성 | 4. 자동 수정·PR | A | 브랜치·커밋 |
| PR 목록 조회 | 4. 자동 수정·PR | A | PR 생성 |

### 담당별 시작 포인트

- **A**: `docker compose up`으로 전체가 뜨는지 먼저 확인 → `services/git/repo.py` 클론 테스트 → `create_pr_task` 흐름 연결
- **B**: 도구 3종의 실제 JSON 출력을 뽑아 `parse()`가 맞는지 확인 (OSV-Scanner는 v1/v2 출력 형식이 다름) → 원본 샘플을 `tests/`에 저장해 테스트 보강 → 바이브 코딩 특화 커스텀 룰 추가
- **C**: `mocks/normalized_findings.json`으로 바로 개발 가능. `pytest tests/test_classification.py` → `mapping.py` 매핑표 보강, `risk.py` 가중치 튜닝
- **D**: 목 데이터의 `snippet`으로 `services/ai/fixer.py` 프롬프트부터 다듬기 → `verifier.py` 재스캔 검증 → (여유 시) Haiku로 오탐 판정 추가

## 협업 규칙

- **브랜치**: `main` 보호 → `feat/<담당>-<기능>` (예: `feat/b-semgrep`, `fix/c-dedup`) → PR 후 머지
- **커밋**: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:` + 한 줄 설명
- **공통 스키마(`schemas/`) 변경**은 PR 설명에 명시하고 팀에 공유
- **`.env`·API 키·토큰은 절대 커밋 금지** (보안 해커톤에서 키 유출은 치명적입니다)
- LLM 호출 시 `temperature`, `top_p`, `top_k` 파라미터를 넣지 말 것 (최신 모델은 400 에러)

## 보안 원칙

- 분석 대상 코드는 **실행하지 않고 읽기만** 한다 (정적 분석)
- 클론한 코드는 스캔 종료 시 **무조건 삭제** (`tempfile.TemporaryDirectory`)
- 시크릿 탐지 결과의 실제 키 값은 **마스킹 후 저장**, 원본 값은 저장하지 않음
- LLM 프롬프트에서 분석 대상 코드는 `<code>` 태그로 격리하고 **내부 지시는 무시**하도록 명시 (프롬프트 인젝션 방어)
- PR은 **사용자가 수정안을 선택해 승인했을 때만** 생성
