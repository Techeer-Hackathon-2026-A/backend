# C 실제 실행 흐름 연결

작업 브랜치: feat/backend-c. 커밋·push는 하지 않았다.

## 실행 경로

기존 scan_repo → classify(NormalizedFinding 목록) → _to_entity → 기존 findings 테이블 저장 → 기존 report/list/detail 라우터로 연결했다. 과거의 새 코어 미연결 설명은 더 이상 적용되지 않는다.

- app/services/classification/core/: 검증된 순수 서비스 및 공식 사전.
- pipeline.py: 기존 입력·출력 스키마와 코어를 연결하는 어댑터.
- safety.py / http.py: DB 저장·공개 응답·검증 오류 정제.
- repository.py: 기존 SQLAlchemy 테이블을 사용하는 Protocol 및 조회 어댑터.
- report.py: 기존 SecurityReport 응답 생성.
- handoff.py: D용 비식별 컨텍스트. 시크릿 자동 수정 불허.

## API 호환

기존 경로와 응답 필드 구성은 유지했다. 분류 값은 A05:2025처럼 2025 기준이다. owasp_top10은 정렬한 범주의 첫 항목이며 상세의 기존 owasp 목록에 모든 범주를 제공한다. 목록 필터도 모든 범주에 적용한다. limit(1~1000, 기본100), offset(기본0)을 추가했다.

새 DB 컬럼·테이블은 없다. 기존 raw JSON에 검증된 분류·위험도 근거와 비식별 출처를 저장한다. 공개 API에 raw를 내보내지 않는다. 기존 message 필드에 안전한 위험도 근거를 제공한다. 스캔 summary에는 OWASP 버전, CWE 분포, 원본 탐지 건수, 도구 실패 여부를 기록한다.

## 정책

OWASP 2025, MITRE Weakness 사전, 엄격한 행·열 중복 기준, CVSS 우선 평가를 적용한다. B가 열 위치를 주지 않으면 코드 탐지는 개별 유지한다. 비슷한 CWE나 같은 fingerprint라는 이유만으로 합치지 않는다. 시크릿은 HMAC 계약 전 개별 유지한다. 파일 위치만 다른 의존성도 개별 유지한다.

기존 risk_score 0~100 필드에는 CVSS가 있으면 점수×10, 없으면 critical90/high70/medium40/low10/info0/unknown0의 등급 표시값을 넣는다. 이는 새 위험 공식이 아니라 기존 API 숫자 필드의 호환 표현이다. 우선순위는 등급·안정적 ID 순이다. 경로 감점·도구 보너스·중복 가중치는 제거했다. 같은 등급이면 CVSS 근거가 있는 원본을 대표로 선택한다.

기존 스키마에 UNKNOWN 심각도와 선택적 CVSS 점수·버전, 열 위치 필드를 추가했다. 기존 B 입력은 그대로 유효하다. 미확인 위험만 있는 스캔 등급은 U이며 도구 실패가 있으면 등급을 부여하지 않는다. 모든 도구가 실패하면 FAILED로 끝난다. 일부 실패면 결과는 보존하고 summary.complete=false를 기록한다.

## 민감정보와 D

임의 제목·설명·규칙·코드·raw는 그대로 저장·공개하지 않는다. 시크릿 탐지는 파일 경로도 숨긴다. 비식별 출처와 콘텐츠 해시로 원본과 대조할 수 있지만 삭제한 원문을 복원할 수는 없다. 원본 보관·비밀키 관리는 A/B 책임이다.

스니펫은 항상 None으로 저장·응답한다. 따라서 D의 기존 스니펫 기반 자동 수정은 새 결과를 바로 수정할 수 없다. D는 build_fix_context의 requires_source_access 표시를 보고 권한 있는 저장소에서 코드 문맥을 별도로 확보·정제해야 한다. 시크릿 원문을 C가 D로 전달하지 않는다. Claude 호출·코드 조회는 구현하지 않았다.

## A 연결 조건과 검증 한계

현재 저장소에는 사용자 인증·저장소 권한 검사 구현이 없다. A가 get_report_repository 의존성을 사용자별 접근 제한 저장소로 교체하거나 상위 router에 인증·인가를 연결해야 한다. 의존성을 거부 정책으로 교체했을 때 C의 세 조회 경로가 403을 반환하는 테스트를 추가했다. C가 사용자 신원·권한을 추측하여 만들지 않았다. 운영 권한 검사가 완료된 것으로 간주하면 안 된다.

과거 2021 DB 행을 일괄 재분류하는 마이그레이션은 실행하지 않았다. 새 스캔부터 2025로 저장하며 기존 결과의 재분류는 재스캔으로 수행한다. 실제 PostgreSQL·Redis·스캐너·Claude·GitHub 변경 테스트는 별도다.

저장소 루트에서 python -m pytest -q로 실행한다.

최신 검증: 저장소 고정 의존성에서 93 passed, 1 warning in 5.72s. 변경 코드 Ruff 검사 통과. 자세한 범위는 TEST_RESULTS.md를 참고한다.
