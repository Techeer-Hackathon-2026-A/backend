# 입력·출력 계약 1.0

외부 연결 시 A는 기존 순수 함수 대신 boundary.process_batch(payload)를 인증·인가 후 호출한다. 반환값은 (상태 코드, JSON 본문)이며 실제 HTTP 서버는 만들지 않는다. 내부 build_report/get_detail 반환값을 API에 직접 반환하지 않는다. 상세 객체가 필요하면 PublicVulnerability 모델로 검증 후 직렬화한다.

## 분석 묶음

- schema_version: 현재 "1.0"만 허용.
- analysis_id/repository_id: 1~128자의 영숫자·점·밑줄·하이픈 식별자. 첫 글자는 영숫자. A가 발급한 안전한 값만 전달하며 토큰·URL을 사용하지 않는다.
- commit_sha: 40자리 또는 64자리 16진수. 저장소의 실제 커밋인지 확인하는 책임은 A에 있다.
- data_origin: mock 또는 scanner. 목 데이터는 반드시 mock으로 전달한다. scanner 표시는 실제 스캐너 실행 증명이 아니므로 A/B가 출처를 보장해야 한다.
- tool_statuses: semgrep/osv/gitleaks 세 도구를 모두 명시. success/failed/partial/not_run 중 하나.
- findings: Finding 목록. 빈 목록 허용. 탐지 ID는 묶음 내 고유. not_run 도구 결과는 거부.

묶음의 모든 탐지는 하나의 저장소·커밋에 속해야 한다. 실제 코드 저장소와의 일치는 C 단독으로 검증할 수 없다.

입력 및 출력 JSON Schema를 analysis-batch.schema.json, public-report.schema.json으로 제공한다. 실제 팀 연동 전에 B·A와 확인한다.

## 전체 CWE 검증

MITRE 공식 전체 XML의 Weakness 항목만 추출했다. Category/View ID는 개별 약점으로 인정하지 않는다. data/cwe.json은 사전 버전·배포일·다운로드 ZIP SHA-256·출처·이용 조건 링크와 ID별 상태를 보관한다. MITRE CWE의 식별자와 상태에서 추출한 자료이며 저작권은 MITRE에 있다.

- 활성 Weakness ID: cwe_ids로 보존하며 OWASP에 없어도 제거하지 않는다.
- Deprecated ID: deprecated_cwe_ids로 별도 보존하며 다른 CWE로 추측 변환하지 않는다.
- 미확인 ID: unresolved_cwe_count로 집계하고 원본은 내부 Group.sources로 추적한다.
- OWASP 분류: 활성 CWE 중 공식 2025 매핑에 연결된 범주만 반환한다.

따라서 CWE 확인 성공과 OWASP 미분류는 동시에 발생할 수 있다. 사전은 실행 중 외부 조회하지 않는 버전 고정 스냅샷이며 미래에 추가된 ID는 갱신 전까지 미확인이다.

## 공개 응답과 오류

PublicReport와 중첩 모델은 선언하지 않은 필드를 거부한다. 원본·설명·코드·경로는 공개 모델에 없다. 허용되지 않은 내부 필드가 섞이면 전체 응답을 실패 처리한다. 알려진 ID·분류·등급을 제한하며 임의 원문을 공개하지 않는다. 안전한 형식의 ID라도 시크릿을 넣어도 된다는 의미는 아니다.

- 입력 검증 실패: 422, INVALID_INPUT, 고정 한국어 메시지.
- 분류·출력 처리 실패: 500, INTERNAL_ERROR, 고정 한국어 메시지.
- 오류 위치(loc), 메시지(msg), 문맥(ctx), 입력값, 예외 문자열은 반환·로그하지 않는다.

이 경계 함수는 원문 로그를 남기지 않는다. A의 미들웨어·접근 로그·APM에서도 요청 본문과 예외 원문을 기록하지 않도록 연결해야 한다. 모델을 FastAPI 요청 인자로 바로 붙이면 기본 422 처리에 입력이 포함될 수 있으므로 A의 오류 처리도 같은 원칙을 적용해야 한다.

정책 버전은 2025-mock-v3이다. 기존 최적화 측정은 v2에서 측정한 기록이며, CWE 사전 및 출력 검증이 추가된 v3의 성능 측정값은 아니다.
