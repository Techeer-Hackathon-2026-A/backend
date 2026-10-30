# A·B·D·프론트엔드 연동 초안

## 실행 및 책임

C는 순수 서비스다. A의 기존 앱·인증·분석 소유권 검사를 거쳐 호출한다. 별도 DB·앱·Celery 작업은 만들지 않았다. 분석 ID는 반드시 하나의 저장소·커밋에 대응해야 한다. 서로 다른 커밋의 결과를 한 번에 전달하면 안 된다.

B는 Finding 입력을 전달한다. 원본은 B 또는 A가 접근 통제해 보관하고 C의 Group.sources는 내부 추적용으로만 사용한다. 서비스는 원본 데이터를 로그로 남기지 않는다. Pydantic 오류를 HTTP 응답에 그대로 반환하지 말고, 입력을 제외한 고정 오류 코드로 변환해야 한다.

## 공개 조회 계약 후보

- GET /analyses/{analysis_id}/report: build_report 결과에서 vulnerabilities를 제외한 요약.
- GET /analyses/{analysis_id}/vulnerabilities: vulnerabilities에 페이지·필터 적용.
- GET /analyses/{analysis_id}/vulnerabilities/{id}: get_detail 결과. KeyError는 A에서 404로 변환.

실제 HTTP 라우터와 저장소 구현은 아직 없다. 분석 상태와 DB 영속성은 A가 연결한다. 실패·부분 성공·미실행 도구는 complete=false로 표시한다. mock-analysis 같은 데모 식별자를 사용하고 실제 분석 성공으로 표시하지 않는다.

## 공개 정보 제한

현재 공개 모델은 원본 제목·설명·경로·규칙·탐지 ID·원본 참조를 내보내지 않는다. 임의 문자열에 포함된 시크릿을 확실히 판별할 수 없기 때문이다. 공개 제목은 고정 문구다. 도구, 취약점 종류, 집계, 확인된 CWE 및 위험도 등 제한된 정보만 공개한다. 저장소·분석 식별자와 커밋은 A가 발급한 안전한 값이어야 한다.

파일 위치와 구체적 설명을 공개하려면 B의 비식별화 계약과 출력용 안전 메타데이터 모델을 추가해야 한다. D 전달 역시 아직 연결하지 않았다. 시크릿 원문을 D에 전달하지 않는다.

현재 연동 진입점은 boundary.process_batch이며 입력·출력 계약 및 오류 처리의 최신 명세는 CONTRACT.md를 따른다. 아래 초기 설명 중 CWE 목록 제한과 v2 정책은 이전 기록이며 v3에서 전체 MITRE Weakness 사전 검증과 공개 모델을 도입했다.

## 분류와 위험도

data/owasp2025.json은 OWASP/Top10 공식 저장소의 커밋으로 고정한 매핑이다. 출처 URL·revision·CC-BY-3.0 정보를 포함한다. 자료의 CWE 목록을 추출하여 사용했으며 설명 본문은 재배포하지 않는다. CWE는 data/cwe.json의 전체 MITRE Weakness 스냅샷으로 검증한다. 미확인 ID는 추측 배정하지 않으며, OWASP에 없는 유효한 CWE도 보존한다. 폐기된 ID는 별도 표시한다.

CVSS는 입력 점수를 사용하며 벡터에서 재계산하지 않는다. 3.x/4.0은 0=info, 0초과~3.9=low, 4~6.9=medium, 7~8.9=high, 9~10=critical이다. 2.0은 low/medium/high 체계를 사용한다. 근거: https://www.first.org/cvss/v3.1/specification-document 및 https://www.first.org/cvss/v2/guide

도구 심각도는 명시된 등급과 error→high, warning→medium, informational→info만 변환한다. 이는 C의 초기 정책이며 B와 변환 의미를 확인해야 한다. 통합 결과는 각 원본에 CVSS 우선 정책을 적용한 후 최고 등급을 선택한다. unknown은 마지막에 정렬한다. 같은 등급에서는 안정적 ID 순으로 정렬하며 서로 다른 CVSS 버전의 점수를 크기로 비교하지 않는다. 정책 버전은 2025-mock-v2이다.

추가 점검에서 열 위치가 없으면 코드 탐지를 통합하지 않도록 보완했다. B는 행·열 위치의 단위와 끝 위치 포함 규칙을 정규화해야 한다. 미실행(not_run) 도구의 탐지 결과가 들어오면 입력 오류로 거부한다. partial/failed 상태에 남아 있는 탐지 결과는 유지하되 complete=false로 제공한다.

## 추가 합의 필요

도구 간 코드 규칙 동등성, CVE 별칭 검증 자료, 시크릿 HMAC 생성·키 관리, CWE 사전 갱신 주기, 공개용 위치·설명 정제, DB 스키마, 실제 라우터·페이지 계약, D 전달 모델을 팀과 확인해야 한다.
