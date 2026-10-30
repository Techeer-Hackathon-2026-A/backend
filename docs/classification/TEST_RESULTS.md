# 테스트 실행 결과

최신 저장소 통합 검증: **93 passed, 1 warning in 5.72s**, Python 3.12.10/Pydantic 2.11.4/pytest 8.3.5. SQLite·FastAPI 실제 라우터·worker 함수 연결을 검증했으며 Redis/Git/스캐너는 목으로 대체했다. 변경 코드 Ruff 검사 통과. 아래 내용은 독립 개발 단계의 이전 기록이다.

- 실행 환경: Windows, Python 3.12.10, pytest 8.4.2, Pydantic 2.14.2
- 최초 결과: 30 passed in 2.15s
- 추가 점검 후 결과: **51 passed in 0.51s**
- 실제 실행한 대상: test_dedup.py, test_service.py, test_review.py
- 추가 범위: 같은 행의 다른 열 위치, 열 정보 누락, 상이한 취약점 ID, 잘못된 경로·열 범위·manifest, 상태 객체 변경 격리, 상세 응답 복사, 미실행 도구와 결과의 모순, 부분 성공 결과 보존, 분석별 ID 분리
- 범위: 중복 통합·원본 보존, 오통합 방지, 입력 오류, CWE 확인/미확인, OWASP 다중 분류, CVSS 경계값, 위험도 정렬, 빈 결과·실패 상태, 리포트·상세 조회, 공개 출력·로그의 목 시크릿 미노출
- HTTP API 테스트는 아니다. 실제 스캐너·GitHub·DB·Claude 연동 테스트는 실행하지 않았다.

최적화 후에도 전체 테스트를 재실행해 **51 passed in 0.46s**를 확인했다. 목 데이터 5,000건의 리포트는 최적화 전후 전체 객체가 같음을 검증했다. 측정 범위와 결과는 OPTIMIZATION.md에 기록했다.

## 계약 보완 후 최종 결과

**70 passed in 0.58s**. test_boundary.py의 19개 사례를 추가했다. OWASP 밖의 유효 CWE, 폐기 CWE, 분석 메타데이터·상태 모순, 중복 ID, 잘못된 입력 구조, 알 수 없는 공개 필드, 내부 처리 오류, 성공·오류 출력과 로그의 민감정보 미노출을 검증했다. demo.py도 새 공개 경계를 통해 실행해 mock-report.json을 재생성했다.

## 이 작업 환경에서 다시 실행

작업 루트 PowerShell에서:

    ./work/runtime/python.exe -c "import sys; sys.path.insert(0, 'outputs/backend_c'); import pytest; raise SystemExit(pytest.main(['outputs/backend_c', '-q', '--basetemp=work/pytest']))"

일반 Python 환경에서는 backend_c 디렉터리에서 requirements-lock.txt를 설치한 후 python -m pytest -q로 실행한다. requirements-lock.txt는 이번에 실제 설치한 의존성 버전이다.
