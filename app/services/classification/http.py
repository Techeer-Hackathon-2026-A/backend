"""리포트 경로의 검증 오류에서 요청 입력을 제거한다."""

from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute


class SafeReportRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def safe_handler(request):
            try:
                return await handler(request)
            except RequestValidationError:
                return JSONResponse(status_code=422, content={"detail": "조회 조건이 올바르지 않습니다"})
            except HTTPException:
                raise
            except Exception:
                return JSONResponse(status_code=500, content={"detail": "결과를 조회할 수 없습니다"})

        return safe_handler
