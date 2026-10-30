"""D에 공개 가능한 최소 컨텍스트. 코드·시크릿 원문을 전달하지 않는다."""

from pydantic import ValidationError

from app.schemas.api import FindingDetail
from app.services.classification.core.boundary import Classification, PublicRisk
from app.services.classification.safety import public_entity


def build_fix_context(entity):
    context = public_entity(entity, FindingDetail).model_dump(mode="json")
    context["requires_source_access"] = True
    context["automatic_fix_allowed"] = entity.category != "secret"
    try:
        context["assessment"] = PublicRisk.model_validate(entity.raw["assessment"]).model_dump(mode="json")
        context["classification"] = Classification.model_validate(entity.raw["classification"]).model_dump(mode="json")
    except (ValidationError, KeyError, TypeError):
        context["assessment"] = None
        context["classification"] = None
    return context
