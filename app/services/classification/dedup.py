"""기존 import 경로를 보존하는 C 파이프라인 호환 함수."""


def deduplicate(findings):
    from app.services.classification.pipeline import classify

    return classify(findings)
