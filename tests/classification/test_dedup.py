import pytest
from pydantic import ValidationError

from app.services.classification.core.dedup import merge
from app.services.classification.core.models import Finding


def finding(identifier="one", **changes):
    data = dict(
        finding_id=identifier,
        tool="semgrep",
        kind="code",
        rule_id="sql",
        locations=[dict(path="app.py", start_line=3, end_line=3, start_column=1, end_column=8)],
    )
    return Finding(**(data | changes))


def test_duplicates_preserve_sources():
    groups = merge("analysis", [finding(), finding("two")])
    assert len(groups) == 1
    assert len(groups[0].sources) == 2


def test_different_rules_remain_separate():
    assert len(merge("a", [finding(), finding("two", rule_id="xss")])) == 2


def test_order_independence():
    rows = [finding(), finding("two")]
    assert merge("a", rows) == merge("a", rows[::-1])


def test_empty():
    assert merge("a", []) == []


def test_repeated_id_rejected():
    with pytest.raises(ValueError):
        merge("a", [finding(), finding()])


def test_path_traversal_rejected():
    with pytest.raises(ValidationError):
        finding(locations=[dict(path="../key", start_line=1, end_line=1)])


def test_raw_secret_field_rejected_without_value_in_error():
    with pytest.raises(ValidationError) as error:
        finding(secret="mock-sensitive-value")
    assert "mock-sensitive-value" not in str(error.value)


def test_dependency_identity_includes_version_and_manifest():
    from app.services.classification.core.models import Finding

    data = dict(
        tool="osv",
        kind="dependency",
        rule_id="osv",
        vulnerability_ids=["CVE-2025-0001"],
        package=dict(ecosystem="PyPI", name="example", version="1", manifest="requirements.txt"),
    )
    one = Finding(finding_id="a", **data)
    two = Finding(finding_id="b", **data)
    three = Finding(finding_id="c", **(data | {"package": data["package"] | {"version": "2"}}))
    assert len(merge("a", [one, two, three])) == 2


def test_secrets_without_fingerprint_never_merge():
    assert len(merge("a", [finding("a", kind="secret"), finding("b", kind="secret")])) == 2


@pytest.mark.parametrize("score", [float("nan"), float("inf"), -1, 11])
def test_invalid_cvss_rejected(score):
    with pytest.raises(ValidationError):
        finding(cvss_score=score, cvss_version="3.1")
