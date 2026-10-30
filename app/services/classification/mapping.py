"""[백엔드 C] CWE 매핑 + OWASP Top 10 (2021) 분류.

1순위: 탐지 도구가 준 OWASP 값
2순위: CWE → OWASP 매핑표
TODO(C): 매핑표 보강 (https://owasp.org/Top10/ 각 카테고리의 'List of Mapped CWEs')
"""

from app.schemas.finding import Category, ClassifiedFinding

OWASP_TOP10_2021 = {
    "A01:2021": "A01:2021-Broken Access Control",
    "A02:2021": "A02:2021-Cryptographic Failures",
    "A03:2021": "A03:2021-Injection",
    "A04:2021": "A04:2021-Insecure Design",
    "A05:2021": "A05:2021-Security Misconfiguration",
    "A06:2021": "A06:2021-Vulnerable and Outdated Components",
    "A07:2021": "A07:2021-Identification and Authentication Failures",
    "A08:2021": "A08:2021-Software and Data Integrity Failures",
    "A09:2021": "A09:2021-Security Logging and Monitoring Failures",
    "A10:2021": "A10:2021-Server-Side Request Forgery",
}

# 자주 나오는 CWE 위주 (확장 필요)
CWE_TO_OWASP = {
    "CWE-22": "A01:2021",
    "CWE-284": "A01:2021",
    "CWE-285": "A01:2021",
    "CWE-352": "A01:2021",
    "CWE-639": "A01:2021",
    "CWE-862": "A01:2021",
    "CWE-863": "A01:2021",
    "CWE-261": "A02:2021",
    "CWE-310": "A02:2021",
    "CWE-319": "A02:2021",
    "CWE-326": "A02:2021",
    "CWE-327": "A02:2021",
    "CWE-328": "A02:2021",
    "CWE-330": "A02:2021",
    "CWE-20": "A03:2021",
    "CWE-74": "A03:2021",
    "CWE-77": "A03:2021",
    "CWE-78": "A03:2021",
    "CWE-79": "A03:2021",
    "CWE-89": "A03:2021",
    "CWE-94": "A03:2021",
    "CWE-95": "A03:2021",
    "CWE-1336": "A03:2021",
    "CWE-209": "A04:2021",
    "CWE-256": "A04:2021",
    "CWE-501": "A04:2021",
    "CWE-16": "A05:2021",
    "CWE-611": "A05:2021",
    "CWE-614": "A05:2021",
    "CWE-942": "A05:2021",
    "CWE-1104": "A06:2021",
    "CWE-937": "A06:2021",
    "CWE-287": "A07:2021",
    "CWE-306": "A07:2021",
    "CWE-384": "A07:2021",
    "CWE-521": "A07:2021",
    "CWE-798": "A07:2021",
    "CWE-345": "A08:2021",
    "CWE-502": "A08:2021",
    "CWE-829": "A08:2021",
    "CWE-117": "A09:2021",
    "CWE-532": "A09:2021",
    "CWE-778": "A09:2021",
    "CWE-918": "A10:2021",
}

CWE_NAMES = {
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-287": "Improper Authentication",
    "CWE-327": "Broken Crypto Algorithm",
    "CWE-352": "CSRF",
    "CWE-502": "Unsafe Deserialization",
    "CWE-798": "Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-918": "SSRF",
}


def normalize_cwe(values: list[str]) -> list[str]:
    """'CWE-89: SQL Injection', 'cwe-89', '89' → 'CWE-89'"""
    result = []
    for v in values:
        num = v.upper().replace("CWE-", "").split(":")[0].strip()
        if num.isdigit():
            result.append(f"CWE-{num}")
    return sorted(set(result))


def classify_owasp(f: ClassifiedFinding) -> str | None:
    for o in f.owasp:
        key = o[:8]
        if key in OWASP_TOP10_2021:
            return OWASP_TOP10_2021[key]
    for cwe in f.cwe:
        if cwe in CWE_TO_OWASP:
            return OWASP_TOP10_2021[CWE_TO_OWASP[cwe]]
    if f.category == Category.SCA:
        return OWASP_TOP10_2021["A06:2021"]
    return None


def apply_mapping(findings: list[ClassifiedFinding]) -> None:
    for f in findings:
        f.cwe = normalize_cwe(f.cwe)
        f.owasp_top10 = classify_owasp(f)
