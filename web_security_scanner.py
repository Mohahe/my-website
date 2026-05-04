#!/usr/bin/env python3
"""
Web Security Scanner (educational / defensive use)

يفحص الموقع للأشياء التالية:
1) HTTP Security Headers
2) وجود robots.txt
3) فحص بسيط جدًا لاحتمالية XSS المنعكس عبر باراميتر query

ملاحظة: هذا ليس بديلًا عن أدوات فحص احترافية مثل OWASP ZAP أو Burp Suite.
"""

from __future__ import annotations

import argparse
import html
import secrets
import string
from dataclasses import dataclass
from typing import Dict, List, Tuple
from urllib.parse import urlencode, urlparse

import requests


# هيدرّات أمان شائعة يُفضّل وجودها
RECOMMENDED_HEADERS = {
    "Content-Security-Policy": "ينصح بإعداد CSP للحد من XSS وحقن المحتوى.",
    "X-Content-Type-Options": "يفضّل أن تكون القيمة nosniff.",
    "X-Frame-Options": "يفضّل DENY أو SAMEORIGIN لمنع clickjacking.",
    "Referrer-Policy": "يفضّل سياسة واضحة للـ referrer.",
    "Permissions-Policy": "للتحكم بقدرات المتصفح.",
    "Strict-Transport-Security": "يفضّل عند استخدام HTTPS فقط.",
}


@dataclass
class ScanResult:
    target: str
    headers_found: Dict[str, str]
    missing_headers: Dict[str, str]
    robots_exists: bool
    robots_status: int
    xss_tested: bool
    xss_reflection_detected: bool
    xss_details: str


def normalize_url(url: str) -> str:
    """يضمن أن الرابط يحتوي على schema ويعيده بصيغة موحدة."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"
    return url.rstrip("/")


def fetch_response(url: str, timeout: int) -> requests.Response:
    """جلب الصفحة الرئيسية مع اتباع التحويلات."""
    return requests.get(url, timeout=timeout, allow_redirects=True)


def check_security_headers(response: requests.Response) -> Tuple[Dict[str, str], Dict[str, str]]:
    """فحص الهيدرّات الأمنية الموصى بها."""
    found: Dict[str, str] = {}
    missing: Dict[str, str] = {}

    for header, recommendation in RECOMMENDED_HEADERS.items():
        if header in response.headers:
            found[header] = response.headers[header]
        else:
            missing[header] = recommendation

    return found, missing


def check_robots_txt(base_url: str, timeout: int) -> Tuple[bool, int]:
    """التحقق من وجود robots.txt وحالة الاستجابة."""
    robots_url = f"{base_url}/robots.txt"
    try:
        resp = requests.get(robots_url, timeout=timeout, allow_redirects=True)
        exists = resp.status_code == 200 and len(resp.text.strip()) > 0
        return exists, resp.status_code
    except requests.RequestException:
        return False, 0


def generate_xss_payload() -> str:
    """إنشاء payload بسيط وفريد لتقليل false positives."""
    random_tag = "".join(secrets.choice(string.ascii_lowercase) for _ in range(6))
    return f'<script>alert("xss-{random_tag}")</script>'


def check_basic_reflected_xss(base_url: str, timeout: int) -> Tuple[bool, bool, str]:
    """
    فحص بدائي جدًا لـ Reflected XSS:
    - يرسل payload داخل باراميتر q
    - يتحقق هل payload رجع كما هو داخل الاستجابة

    تنبيه: هذا فحص أولي وقد يعطي false positives / false negatives.
    """
    payload = generate_xss_payload()
    query = urlencode({"q": payload})
    test_url = f"{base_url}/?{query}"

    try:
        resp = requests.get(test_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return False, False, f"تعذر تنفيذ اختبار XSS: {exc}"

    body = resp.text
    reflected_raw = payload in body

    # لو انعكس بشكل escaped غالبًا هناك حماية/تعقيم
    escaped_payload = html.escape(payload)
    reflected_escaped = escaped_payload in body

    if reflected_raw:
        return True, True, f"تم رصد انعكاس payload بدون تعقيم واضح في: {test_url}"

    if reflected_escaped:
        return True, False, (
            "تم العثور على انعكاس payload لكن بصيغة escaped؛ "
            "هذا مؤشر أفضل من الانعكاس الخام لكنه لا يؤكد الأمان الكامل."
        )

    return True, False, "لم يتم رصد انعكاس مباشر للـ payload في الاستجابة."


def run_scan(target: str, timeout: int) -> ScanResult:
    """تشغيل جميع الفحوصات وتجميع النتيجة."""
    base_url = normalize_url(target)
    response = fetch_response(base_url, timeout=timeout)

    found_headers, missing_headers = check_security_headers(response)
    robots_exists, robots_status = check_robots_txt(base_url, timeout=timeout)
    xss_tested, xss_detected, xss_details = check_basic_reflected_xss(base_url, timeout=timeout)

    return ScanResult(
        target=base_url,
        headers_found=found_headers,
        missing_headers=missing_headers,
        robots_exists=robots_exists,
        robots_status=robots_status,
        xss_tested=xss_tested,
        xss_reflection_detected=xss_detected,
        xss_details=xss_details,
    )


def print_report(result: ScanResult) -> None:
    """طباعة تقرير واضح في الطرفية."""
    print("=" * 60)
    print(f"Web Security Scan Report: {result.target}")
    print("=" * 60)

    print("\n[1] HTTP Security Headers")
    if result.headers_found:
        print("- Headers الموجودة:")
        for k, v in result.headers_found.items():
            print(f"  ✓ {k}: {v}")
    else:
        print("- لم يتم العثور على أي Header أمني من القائمة الموصى بها.")

    if result.missing_headers:
        print("- Headers المفقودة:")
        for k, advice in result.missing_headers.items():
            print(f"  ✗ {k} -> {advice}")

    print("\n[2] robots.txt")
    if result.robots_exists:
        print(f"- ✓ robots.txt موجود (HTTP {result.robots_status})")
    else:
        status_text = result.robots_status if result.robots_status else "غير متاح"
        print(f"- ✗ robots.txt غير موجود/غير قابل للوصول (HTTP {status_text})")

    print("\n[3] Basic Reflected XSS Check")
    if not result.xss_tested:
        print(f"- ⚠️ لم يتم تنفيذ الاختبار: {result.xss_details}")
    elif result.xss_reflection_detected:
        print(f"- ⚠️ مؤشر ثغرة محتملة: {result.xss_details}")
    else:
        print(f"- ✓ لا يوجد انعكاس خام واضح: {result.xss_details}")

    print("\nمهم: هذه النتائج أولية. نفّذ اختبارات أعمق قبل اتخاذ قرارات أمنية.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple Web Security Scanner")
    parser.add_argument("url", help="رابط الموقع (مثال: https://example.com)")
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="مهلة الطلبات بالثواني (افتراضي: 10)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    try:
        result = run_scan(args.url, timeout=args.timeout)
        print_report(result)
    except requests.RequestException as exc:
        print(f"فشل الاتصال بالموقع: {exc}")


if __name__ == "__main__":
    main()
