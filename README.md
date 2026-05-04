# Web Security Scanner (Python)

سكريبت بسيط بلغة Python لفحص أمني أولي للمواقع (تعليمي/دفاعي)، ويغطي:

1. فحص HTTP Security Headers الشائعة.
2. التحقق من وجود ملف `robots.txt`.
3. اختبار بدائي جدًا لاحتمال Reflected XSS عبر باراميتر Query.

> **تنبيه:** هذه الأداة ليست بديلًا عن اختبار اختراق احترافي أو أدوات مثل OWASP ZAP و Burp Suite.

---

## المتطلبات

- Python 3.9+
- مكتبة `requests`

تثبيت الاعتمادات:

```bash
pip install requests
```

---

## طريقة التشغيل

```bash
python3 web_security_scanner.py https://example.com
```

مع تخصيص المهلة الزمنية:

```bash
python3 web_security_scanner.py https://example.com --timeout 15
```

---

## ماذا يفحص السكربت؟

### 1) HTTP Security Headers
يفحص وجود هيدرّات أمان شائعة مثل:
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Strict-Transport-Security`

ويعرض ما هو موجود وما هو مفقود مع توصية مختصرة.

### 2) robots.txt
يحاول الوصول إلى:

`https://target-domain/robots.txt`

ويعرض هل الملف موجود وقابل للوصول.

### 3) Basic Reflected XSS Check
يرسل Payload بسيط داخل باراميتر `q` في الرابط، ويتحقق هل تم عكسه داخل الاستجابة.

- إذا انعكس كما هو: يعطي مؤشر خطر محتمل.
- إذا انعكس بشكل escaped: يذكر أن هذا أفضل لكنه لا يعني أمانًا كاملًا.
- إذا لم ينعكس: يعرض أن الفحص الأولي لم يرصد انعكاسًا مباشرًا.

---

## مثال

```bash
python3 web_security_scanner.py https://example.com
```

---

## ملاحظات مهمة

- الفحص الخاص بـ XSS هنا **محدود جدًا** وقد يعطي نتائج غير دقيقة (false positives/false negatives).
- استخدم السكربت فقط على مواقع تملك تصريحًا لاختبارها.
- للأعمال الاحترافية، استخدم منهجية اختبار شاملة وأدوات متقدمة.
