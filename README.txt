🛡️ دليل تشغيل أدوات الأمن السيبراني المتقدمة
=====================================================

الأدوات المتوفرة:
================

1. الماسح الذكي للثغرات الأمنية (Intelligent Security Scanner)
2. نظام التقارير المتقدم (Advanced Reporting System)
3. واجهة الويب (Web Interface)
4. الماسح المتخفي (Stealth Scanner)
5. نظام الاستغلال (Exploitation System)
6. أداة تجاوز جدار الحماية (WAF Bypass)
7. ماسح SQL حقيقي (Real SQL Scanner)
8. ماسح XSS حقيقي (Real XSS Scanner)

طريقة التشغيل:
=============

1. تشغيل الواجهة الويب (الأفضل للمبتدئين):
-------------------------------------------
# تشغيل الواجهة الويب
python web_interface.py

# ثم فتح المتصفح على:
http://localhost:5000

2. تشغيل الماسح الذكي مباشرة:
------------------------------
# مسح هدف معين
python intelligent_security_scanner_v3.py https://example.com -o results.json -t 10

# عرض المساعدة
python intelligent_security_scanner_v3.py --help

3. تشغيل نظام التقارير المتقدم:
---------------------------------
# توليد تقارير متعددة
python advanced_reporting_system.py

# أو استخدامه كمكتبة في الكود
from advanced_reporting_system import AdvancedReportingSystem

4. تشغيل الماسح المتخفي:
------------------------
python stealth_scanner.py

5. تشغيل نظام الاستغلال:
------------------------
python poc_exploiter.py

6. تشغيل أداة تجاوز جدار الحماية:
---------------------------------
python waf_bypass_advanced.py

7. تشغيل الماسحات اللغوية (Lua):
---------------------------------
# ماسح شامل
lua vulnerability_scanner.lua https://example.com

# ماسح ويب
lua web_scanner.lua https://example.com

# ماسح متقدم
lua advanced_stealth_scanner.lua

الأوامر السريعة:
===============

# تثبيت المتطلبات
pip install -r requirements_enhanced.txt

# تشغيل الواجهة الويب (الطريقة الأسهل)
python web_interface.py

# مسح سريع لموقع
python intelligent_security_scanner_v3.py https://httpbin.org

# توليد تقرير شامل
python advanced_reporting_system.py

# تشغيل جميع الأدوات تلقائياً
python complete_demonstration.py

أنواع المسح المتوفرة:
====================

1. XSS (Cross-Site Scripting)
2. SQL Injection
3. LFI (Local File Inclusion)
4. RCE (Remote Code Execution)
5. XXE (XML External Entity)
6. NoSQL Injection
7. SSRF (Server-Side Request Forgery)
8. SSTI (Server-Side Template Injection)
9. GraphQL Injection
10. Anomaly Detection (كشف الشذوذ بالذكاء الاصطناعي)

تنسيقات التقارير:
=================

- HTML: تقرير تفاعلي مع تصميم احترافي
- JSON: بيانات خام للمعالجة
- CSV: جدول بيانات للتحليل
- XML: بيانات منظمة للأنظمة الأخرى
- PDF: تقرير رسمي قابل للطباعة

مثال عملي للاستخدام:
===================

# الخطوة 1: تشغيل الواجهة الويب
python web_interface.py

# الخطوة 2: فتح المتصفح http://localhost:5000
# الخطوة 3: إدخال رابط الهدف
# الخطوة 4: اختيار أنواع المسح
# الخطوة 5: بدء المسح
# الخطوة 6: مشاهدة النتائج وتوليد التقارير

الملفات المهمة:
===============

- web_interface.py: الواجهة الويب الرئيسية
- intelligent_security_scanner_v3.py: الماسح الذكي
- advanced_reporting_system.py: نظام التقارير المتقدم
- advanced_stealth_scanner.lua: الماسح المتخفي
- poc_exploiter.py: نظام الاستغلال
- waf_bypass_advanced.py: تجاوز جدار الحماية
- requirements_enhanced.txt: متطلبات التثبيت

نصائح مهمة:
============

1. استخدم الواجهة الويب للبدء (أسهل طريقة)
2. ابدأ بالمسح الخفيف ثم انتقل للمتقدم
3. تأكد من صلاحياتك القانونية قبل المسح
4. استخدم وضع التخفي للأهداف الحساسة
5. راجع التقارير بعناية قبل اتخاذ أي إجراء

للمساعدة والدعم:
================

- اقرأ ملفات README الأخرى في المجلد
- استخدم خيار --help مع أي أداة
- راجع سجلات التشغيل للحصول على تفاصيل
- تأكد من تثبيت جميع المتطلبات

⚠️ تحذير: استخدم هذه الأدوات فقط للأهداف التي تملك صلاحية اختبارها!

تم التحديث في: 2025-10-19
الإصدار: 3.0 المتقدم