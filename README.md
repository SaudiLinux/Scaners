# Advanced Web Vulnerability Scanner & Exploitation Framework

A comprehensive Python-based web vulnerability scanner that detects common web security vulnerabilities including SQL injection, XSS, directory traversal, file inclusion, XXE, CSRF, and more. This framework also includes exploitation tools and a vulnerable application for educational purposes.

## ⚠️ Legal Disclaimer

**This tool is intended for authorized security testing only!**

- Only use this scanner on systems you own or have explicit written permission to test
- Unauthorized scanning may violate applicable laws and regulations
- The authors are not responsible for any misuse or damage caused by this tool
- Always ensure you have proper authorization before conducting security tests
- The vulnerable application is for educational purposes only - never deploy in production

## Features

### Vulnerability Detection
- **SQL Injection**: Tests for SQL injection vulnerabilities using various payloads
- **Cross-Site Scripting (XSS)**: Detects reflected and stored XSS vulnerabilities
- **Directory Traversal**: Identifies path traversal vulnerabilities
- **File Inclusion**: Tests for Local File Inclusion (LFI) and Remote File Inclusion (RFI)
- **XML External Entity (XXE)**: Detects XXE injection vulnerabilities
- **Cross-Site Request Forgery (CSRF)**: Identifies missing CSRF protection
- **Security Headers**: Checks for missing security headers
- **Information Disclosure**: Finds sensitive information leaks
- **Weak Authentication**: Tests for authentication bypass vulnerabilities
- **Zero-Day Vulnerabilities**: Advanced detection for Log4j, Spring4Shell, deserialization, GraphQL, SSRF, SSTI, and memory corruption

### Exploitation Testing
- **SQL Injection**: Attempts data extraction and database information gathering
- **XSS**: Tests for JavaScript execution capabilities
- **Directory Traversal**: Attempts to read system files
- **File Inclusion**: Tests for code execution through file inclusion
- **XXE**: Attempts to read local files and perform SSRF attacks
- **Command Injection**: Tests for system command execution
- **SSRF**: Server-side request forgery exploitation
- **LFI/RFI**: Local and remote file inclusion exploitation

### Educational Components
- **Vulnerable Application**: Flask-based web app with intentional vulnerabilities
- **Proof of Concept Exploiter**: Automated exploitation tool for educational testing
- **Complete Demonstration**: Automated workflow from scanning to exploitation
- **Vulnerable URLs List**: Comprehensive list of infected endpoints with payloads

### Reporting & Analysis
- Comprehensive vulnerability reports with severity ratings
- Risk assessment and security recommendations
- JSON export for integration with other tools
- Detailed exploitation results with proof-of-concept
- Executive summary with actionable insights

## Installation

### Prerequisites

- **Python 3.6+**
- **pip** (for dependency management)
- **Git** (for cloning the repository)

### Install Dependencies

```bash
# Install required Python packages
pip install -r requirements.txt
```

### Download the Scanner

```bash
# Clone or download the scanner files
# You should have these files:
# - web_scanner.py (main scanner application)
# - poc_exploiter.py (exploitation tool)
# - vulnerable_app.py (educational vulnerable application)
# - complete_demonstration.py (automated demonstration)
# - requirements.txt (Python dependencies)
# - requirements_vulnerable.txt (vulnerable app dependencies)
# - README.md (documentation)
```

## Usage

### Basic Scan

```bash
# Basic vulnerability scan
python web_scanner.py https://example.com

# Scan with verbose output
python web_scanner.py -v https://example.com

# Scan with custom timeout (15 seconds)
python web_scanner.py --timeout 15 https://example.com

# Scan with custom User-Agent
python web_scanner.py --user-agent "Mozilla/5.0 (Custom Scanner)" https://example.com
```

### Advanced Scan with Report Export

```bash
# Save detailed report to JSON file
python web_scanner.py -o report.json https://example.com

# Full scan with all options
python web_scanner.py -v -o full_report.json --timeout 20 https://example.com
```

### Educational Tools Usage

#### Vulnerable Application (Educational Only)
```bash
# Install dependencies for vulnerable app
pip install -r requirements_vulnerable.txt

# Start the vulnerable web application
python vulnerable_app.py

# The application will run on http://127.0.0.1:5000
# Access vulnerable endpoints:
# - SQL Injection: http://127.0.0.1:5000/user?id=1' UNION SELECT 1,2,3,4--
# - XSS: http://127.0.0.1:5000/search?q=<script>alert('XSS')</script>
# - LFI: http://127.0.0.1:5000/include?file=../../../../etc/passwd
# - Command Injection: http://127.0.0.1:5000/execute?cmd=id;whoami
# - SSRF: http://127.0.0.1:5000/fetch?url=http://169.254.169.254/latest/meta-data/
```

#### Proof of Concept Exploiter
```bash
# Test exploitation against vulnerable app
python poc_exploiter.py http://127.0.0.1:5000

# Test with custom timeout
python poc_exploiter.py --timeout 10 http://127.0.0.1:5000

# Save exploitation results
python poc_exploiter.py -o exploitation_results.json http://127.0.0.1:5000
```

#### Complete Demonstration
```bash
# Run complete demonstration (starts vulnerable app, scans, exploits)
python complete_demonstration.py

# This will:
# 1. Start the vulnerable application
# 2. Run vulnerability scan
# 3. Attempt exploitation
# 4. Generate comprehensive report
```

#### Vulnerable URLs List
```bash
# Display all vulnerable URLs and payloads
python vulnerable_urls_list.py

# Quick reference of main infected links
python infected_links_summary.py

# Quick reference card
python quick_reference.py
```

### Command Line Options

```
Usage: python web_scanner.py [options] <target_url>

Options:
  -h, --help              Show help message
  -o, --output <file>     Save report to file (JSON format)
  -v, --verbose           Enable verbose output
  --user-agent <ua>       Set custom User-Agent string
  --timeout <seconds>     Set request timeout (default: 10)

Examples:
  python web_scanner.py https://example.com
  python web_scanner.py -o report.json https://example.com
  python web_scanner.py --verbose --timeout 15 https://example.com
```

## Understanding the Results

### Vulnerability Severity Levels

- **Critical**: Immediate security risk requiring urgent attention
- **High**: Significant security vulnerability with potential for serious impact
- **Medium**: Moderate security issue that should be addressed
- **Low**: Minor security concern with limited impact
- **Info**: Informational findings that don't pose direct security risks

### Exploitation Results

When using the `-e` flag, the scanner attempts to exploit discovered vulnerabilities:

- **Successful Exploitation**: Confirms the vulnerability is exploitable
- **Failed Exploitation**: Vulnerability exists but exploitation was blocked
- **Partial Success**: Some exploitation techniques worked, others failed

### Risk Assessment

The scanner provides an overall risk assessment based on:
- Number and severity of vulnerabilities
- Exploitation success rate
- Potential impact on the target system
- Common attack vectors present

## Security Recommendations

The scanner generates specific recommendations based on discovered vulnerabilities:

### Critical Recommendations
- Implement parameterized queries for SQL injection
- Use strict input validation for file paths
- Disable dangerous PHP wrappers
- Implement proper authentication controls
- Update Log4j and Spring frameworks to latest versions
- Disable external entity processing in XML parsers
- Implement proper input sanitization for all user inputs

### High Priority Recommendations
- Add output encoding for XSS prevention
- Implement Content Security Policy (CSP)
- Disable external entity processing in XML parsers
- Use secure authentication mechanisms
- Implement SSRF protection and URL validation
- Add rate limiting and input validation

### General Best Practices
- Implement comprehensive security headers
- Use HTTPS for all communications
- Keep software components updated
- Conduct regular security assessments
- Implement zero-day vulnerability monitoring
- Use Web Application Firewalls (WAF)
- Enable comprehensive logging and monitoring

## Zero-Day Vulnerability Detection

The scanner includes advanced detection capabilities for zero-day vulnerabilities:

### Log4j (Log4Shell) Detection
- Tests for JNDI injection vulnerabilities
- Detects remote code execution attempts
- Identifies various Log4j exploitation techniques

### Spring4Shell Detection
- Tests for Spring Framework RCE vulnerabilities
- Detects Spring Cloud Function exploitation
- Identifies Spring Data Commons vulnerabilities

### Advanced XXE Detection
- Tests for XML External Entity injection
- Detects blind XXE vulnerabilities
- Identifies out-of-band XXE attacks

### Deserialization Vulnerabilities
- Tests for insecure deserialization
- Detects Java and PHP deserialization attacks
- Identifies dangerous deserialization patterns

### GraphQL Vulnerabilities
- Tests for GraphQL injection attacks
- Detects GraphQL introspection issues
- Identifies GraphQL authorization bypasses

### SSRF Detection
- Tests for Server-Side Request Forgery
- Detects internal network access attempts
- Identifies cloud metadata service access

### Command Injection Detection
- Tests for system command injection
- Detects shell command execution
- Identifies command chaining vulnerabilities

### Memory Corruption Detection
- Tests for buffer overflow vulnerabilities
- Detects format string vulnerabilities
- Identifies memory corruption patterns

## Sample Output

```
================================================================================
                           SCAN SUMMARY
================================================================================
Total Vulnerabilities Found: 12
Critical: 2
High: 3
Medium: 4
Low: 2
Info: 1

Overall Risk Level: HIGH
Risk Factors:
  - High severity vulnerabilities found
  - Multiple high-risk vulnerabilities

================================================================================
[!] SECURITY RECOMMENDATIONS:
================================================================================

CRITICAL (Immediate Action Required):
  ⚠️  Immediately implement parameterized queries for all database interactions
  ⚠️  Implement strict input validation for file paths

HIGH PRIORITY:
  🔴 Implement output encoding for all user-supplied data
  🔴 Use Content Security Policy (CSP) headers

MEDIUM PRIORITY:
  🟡 Implement anti-CSRF tokens for all state-changing operations
  🟡 Implement comprehensive security headers

LOW PRIORITY:
  🟢 Implement comprehensive logging and monitoring
  🟢 Conduct regular security assessments
```

## File Structure

```
Advanced-Web-Vulnerability-Scanner/
├── web_scanner.py              # Main vulnerability scanner
├── poc_exploiter.py            # Proof of concept exploitation tool
├── vulnerable_app.py           # Educational vulnerable application
├── complete_demonstration.py   # Automated demonstration script
├── requirements.txt            # Main dependencies
├── requirements_vulnerable.txt   # Vulnerable app dependencies
├── README.md                   # Documentation
├── POC_DOCUMENTATION.md        # Detailed POC documentation
├── poc_summary_report.json     # POC summary report
├── vulnerable_urls_complete.json # Complete vulnerable URLs list
├── infected_links_summary.py   # Quick infected links summary
├── quick_reference.py          # Quick reference card
└── test.txt                    # Test file for LFI demonstration
```

## Troubleshooting

### Common Issues

#### Scanner Not Working
- Ensure Python 3.7+ is installed
- Install all dependencies: `pip install -r requirements.txt`
- Check internet connectivity
- Verify target URL is accessible

#### Vulnerable Application Issues
- Install vulnerable app dependencies: `pip install -r requirements_vulnerable.txt`
- Ensure port 5000 is available
- Check Flask version compatibility
- Verify file permissions for test files

#### Exploitation Tool Issues
- Ensure target is running the vulnerable application
- Check timeout settings for slow connections
- Verify payload generation is working correctly
- Check JSON output format

#### Educational Tools Issues
- Run vulnerable application first before testing
- Check endpoint URLs are correct
- Verify payload formats match expected patterns
- Ensure proper ethical usage guidelines are followed

### Performance Issues
- Increase timeout for slow connections
- Reduce concurrent requests if needed
- Check system resources (CPU, memory)
- Consider using proxy for better connectivity

## Educational Components

This framework includes educational tools designed for learning and demonstration purposes:

### Vulnerable Application
A deliberately vulnerable web application that demonstrates common security flaws:
- SQL Injection vulnerabilities
- Cross-Site Scripting (XSS) flaws
- Local File Inclusion (LFI) issues
- Command Injection vulnerabilities
- Server-Side Request Forgery (SSRF) flaws
- HTTP Header Injection problems

### Proof of Concept Exploiter
A tool that demonstrates how vulnerabilities can be exploited:
- Automated exploitation testing
- Payload generation and execution
- Result analysis and reporting
- Educational demonstration capabilities

### Complete Demonstration
An automated script that runs the entire process:
- Starts the vulnerable application
- Performs vulnerability scanning
- Attempts exploitation
- Generates comprehensive reports

### Vulnerable URLs Reference
Educational tools that provide:
- Complete list of vulnerable endpoints
- Example exploitation payloads
- Quick reference cards
- Educational documentation

⚠️ **IMPORTANT**: These educational components are designed for learning purposes only. They should only be used in controlled environments for educational purposes.

## Contributing

Contributions are welcome! Please ensure:
- All code follows security best practices
- Educational components are clearly marked
- Documentation is updated for new features
- Ethical guidelines are maintained

## Conclusion

This Advanced Web Vulnerability Scanner & Exploitation Framework provides a comprehensive solution for:

- **Security Testing**: Professional vulnerability scanning capabilities
- **Educational Purposes**: Complete vulnerable application for learning
- **Research**: Advanced zero-day vulnerability detection
- **Demonstration**: Proof of concept exploitation tools

The framework includes both offensive and defensive security tools, making it valuable for:
- Security professionals conducting authorized assessments
- Developers learning about web application security
- Students studying cybersecurity concepts
- Researchers investigating vulnerability patterns

Remember: Always use these tools ethically and only on systems you own or have explicit permission to test.

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CVE Database](https://cve.mitre.org/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

---

**⚠️ Legal Notice**: This tool is for educational and authorized testing purposes only. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse of this software.