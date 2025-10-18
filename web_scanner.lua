#!/usr/bin/env lua

-- Web Vulnerability Scanner - Main Application
-- Advanced security testing tool for web applications

local VulnerabilityScanner = require("vulnerability_scanner")
local VulnTests = require("vulnerability_tests")
local ExploitTests = require("exploitation_tests")
local json = require("dkjson")

-- Enhanced Scanner Class with all test methods
local EnhancedScanner = {}
setmetatable(EnhancedScanner, {__index = VulnerabilityScanner})

function EnhancedScanner:new(url)
    local self = VulnerabilityScanner:new(url)
    setmetatable(self, EnhancedScanner)
    return self
end

-- Add all vulnerability test methods to the scanner
function EnhancedScanner:test_sql_injection()
    VulnTests.test_sql_injection(self)
end

function EnhancedScanner:test_xss()
    VulnTests.test_xss(self)
end

function EnhancedScanner:test_directory_traversal()
    VulnTests.test_directory_traversal(self)
end

function EnhancedScanner:test_file_inclusion()
    VulnTests.test_file_inclusion(self)
end

function EnhancedScanner:test_xxe()
    VulnTests.test_xxe(self)
end

function EnhancedScanner:test_csrf()
    VulnTests.test_csrf(self)
end

function EnhancedScanner:test_insecure_headers()
    VulnTests.test_insecure_headers(self)
end

function EnhancedScanner:test_information_disclosure()
    VulnTests.test_information_disclosure(self)
end

function EnhancedScanner:test_weak_authentication()
    VulnTests.test_weak_authentication(self)
end

-- Run exploitation tests on discovered vulnerabilities
function EnhancedScanner:run_exploitation_tests()
    print("\n[*] Starting exploitation tests on discovered vulnerabilities...")
    
    local exploitation_results = {}
    
    for _, vulnerability in ipairs(self.vulnerabilities) do
        if vulnerability.severity == "critical" or vulnerability.severity == "high" then
            print(string.format("[*] Testing exploitation for: %s", vulnerability.name))
            
            local exploit_result = ExploitTests.run_exploitation(self, vulnerability)
            table.insert(exploitation_results, exploit_result)
            
            if exploit_result.exploitation_successful then
                print(string.format("[+] EXPLOITATION SUCCESSFUL for %s", vulnerability.name))
            else
                print(string.format("[-] Exploitation failed for %s", vulnerability.name))
            end
        end
    end
    
    return exploitation_results
end

-- Generate comprehensive report
function EnhancedScanner:generate_comprehensive_report(exploitation_results)
    local report = {
        scan_metadata = {
            scanner_name = "Advanced Web Vulnerability Scanner",
            version = "1.0.0",
            scan_date = os.date("%Y-%m-%d %H:%M:%S"),
            target_url = self.target_url,
            scan_duration = os.time() - (self.scan_start_time or os.time())
        },
        vulnerability_summary = self:generate_summary(),
        discovered_vulnerabilities = self.vulnerabilities,
        exploitation_results = exploitation_results or {},
        risk_assessment = self:generate_risk_assessment(),
        recommendations = self:generate_recommendations()
    }
    
    return report
end

-- Generate risk assessment
function EnhancedScanner:generate_risk_assessment()
    local summary = self:generate_summary()
    local risk_level = "LOW"
    local risk_factors = {}
    
    if summary.critical > 0 then
        risk_level = "CRITICAL"
        table.insert(risk_factors, "Critical vulnerabilities present")
    elseif summary.high > 0 then
        risk_level = "HIGH"
        table.insert(risk_factors, "High severity vulnerabilities found")
    elseif summary.medium > 0 then
        risk_level = "MEDIUM"
        table.insert(risk_factors, "Medium severity vulnerabilities detected")
    end
    
    if summary.critical + summary.high > 3 then
        table.insert(risk_factors, "Multiple high-risk vulnerabilities")
    end
    
    if #self.vulnerabilities > 10 then
        table.insert(risk_factors, "Large number of vulnerabilities")
    end
    
    return {
        overall_risk_level = risk_level,
        risk_factors = risk_factors,
        total_vulnerabilities = #self.vulnerabilities,
        severity_breakdown = summary
    }
end

-- Generate security recommendations
function EnhancedScanner:generate_recommendations()
    local recommendations = {
        critical = {},
        high = {},
        medium = {},
        low = {}
    }
    
    -- Critical recommendations
    if self:has_vulnerability_type("SQL Injection") then
        table.insert(recommendations.critical, "Immediately implement parameterized queries for all database interactions")
        table.insert(recommendations.critical, "Conduct comprehensive code review of all SQL query constructions")
    end
    
    if self:has_vulnerability_type("Directory Traversal") then
        table.insert(recommendations.critical, "Implement strict input validation for file paths")
        table.insert(recommendations.critical, "Use whitelisting approach for file access controls")
    end
    
    if self:has_vulnerability_type("File Inclusion") then
        table.insert(recommendations.critical, "Disable dangerous PHP wrappers (expect, data, php)")
        table.insert(recommendations.critical, "Implement proper file inclusion validation")
    end
    
    -- High priority recommendations
    if self:has_vulnerability_type("XSS") then
        table.insert(recommendations.high, "Implement output encoding for all user-supplied data")
        table.insert(recommendations.high, "Use Content Security Policy (CSP) headers")
    end
    
    if self:has_vulnerability_type("XXE") then
        table.insert(recommendations.high, "Disable external entity processing in XML parsers")
        table.insert(recommendations.high, "Use JSON instead of XML where possible")
    end
    
    -- Medium priority recommendations
    if self:has_vulnerability_type("CSRF") then
        table.insert(recommendations.medium, "Implement anti-CSRF tokens for all state-changing operations")
        table.insert(recommendations.medium, "Use SameSite cookie attribute")
    end
    
    if self:has_vulnerability_type("Missing Security Headers") then
        table.insert(recommendations.medium, "Implement comprehensive security headers")
        table.insert(recommendations.medium, "Configure HSTS, X-Frame-Options, and X-Content-Type-Options")
    end
    
    -- General recommendations
    table.insert(recommendations.low, "Implement comprehensive logging and monitoring")
    table.insert(recommendations.low, "Conduct regular security assessments")
    table.insert(recommendations.low, "Keep all software components up to date")
    
    return recommendations
end

-- Check if specific vulnerability type exists
function EnhancedScanner:has_vulnerability_type(vuln_type)
    for _, vuln in ipairs(self.vulnerabilities) do
        if vuln.name:match(vuln_type) then
            return true
        end
    end
    return false
end

-- Print banner
function print_banner()
    print([[
╔══════════════════════════════════════════════════════════════════════════════╗
║                    Advanced Web Vulnerability Scanner                       ║
║                            Version 1.0.0                                   ║
║                                                                              ║
║  ⚠️  WARNING: This tool is for authorized security testing only!           ║
║     Unauthorized use may violate applicable laws.                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
    ]])
end

-- Print usage
function print_usage()
    print("\nUsage: lua web_scanner.lua [options] <target_url>")
    print("\nOptions:")
    print("  -h, --help              Show this help message")
    print("  -o, --output <file>     Save report to file (JSON format)")
    print("  -e, --exploit           Run exploitation tests on discovered vulnerabilities")
    print("  -v, --verbose           Enable verbose output")
    print("  --user-agent <ua>       Set custom User-Agent string")
    print("  --timeout <seconds>     Set request timeout (default: 10)")
    print("\nExamples:")
    print("  lua web_scanner.lua https://example.com")
    print("  lua web_scanner.lua -o report.json -e https://example.com")
    print("  lua web_scanner.lua --verbose --timeout 15 https://example.com")
end

-- Parse command line arguments
function parse_arguments(args)
    local options = {
        target_url = nil,
        output_file = nil,
        run_exploitation = false,
        verbose = false,
        user_agent = nil,
        timeout = 10
    }
    
    local i = 1
    while i <= #args do
        local arg = args[i]
        
        if arg == "-h" or arg == "--help" then
            print_usage()
            os.exit(0)
        elseif arg == "-o" or arg == "--output" then
            i = i + 1
            if i <= #args then
                options.output_file = args[i]
            else
                print("[!] Error: --output requires a filename")
                os.exit(1)
            end
        elseif arg == "-e" or arg == "--exploit" then
            options.run_exploitation = true
        elseif arg == "-v" or arg == "--verbose" then
            options.verbose = true
        elseif arg == "--user-agent" then
            i = i + 1
            if i <= #args then
                options.user_agent = args[i]
            else
                print("[!] Error: --user-agent requires a string")
                os.exit(1)
            end
        elseif arg == "--timeout" then
            i = i + 1
            if i <= #args then
                options.timeout = tonumber(args[i])
                if not options.timeout or options.timeout <= 0 then
                    print("[!] Error: --timeout must be a positive number")
                    os.exit(1)
                end
            else
                print("[!] Error: --timeout requires a number")
                os.exit(1)
            end
        elseif not arg:match("^-") then
            if not options.target_url then
                options.target_url = arg
            else
                print("[!] Error: Multiple target URLs specified")
                print_usage()
                os.exit(1)
            end
        else
            print("[!] Error: Unknown option: " .. arg)
            print_usage()
            os.exit(1)
        end
        
        i = i + 1
    end
    
    if not options.target_url then
        print("[!] Error: No target URL specified")
        print_usage()
        os.exit(1)
    end
    
    return options
end

-- Main function
function main()
    print_banner()
    
    -- Parse command line arguments
    local options = parse_arguments(arg)
    
    -- Create scanner instance
    local scanner = EnhancedScanner:new(options.target_url)
    
    -- Configure scanner options
    if options.user_agent then
        scanner.user_agent = options.user_agent
    end
    scanner.timeout = options.timeout
    scanner.verbose = options.verbose
    scanner.scan_start_time = os.time()
    
    print(string.format("[*] Target: %s", options.target_url))
    print(string.format("[*] User-Agent: %s", scanner.user_agent))
    print(string.format("[*] Timeout: %d seconds", scanner.timeout))
    if options.run_exploitation then
        print("[*] Exploitation testing: ENABLED")
    end
    print()
    
    -- Run vulnerability scan
    local scan_success = scanner:scan()
    
    if not scan_success then
        print("[!] Scan failed!")
        os.exit(1)
    end
    
    -- Run exploitation tests if requested
    local exploitation_results = {}
    if options.run_exploitation and #scanner.vulnerabilities > 0 then
        exploitation_results = scanner:run_exploitation_tests()
    end
    
    -- Generate comprehensive report
    local report = scanner:generate_comprehensive_report(exploitation_results)
    
    -- Display summary
    print("\n" .. string.rep("=", 80))
    print("                           SCAN SUMMARY")
    print(string.rep("=", 80))
    
    local summary = scanner:generate_summary()
    print(string.format("Total Vulnerabilities Found: %d", #scanner.vulnerabilities))
    print(string.format("Critical: %d", summary.critical))
    print(string.format("High: %d", summary.high))
    print(string.format("Medium: %d", summary.medium))
    print(string.format("Low: %d", summary.low))
    print(string.format("Info: %d", summary.info))
    
    -- Display risk assessment
    local risk_assessment = scanner:generate_risk_assessment()
    print(string.format("\nOverall Risk Level: %s", risk_assessment.overall_risk_level))
    
    if #risk_assessment.risk_factors > 0 then
        print("Risk Factors:")
        for _, factor in ipairs(risk_assessment.risk_factors) do
            print("  - " .. factor)
        end
    end
    
    -- Save report if requested
    if options.output_file then
        local json_report = json.encode(report, { indent = true })
        local file = io.open(options.output_file, "w")
        if file then
            file:write(json_report)
            file:close()
            print(string.format("\n[+] Report saved to: %s", options.output_file))
        else
            print(string.format("\n[!] Error: Could not save report to %s", options.output_file))
        end
    end
    
    print("\n" .. string.rep("=", 80))
    print("[!] SECURITY RECOMMENDATIONS:")
    print(string.rep("=", 80))
    
    local recommendations = scanner:generate_recommendations()
    
    if #recommendations.critical > 0 then
        print("\nCRITICAL (Immediate Action Required):")
        for _, rec in ipairs(recommendations.critical) do
            print("  ⚠️  " .. rec)
        end
    end
    
    if #recommendations.high > 0 then
        print("\nHIGH PRIORITY:")
        for _, rec in ipairs(recommendations.high) do
            print("  🔴 " .. rec)
        end
    end
    
    if #recommendations.medium > 0 then
        print("\nMEDIUM PRIORITY:")
        for _, rec in ipairs(recommendations.medium) do
            print("  🟡 " .. rec)
        end
    end
    
    if #recommendations.low > 0 then
        print("\nLOW PRIORITY:")
        for _, rec in ipairs(recommendations.low) do
            print("  🟢 " .. rec)
        end
    end
    
    print("\n" .. string.rep("=", 80))
    print("⚠️  DISCLAIMER: This scan was performed for security testing purposes.")
    print("   Ensure you have proper authorization before testing any system.")
    print(string.rep("=", 80))
end

-- Run main function
main()