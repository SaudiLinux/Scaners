#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Reporting System for Security Tools
Supports multiple output formats with AI integration
"""

import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
import os
from typing import Dict, List, Any, Optional
import base64
import io
from pathlib import Path


class AdvancedReportingSystem:
    """Advanced reporting system with multiple format support and AI integration"""
    
    def __init__(self):
        self.supported_formats = ['html', 'json', 'csv', 'xml', 'pdf']
        self.reports_dir = 'reports'
        self.templates_dir = 'templates'
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Ensure required directories exist"""
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.templates_dir, exist_ok=True)
    
    def generate_report(self, scan_results: Dict[str, Any], 
                       output_format: str = 'html',
                       filename: Optional[str] = None) -> str:
        """
        Generate report in specified format
        
        Args:
            scan_results: Complete scan results dictionary
            output_format: Output format (html, json, csv, xml, pdf)
            filename: Optional custom filename
            
        Returns:
            Path to generated report file
        """
        if output_format not in self.supported_formats:
            raise ValueError(f"Unsupported format: {output_format}")
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.{output_format}"
        
        filepath = os.path.join(self.reports_dir, filename)
        
        if output_format == 'html':
            return self._generate_html_report(scan_results, filepath)
        elif output_format == 'json':
            return self._generate_json_report(scan_results, filepath)
        elif output_format == 'csv':
            return self._generate_csv_report(scan_results, filepath)
        elif output_format == 'xml':
            return self._generate_xml_report(scan_results, filepath)
        elif output_format == 'pdf':
            return self._generate_pdf_report(scan_results, filepath)
        
        return filepath
    
    def _generate_html_report(self, scan_results: Dict[str, Any], filepath: str) -> str:
        """Generate HTML report"""
        html_template = self._get_html_template()
        
        # Extract data for template
        summary = scan_results.get('scan_summary', {})
        vulnerabilities = scan_results.get('vulnerabilities', [])
        ai_analysis = scan_results.get('ai_analysis', {})
        recommendations = scan_results.get('recommendations', [])
        
        # Calculate statistics
        total_vulns = len(vulnerabilities)
        severity_counts = self._calculate_severity_counts(vulnerabilities)
        
        # Generate vulnerability rows
        vuln_rows = ""
        for i, vuln in enumerate(vulnerabilities):
            severity_class = self._get_severity_class(vuln.get('severity', 0))
            vuln_rows += f"""
            <tr class="{severity_class}">
                <td>{i + 1}</td>
                <td>{vuln.get('type', 'Unknown').upper()}</td>
                <td>{vuln.get('method', 'GET')}</td>
                <td>{vuln.get('severity', 0)}/5</td>
                <td>{(vuln.get('confidence', 0) * 100):.1f}%</td>
                <td><code>{vuln.get('payload', 'N/A')}</code></td>
                <td><a href="{vuln.get('url', '#')}" target="_blank">{vuln.get('url', 'N/A')}</a></td>
            </tr>
            """
        
        # Generate recommendations
        recommendations_html = ""
        for rec in recommendations:
            recommendations_html += f"<li>{rec}</li>"
        
        # Generate AI analysis section
        ai_analysis_html = ""
        if ai_analysis:
            ai_analysis_html = f"""
            <div class="ai-analysis">
                <h3><i class="fas fa-brain"></i> AI Analysis</h3>
                <p><strong>Anomaly Score:</strong> {ai_analysis.get('anomaly_score', 0):.2f}</p>
                <p><strong>Attack Patterns:</strong></p>
                <ul>
                    {''.join([f'<li>{pattern}</li>' for pattern in ai_analysis.get('attack_patterns', [])])}
                </ul>
            </div>
            """
        
        # Fill template
        html_content = html_template.format(
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target=summary.get('target', 'Unknown'),
            total_vulnerabilities=total_vulns,
            risk_level=summary.get('overall_risk', 'Low'),
            risk_score=summary.get('risk_score', 0),
            anomaly_score=ai_analysis.get('anomaly_score', 0),
            critical_count=severity_counts.get('critical', 0),
            high_count=severity_counts.get('high', 0),
            medium_count=severity_counts.get('medium', 0),
            low_count=severity_counts.get('low', 0),
            vulnerability_rows=vuln_rows,
            recommendations_html=recommendations_html,
            ai_analysis_html=ai_analysis_html
        )
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath
    
    def _generate_json_report(self, scan_results: Dict[str, Any], filepath: str) -> str:
        """Generate JSON report"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(scan_results, f, indent=2, ensure_ascii=False)
        return filepath
    
    def _generate_csv_report(self, scan_results: Dict[str, Any], filepath: str) -> str:
        """Generate CSV report"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['ID', 'Type', 'Method', 'Severity', 'Confidence', 'Payload', 'URL'])
            
            for i, vuln in enumerate(vulnerabilities):
                writer.writerow([
                    i + 1,
                    vuln.get('type', 'Unknown').upper(),
                    vuln.get('method', 'GET'),
                    vuln.get('severity', 0),
                    f"{(vuln.get('confidence', 0) * 100):.1f}%",
                    vuln.get('payload', 'N/A'),
                    vuln.get('url', 'N/A')
                ])
        
        return filepath
    
    def _generate_xml_report(self, scan_results: Dict[str, Any], filepath: str) -> str:
        """Generate XML report"""
        root = ET.Element("SecurityReport")
        
        # Add metadata
        metadata = ET.SubElement(root, "Metadata")
        ET.SubElement(metadata, "GeneratedDate").text = datetime.now().isoformat()
        ET.SubElement(metadata, "Target").text = scan_results.get('scan_summary', {}).get('target', 'Unknown')
        
        # Add summary
        summary = ET.SubElement(root, "Summary")
        vuln_count = len(scan_results.get('vulnerabilities', []))
        ET.SubElement(summary, "TotalVulnerabilities").text = str(vuln_count)
        ET.SubElement(summary, "RiskLevel").text = scan_results.get('scan_summary', {}).get('overall_risk', 'Low')
        ET.SubElement(summary, "RiskScore").text = str(scan_results.get('scan_summary', {}).get('risk_score', 0))
        
        # Add vulnerabilities
        vulnerabilities = ET.SubElement(root, "Vulnerabilities")
        for i, vuln in enumerate(scan_results.get('vulnerabilities', [])):
            vuln_elem = ET.SubElement(vulnerabilities, "Vulnerability", id=str(i + 1))
            ET.SubElement(vuln_elem, "Type").text = vuln.get('type', 'Unknown').upper()
            ET.SubElement(vuln_elem, "Method").text = vuln.get('method', 'GET')
            ET.SubElement(vuln_elem, "Severity").text = str(vuln.get('severity', 0))
            ET.SubElement(vuln_elem, "Confidence").text = str(vuln.get('confidence', 0))
            ET.SubElement(vuln_elem, "Payload").text = vuln.get('payload', 'N/A')
            ET.SubElement(vuln_elem, "URL").text = vuln.get('url', 'N/A')
        
        # Add recommendations
        recommendations = ET.SubElement(root, "Recommendations")
        for rec in scan_results.get('recommendations', []):
            ET.SubElement(recommendations, "Recommendation").text = rec
        
        # Write to file
        tree = ET.ElementTree(root)
        tree.write(filepath, encoding='utf-8', xml_declaration=True)
        
        return filepath
    
    def _generate_pdf_report(self, scan_results: Dict[str, Any], filepath: str) -> str:
        """Generate PDF report (simplified HTML to PDF conversion)"""
        # First generate HTML report
        html_filepath = filepath.replace('.pdf', '.html')
        self._generate_html_report(scan_results, html_filepath)
        
        # For now, we'll return the HTML file path as PDF generation requires additional libraries
        # In a production environment, you could use libraries like WeasyPrint or reportlab
        print(f"PDF generation requires additional libraries. HTML report generated at: {html_filepath}")
        return html_filepath
    
    def _get_html_template(self) -> str:
        """Get HTML template for reports"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid #007bff;
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #333;
        }}
        .summary-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #007bff;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: bold;
        }}
        .vulnerability-critical {{
            background-color: #f8d7da !important;
            color: #721c24 !important;
        }}
        .vulnerability-high {{
            background-color: #fff3cd !important;
            color: #856404 !important;
        }}
        .vulnerability-medium {{
            background-color: #d1ecf1 !important;
            color: #0c5460 !important;
        }}
        .vulnerability-low {{
            background-color: #d4edda !important;
            color: #155724 !important;
        }}
        .ai-analysis {{
            background: linear-gradient(135deg, #9b59b6, #8e44ad);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }}
        .recommendations {{
            background: linear-gradient(135deg, #1abc9c, #16a085);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }}
        code {{
            background: #f8f9fa;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Scan Report</h1>
            <p>Generated on: {scan_date}</p>
            <p>Target: {target}</p>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Total Vulnerabilities</h3>
                <div class="value">{total_vulnerabilities}</div>
            </div>
            <div class="summary-card">
                <h3>Risk Level</h3>
                <div class="value">{risk_level}</div>
            </div>
            <div class="summary-card">
                <h3>Risk Score</h3>
                <div class="value">{risk_score}/10</div>
            </div>
            <div class="summary-card">
                <h3>Anomaly Score</h3>
                <div class="value">{anomaly_score:.2f}</div>
            </div>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Critical</h3>
                <div class="value" style="color: #dc3545;">{critical_count}</div>
            </div>
            <div class="summary-card">
                <h3>High</h3>
                <div class="value" style="color: #fd7e14;">{high_count}</div>
            </div>
            <div class="summary-card">
                <h3>Medium</h3>
                <div class="value" style="color: #ffc107;">{medium_count}</div>
            </div>
            <div class="summary-card">
                <h3>Low</h3>
                <div class="value" style="color: #28a745;">{low_count}</div>
            </div>
        </div>

        {ai_analysis_html}

        <h2>🔍 Vulnerabilities</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Type</th>
                    <th>Method</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Payload</th>
                    <th>URL</th>
                </tr>
            </thead>
            <tbody>
                {vulnerability_rows}
            </tbody>
        </table>

        <div class="recommendations">
            <h3><i class="fas fa-lightbulb"></i> Recommendations</h3>
            <ol>
                {recommendations_html}
            </ol>
        </div>

        <div class="footer">
            <p>Generated by Advanced Security Tools</p>
            <p>For support and updates, visit our repository</p>
        </div>
    </div>
</body>
</html>
        """
    
    def _calculate_severity_counts(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Calculate vulnerability counts by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 0)
            if severity >= 4:
                counts['critical'] += 1
            elif severity >= 3:
                counts['high'] += 1
            elif severity >= 2:
                counts['medium'] += 1
            else:
                counts['low'] += 1
        
        return counts
    
    def _get_severity_class(self, severity: float) -> str:
        """Get CSS class for severity level"""
        if severity >= 4:
            return 'vulnerability-critical'
        elif severity >= 3:
            return 'vulnerability-high'
        elif severity >= 2:
            return 'vulnerability-medium'
        else:
            return 'vulnerability-low'
    
    def generate_batch_reports(self, scan_results: Dict[str, Any], 
                              formats: List[str]) -> List[str]:
        """
        Generate multiple report formats at once
        
        Args:
            scan_results: Complete scan results
            formats: List of formats to generate
            
        Returns:
            List of generated file paths
        """
        generated_files = []
        
        for format_type in formats:
            try:
                filepath = self.generate_report(scan_results, format_type)
                generated_files.append(filepath)
                print(f"✅ Generated {format_type.upper()} report: {filepath}")
            except Exception as e:
                print(f"❌ Error generating {format_type} report: {str(e)}")
        
        return generated_files


def main():
    """Main function for testing the reporting system"""
    try:
        # Sample scan results for testing
        sample_results = {
            'scan_summary': {
                'target': 'https://example.com',
                'start_time': '2024-01-01T10:00:00',
                'end_time': '2024-01-01T10:15:00',
                'duration': 900,
                'total_requests': 150,
                'successful_requests': 145,
                'failed_requests': 5,
                'overall_risk': 'Medium',
                'risk_score': 6.5
            },
            'vulnerabilities': [
                {
                    'type': 'xss',
                    'method': 'GET',
                    'url': 'https://example.com/search?q=<script>alert(1)</script>',
                    'payload': '<script>alert(1)</script>',
                    'severity': 3,
                    'confidence': 0.85,
                    'description': 'Reflected XSS vulnerability found'
                },
                {
                    'type': 'sql',
                    'method': 'POST',
                    'url': 'https://example.com/login',
                    'payload': "admin' OR '1'='1",
                    'severity': 4,
                    'confidence': 0.95,
                    'description': 'SQL Injection vulnerability in login form'
                }
            ],
            'ai_analysis': {
                'anomaly_score': 7.2,
                'attack_patterns': ['SQL Injection', 'XSS', 'Directory Traversal'],
                'risk_assessment': 'High risk detected with multiple attack vectors'
            },
            'recommendations': [
                'Implement input validation and sanitization',
                'Use parameterized queries to prevent SQL injection',
                'Implement Content Security Policy (CSP) headers',
                'Regular security audits and penetration testing'
            ]
        }
        
        # Initialize reporting system
        reporter = AdvancedReportingSystem()
        
        # Generate reports in multiple formats
        formats = ['html', 'json', 'csv', 'xml']
        generated_files = reporter.generate_batch_reports(sample_results, formats)
        
        print(f"\n📊 Generated {len(generated_files)} reports:")
        for file_path in generated_files:
            print(f"  - {file_path}")
        
    except Exception as e:
        print(f"❌ Error in reporting system: {str(e)}")


if __name__ == "__main__":
    main()