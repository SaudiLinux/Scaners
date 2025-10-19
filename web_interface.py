#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
الواجهة الويب المتقدمة للأدوات الأمنية - Advanced Security Tools Web Interface v1.0
"""

from flask import Flask, render_template, request, jsonify, send_file
import json
import os
from datetime import datetime
import threading
from intelligent_security_scanner_v3 import AdvancedIntelligentScanner
from advanced_reporting_system import AdvancedReportingSystem

app = Flask(__name__)

# تهيئة الأدوات
scanner = AdvancedIntelligentScanner()
reporter = AdvancedReportingSystem()

# متغيرات التطبيق
scan_results = {}
current_scan_thread = None

@app.route('/')
def index():
    """الصفحة الرئيسية"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    """بدء الفحص الأمني"""
    global scan_results, current_scan_thread
    
    data = request.json
    target = data.get('target', '').strip()
    scan_types = data.get('scan_types', ['xss', 'sql', 'lfi'])
    threads = data.get('threads', 10)
    
    if not target:
        return jsonify({'error': 'يرجى إدخال هدف صالح'}), 400
    
    # بدء الفحص في خيط منفصل
    def run_scan():
        global scan_results
        try:
            results = scanner.intelligent_scan(
                target, 
                scan_types=scan_types,
                max_threads=threads
            )
            scan_results = results
        except Exception as e:
            scan_results = {'error': str(e)}
    
    current_scan_thread = threading.Thread(target=run_scan)
    current_scan_thread.start()
    
    return jsonify({'message': 'تم بدء الفحص بنجاح', 'status': 'running'})

@app.route('/scan_status')
def scan_status():
    """التحقق من حالة الفحص"""
    if current_scan_thread and current_scan_thread.is_alive():
        return jsonify({'status': 'running'})
    elif scan_results:
        if 'error' in scan_results:
            return jsonify({'status': 'error', 'message': scan_results['error']})
        else:
            return jsonify({'status': 'completed', 'results': scan_results})
    else:
        return jsonify({'status': 'idle'})

@app.route('/results')
def get_results():
    """الحصول على نتائج الفحص"""
    if scan_results:
        return jsonify(scan_results)
    return jsonify({'error': 'لا توجد نتائج'}), 404

@app.route('/generate_report', methods=['POST'])
def generate_report():
    """توليد تقرير"""
    if not scan_results or 'error' in scan_results:
        return jsonify({'error': 'لا توجد نتائج صالحة للتقرير'}), 400
    
    data = request.json
    report_format = data.get('format', 'html')
    
    try:
        # توليد التقرير
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}"
        
        if report_format == 'html':
            success, report_path = reporter.generate_html_report(scan_results, "reports", filename)
        elif report_format == 'json':
            success, report_path = reporter.generate_json_report(scan_results, "reports", filename)
        elif report_format == 'csv':
            success, report_path = reporter.generate_csv_report(scan_results, "reports", filename)
        else:
            return jsonify({'error': 'صيغة تقرير غير مدعومة'}), 400
        
        if success:
            return jsonify({'message': 'تم توليد التقرير بنجاح', 'file': report_path})
        else:
            return jsonify({'error': f'خطأ في توليد التقرير: {report_path}'}), 500
            
    except Exception as e:
        return jsonify({'error': f'خطأ في توليد التقرير: {str(e)}'}), 500

@app.route('/download_report/<filename>')
def download_report(filename):
    """تحميل التقرير"""
    try:
        return send_file(f"reports/{filename}", as_attachment=True)
    except FileNotFoundError:
        return jsonify({'error': 'الملف غير موجود'}), 404

@app.route('/api/scan_types')
def get_scan_types():
    """الحصول على أنواع الفحص المتاحة"""
    return jsonify({
        'scan_types': [
            {'id': 'xss', 'name': 'XSS', 'description': 'Cross-Site Scripting'},
            {'id': 'sql', 'name': 'SQL Injection', 'description': 'SQL Injection'},
            {'id': 'lfi', 'name': 'LFI', 'description': 'Local File Inclusion'},
            {'id': 'command', 'name': 'Command Injection', 'description': 'Command Injection'},
            {'id': 'xxe', 'name': 'XXE', 'description': 'XML External Entity'},
            {'id': 'nosql', 'name': 'NoSQL', 'description': 'NoSQL Injection'},
            {'id': 'ssrf', 'name': 'SSRF', 'description': 'Server-Side Request Forgery'},
            {'id': 'ssti', 'name': 'SSTI', 'description': 'Server-Side Template Injection'},
            {'id': 'graphql', 'name': 'GraphQL', 'description': 'GraphQL Injection'}
        ]
    })

if __name__ == '__main__':
    # إنشاء مجلد التقارير إذا لم يكن موجوداً
    os.makedirs('reports', exist_ok=True)
    
    print("🚀 تشغيل الواجهة الويب للأدوات الأمنية المتقدمة")
    print("📍 فتح المتصفح على: http://localhost:5000")
    
    app.run(debug=True, host='0.0.0.0', port=5000)