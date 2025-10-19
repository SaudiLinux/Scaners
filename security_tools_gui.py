#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
الواجهة الرسومية المتقدمة للأدوات الأمنية - Advanced Security Tools GUI v2.0
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import json
import os
from datetime import datetime

# استيراد الأدوات الأمنية
from intelligent_security_scanner_v3 import AdvancedIntelligentScanner
from advanced_reporting_system import AdvancedReportingSystem

class SecurityToolsGUI:
    """الواجهة الرسومية المتقدمة للأدوات الأمنية"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🛡️ الأدوات الأمنية المتقدمة - Advanced Security Tools")
        self.root.geometry("1200x800")
        
        # تكوين الأنماط
        self.setup_styles()
        
        # تهيئة الأدوات
        self.scanner = AdvancedIntelligentScanner()
        self.reporter = AdvancedReportingSystem()
        
        # متغيرات التطبيق
        self.current_scan_results = None
        self.scan_thread = None
        
        # إنشاء الواجهة
        self.create_widgets()
        
    def setup_styles(self):
        """إعداد أنماط الواجهة"""
        style = ttk.Style()
        
        # تكوين الألوان
        self.colors = {
            'primary': '#2c3e50',
            'secondary': '#3498db',
            'success': '#27ae60',
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'light': '#ecf0f1',
            'dark': '#34495e'
        }
        
        # تكوين أنماط ttk
        style.theme_use('clam')
        style.configure('TFrame', background=self.colors['light'])
        style.configure('TLabel', background=self.colors['light'], foreground=self.colors['primary'])
        style.configure('TButton', background=self.colors['secondary'], foreground='white')
        style.configure('Success.TButton', background=self.colors['success'], foreground='white')
        style.configure('Warning.TButton', background=self.colors['warning'], foreground='white')
        style.configure('Danger.TButton', background=self.colors['danger'], foreground='white')
        
    def create_widgets(self):
        """إنشاء عناصر الواجهة"""
        # الإطار الرئيسي
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # تكوين شبكة الإطار الرئيسي
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=2)
        main_frame.rowconfigure(1, weight=1)
        
        # العنوان
        title_label = ttk.Label(main_frame, text="🛡️ الأدوات الأمنية المتقدمة", 
                               font=('Arial', 24, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # لوحة التحكم اليسرى
        self.create_control_panel(main_frame)
        
        # منطقة العرض اليمنى
        self.create_display_area(main_frame)
        
        # شريط الحالة
        self.status_bar = ttk.Label(self.root, text="جاهز للاستخدام", relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def create_control_panel(self, parent):
        """إنشاء لوحة التحكم"""
        control_frame = ttk.LabelFrame(parent, text="لوحة التحكم", padding="15")
        control_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        # إطار إدخال الهدف
        target_frame = ttk.LabelFrame(control_frame, text="إعدادات الفحص", padding="10")
        target_frame.pack(fill=tk.X, pady=(0, 15))
        
        # حقل إدخال الهدف
        ttk.Label(target_frame, text="الهدف:").pack(anchor=tk.W)
        self.target_entry = ttk.Entry(target_frame, width=40)
        self.target_entry.pack(fill=tk.X, pady=(0, 10))
        self.target_entry.insert(0, "https://example.com")
        
        # أنواع الفحص
        scan_types_frame = ttk.LabelFrame(target_frame, text="أنواع الفحص", padding="10")
        scan_types_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.scan_types = {
            'xss': tk.BooleanVar(value=True),
            'sql': tk.BooleanVar(value=True),
            'lfi': tk.BooleanVar(value=True),
            'command': tk.BooleanVar(value=True),
            'xxe': tk.BooleanVar(value=False),
            'nosql': tk.BooleanVar(value=False),
            'ssrf': tk.BooleanVar(value=False),
            'ssti': tk.BooleanVar(value=False),
            'graphql': tk.BooleanVar(value=False)
        }
        
        # إنشاء خانات الاختيار
        for i, (scan_type, var) in enumerate(self.scan_types.items()):
            cb = ttk.Checkbutton(scan_types_frame, text=scan_type.upper(), variable=var)
            cb.grid(row=i//3, column=i%3, sticky=tk.W, padx=5, pady=2)
        
        # إعدادات متقدمة
        advanced_frame = ttk.LabelFrame(control_frame, text="إعدادات متقدمة", padding="10")
        advanced_frame.pack(fill=tk.X, pady=(0, 15))
        
        # عدد المؤشرات
        ttk.Label(advanced_frame, text="عدد المؤشرات:").pack(anchor=tk.W)
        self.threads_var = tk.IntVar(value=10)
        threads_spin = ttk.Spinbox(advanced_frame, from_=1, to=50, textvariable=self.threads_var)
        threads_spin.pack(fill=tk.X, pady=(0, 10))
        
        # أزرار التحكم
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X)
        
        # زر البدء
        self.start_button = ttk.Button(button_frame, text="🚀 بدء الفحص", 
                                      command=self.start_scan, style='Success.TButton')
        self.start_button.pack(fill=tk.X, pady=(0, 5))
        
        # زر الإيقاف
        self.stop_button = ttk.Button(button_frame, text="⏹️ إيقاف", 
                                     command=self.stop_scan, style='Danger.TButton')
        self.stop_button.pack(fill=tk.X, pady=(0, 5))
        self.stop_button.config(state=tk.DISABLED)
        
        # زر التقرير
        self.report_button = ttk.Button(button_frame, text="📊 توليد تقرير", 
                                       command=self.generate_report)
        self.report_button.pack(fill=tk.X, pady=(0, 5))
        self.report_button.config(state=tk.DISABLED)
        
        # إطار التقارير
        report_frame = ttk.LabelFrame(control_frame, text="خيارات التقرير", padding="10")
        report_frame.pack(fill=tk.X)
        
        self.report_formats = {
            'HTML': tk.BooleanVar(value=True),
            'JSON': tk.BooleanVar(value=True),
            'CSV': tk.BooleanVar(value=False)
        }
        
        for i, (format_name, var) in enumerate(self.report_formats.items()):
            cb = ttk.Checkbutton(report_frame, text=format_name, variable=var)
            cb.grid(row=i//2, column=i%2, sticky=tk.W, padx=5, pady=2)
        
    def create_display_area(self, parent):
        """إنشاء منطقة العرض"""
        display_frame = ttk.LabelFrame(parent, text="نتائج الفحص", padding="15")
        display_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # إنشاء notebook للتبويبات
        self.notebook = ttk.Notebook(display_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # تبويب النتائج
        self.results_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.results_frame, text="📝 النتائج")
        
        # منطقة النص للنتائج
        self.results_text = scrolledtext.ScrolledText(self.results_frame, wrap=tk.WORD, 
                                                     width=70, height=25)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # تبويب الإحصائيات
        self.stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_frame, text="📈 الإحصائيات")
        
        # إطار الإحصائيات
        stats_container = ttk.Frame(self.stats_frame)
        stats_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # متغيرات الإحصائيات
        self.stats_vars = {}
        stats_labels = [
            ('إجمالي الثغرات', '0'),
            ('مستوى المخاطر', 'غير محدد'),
            ('درجة المخاطر', '0/10'),
            ('درجة الشذوذ', '0.0'),
            ('أنواع الثغرات', '0')
        ]
        
        for i, (label, default_value) in enumerate(stats_labels):
            frame = ttk.Frame(stats_container)
            frame.pack(fill=tk.X, pady=5)
            
            ttk.Label(frame, text=f"{label}:", font=('Arial', 12, 'bold')).pack(side=tk.LEFT)
            self.stats_vars[label] = tk.StringVar(value=default_value)
            ttk.Label(frame, textvariable=self.stats_vars[label], 
                     font=('Arial', 12)).pack(side=tk.RIGHT)
        
        # تبويب السجل
        self.log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.log_frame, text="📝 السجل")
        
        self.log_text = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD, 
                                                 width=70, height=25)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
    def log_message(self, message):
        """إضافة رسالة إلى السجل"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        
        # تحديث شريط الحالة
        self.status_bar.config(text=message)
        
    def get_selected_scan_types(self):
        """الحصول على أنواع الفحص المحددة"""
        return [scan_type for scan_type, var in self.scan_types.items() if var.get()]
        
    def start_scan(self):
        """بدء الفحص الأمني"""
        target = self.target_entry.get().strip()
        
        if not target:
            messagebox.showwarning("تحذير", "يرجى إدخال هدف للفحص")
            return
        
        selected_types = self.get_selected_scan_types()
        if not selected_types:
            messagebox.showwarning("تحذير", "يرجى اختيار نوع واحد على الأقل للفحص")
            return
        
        # تعطيل زر البدء وتفعيل زر الإيقاف
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.report_button.config(state=tk.DISABLED)
        
        # مسح النتائج السابقة
        self.results_text.delete(1.0, tk.END)
        self.log_message(f"بدء الفحص الأمني لـ {target}")
        self.log_message(f"أنواع الفحص المحددة: {', '.join(selected_types)}")
        
        # بدء الفحص في خيط منفصل
        self.scan_thread = threading.Thread(target=self.run_scan, args=(target, selected_types))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def run_scan(self, target, scan_types):
        """تشغيل الفحص في خيط منفصل"""
        try:
            # تشغيل الماسح الذكي
            self.log_message("جارٍ تشغيل الماسح الذكي...")
            
            scan_results = self.scanner.intelligent_scan(
                target, 
                scan_types=scan_types,
                max_threads=self.threads_var.get()
            )
            
            # حفظ النتائج
            self.current_scan_results = scan_results
            
            # عرض النتائج
            self.display_results(scan_results)
            
            # تحديث الإحصائيات
            self.update_statistics(scan_results)
            
            self.log_message("تم إكمال الفحص بنجاح")
            
        except Exception as e:
            self.log_message(f"خطأ في الفحص: {str(e)}")
            messagebox.showerror("خطأ", f"حدث خطأ أثناء الفحص: {str(e)}")
        
        finally:
            # إعادة تعيين الأزرار
            self.root.after(0, self.reset_buttons)
            
    def stop_scan(self):
        """إيقاف الفحص"""
        if self.scan_thread and self.scan_thread.is_alive():
            self.log_message("جارٍ إيقاف الفحص...")
            # ملاحظة: لا يمكن إيقاف الخيط بشكل آمن في Python
            # سيتم إكمال الفحص الحالي فقط
            
    def reset_buttons(self):
        """إعادة تعيين حالة الأزرار"""
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        if self.current_scan_results:
            self.report_button.config(state=tk.NORMAL)
        
    def display_results(self, results):
        """عرض نتائج الفحص"""
        def update_display():
            self.results_text.delete(1.0, tk.END)
            
            # عرض الملخص
            summary = results.get('scan_summary', {})
            self.results_text.insert(tk.END, "=" * 50 + "\n")
            self.results_text.insert(tk.END, "📊 الملخص التنفيذي\n")
            self.results_text.insert(tk.END, "=" * 50 + "\n")
            self.results_text.insert(tk.END, f"الهدف: {summary.get('target', 'غير محدد')}\n")
            self.results_text.insert(tk.END, f"تاريخ الفحص: {summary.get('scan_time', 'غير محدد')}\n")
            self.results_text.insert(tk.END, f"إجمالي الثغرات: {len(results.get('vulnerabilities', []))}\n")
            
            # عرض تحليل الذكاء الاصطناعي
            ai_analysis = results.get('ai_analysis', {})
            if ai_analysis:
                self.results_text.insert(tk.END, "\n" + "=" * 50 + "\n")
                self.results_text.insert(tk.END, "🤖 تحليلات الذكاء الاصطناعي\n")
                self.results_text.insert(tk.END, "=" * 50 + "\n")
                self.results_text.insert(tk.END, f"درجة الشذوذ: {ai_analysis.get('anomaly_score', 0):.2f}\n")
                
                if ai_analysis.get('attack_patterns'):
                    self.results_text.insert(tk.END, "أنماط الهجمات المكتشفة:\n")
                    for pattern in ai_analysis['attack_patterns']:
                        self.results_text.insert(tk.END, f"  • {pattern}\n")
            
            # عرض الثغرات
            vulnerabilities = results.get('vulnerabilities', [])
            if vulnerabilities:
                self.results_text.insert(tk.END, "\n" + "=" * 50 + "\n")
                self.results_text.insert(tk.END, "🎯 الثغرات المكتشفة\n")
                self.results_text.insert(tk.END, "=" * 50 + "\n")
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    self.results_text.insert(tk.END, f"\nثغرة #{i}:\n")
                    self.results_text.insert(tk.END, f"  النوع: {vuln.get('type', 'غير محدد').upper()}\n")
                    self.results_text.insert(tk.END, f"  الطريقة: {vuln.get('method', 'غير محدد')}\n")
                    self.results_text.insert(tk.END, f"  الشدة: {vuln.get('severity', 0)}/5\n")
                    self.results_text.insert(tk.END, f"  الثقة: {vuln.get('confidence', 0)*100:.0f}%\n")
                    self.results_text.insert(tk.END, f"  الحمولة: {vuln.get('payload', 'غير محدد')}\n")
                    self.results_text.insert(tk.END, f"  الرابط: {vuln.get('url', 'غير محدد')}\n")
                    self.results_text.insert(tk.END, "-" * 30 + "\n")
            
            # عرض التوصيات
            recommendations = results.get('recommendations', [])
            if recommendations:
                self.results_text.insert(tk.END, "\n" + "=" * 50 + "\n")
                self.results_text.insert(tk.END, "💡 التوصيات\n")
                self.results_text.insert(tk.END, "=" * 50 + "\n")
                
                for i, rec in enumerate(recommendations, 1):
                    self.results_text.insert(tk.END, f"{i}. {rec}\n")
        
        # تشغيل في الخيط الرئيسي
        self.root.after(0, update_display)
        
    def update_statistics(self, results):
        """تحديث الإحصائيات"""
        def update_stats():
            summary = results.get('scan_summary', {})
            ai_analysis = results.get('ai_analysis', {})
            
            self.stats_vars['إجمالي الثغرات'].set(str(len(results.get('vulnerabilities', []))))
            self.stats_vars['مستوى المخاطر'].set(summary.get('overall_risk', 'غير محدد'))
            self.stats_vars['درجة المخاطر'].set(f"{summary.get('risk_score', 0):.1f}/10")
            self.stats_vars['درجة الشذوذ'].set(f"{ai_analysis.get('anomaly_score', 0):.2f}")
            
            vuln_types = ai_analysis.get('vulnerability_types', {})
            self.stats_vars['أنواع الثغرات'].set(str(len(vuln_types)))
        
        # تشغيل في الخيط الرئيسي
        self.root.after(0, update_stats)
        
    def generate_report(self):
        """توليد التقرير"""
        if not self.current_scan_results:
            messagebox.showwarning("تحذير", "لا توجد نتائج للتقرير")
            return
        
        # اختيار مجلد الحفظ
        output_dir = filedialog.askdirectory(title="اختر مجلد حفظ التقارير")
        if not output_dir:
            return
        
        # الحصول على الصيغ المحددة
        selected_formats = [fmt for fmt, var in self.report_formats.items() if var.get()]
        if not selected_formats:
            messagebox.showwarning("تحذير", "يرجى اختيار صيغة واحدة على الأقل")
            return
        
        self.log_message("جارٍ توليد التقارير...")
        
        try:
            # توليد التقارير
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"security_report_{timestamp}"
            
            success, reports = self.reporter.generate_comprehensive_report(
                self.current_scan_results, output_dir, base_filename
            )
            
            if success:
                self.log_message("تم توليد التقارير بنجاح:")
                for format_type, file_path in reports.items():
                    self.log_message(f"  📄 {format_type.upper()}: {file_path}")
                
                messagebox.showinfo("نجاح", "تم توليد التقارير بنجاح!")
            else:
                messagebox.showerror("خطأ", f"خطأ في توليد التقارير: {reports}")
                
        except Exception as e:
            self.log_message(f"خطأ في توليد التقرير: {str(e)}")
            messagebox.showerror("خطأ", f"خطأ في توليد التقرير: {str(e)}")
        
    def run(self):
        """تشغيل التطبيق"""
        self.log_message("تم تشغيل الأدوات الأمنية المتقدمة")
        self.log_message("النظام جاهز لبدء الفحص")
        
        self.root.mainloop()

# دالة تشغيل الواجهة الرسومية
def run_gui():
    """تشغيل الواجهة الرسومية"""
    try:
        app = SecurityToolsGUI()
        app.run()
    except ImportError as e:
        print(f"خطأ في استيراد المكتبات: {e}")
        print("يرجى التأكد من تثبيت المكتبات المطلوبة:")
        print("pip install tkinter")
    except Exception as e:
        print(f"خطأ في تشغيل الواجهة الرسومية: {e}")

if __name__ == "__main__":
    run_gui()