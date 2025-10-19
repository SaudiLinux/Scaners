def main():
    """الدالة الرئيسية"""
    
    print("🚀 بدء تشغيل الفاحص الأمني المتقدم")
    print("=" * 60)
    
    # إنشاء مثيل الفاحص
    scanner = AdvancedSecurityScanner()
    
    # إعدادات الفحص
    target_url = "https://dxp.salam.sa/test.php"
    scan_type = "all"  # all, web, api, xss, sql, lfi, command, xxe, graphql, nosql
    stealth_level = 5  # 1-5
    threads = 10
    
    print(f"🎯 الهدف: {target_url}")
    print(f"🔍 نوع الفحص: {scan_type}")
    print(f"🛡️ مستوى التخفي: {stealth_level}")
    print(f"⚡ عدد الخيوط: {threads}")
    print("-" * 60)
    
    try:
        # تنفيذ الفحص
        print("🔄 بدء الفحص...")
        results = scanner.scan_with_stealth(target_url, scan_type, stealth_level, threads)
        
        # حفظ التقارير
        print("💾 حفظ التقارير...")
        json_report = scanner.save_report(results)
        html_report = scanner.generate_html_report(results)
        
        # عرض الملخص
        print("\n📊 ملخص الفحص:")
        print(f"✅ إجمالي الاختبارات: {results['statistics']['total_tests']}")
        print(f"⚠️ الثغرات المكتشفة: {results['statistics']['total_vulnerabilities']}")
        print(f"🎯 نجاحات التخطي: {results['statistics']['bypass_successes']}")
        print(f"📈 نسبة النجاح: {results['statistics']['success_rate']:.1f}%")
        print(f"⏱️ وقت الفحص: {results['start_time']} - {results['end_time']}")
        
        print(f"\n📄 تم حفظ التقارير:")
        print(f"📋 JSON: {json_report}")
        print(f"🌐 HTML: {html_report}")
        
        print("\n✅ اكتمل الفحص بنجاح!")
        
    except Exception as e:
        print(f"❌ خطأ أثناء الفحص: {e}")
        import traceback
        traceback.print_exc()