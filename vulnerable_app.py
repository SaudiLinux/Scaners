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
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        email TEXT
    )''')
    
    # Insert sample data
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@vulnerable.local')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user1', 'password1', 'user1@vulnerable.local')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (3, 'user2', 'password2', 'user2@vulnerable.local')")
    
    conn.commit()
    conn.close()

# Vulnerable routes for demonstration

@app.route('/')
def index():
    """Main page with links to vulnerable endpoints"""
    return '''
    <h1>Vulnerable Web Application (Educational)</h1>
    <p>⚠️ This application contains intentional vulnerabilities for educational purposes only!</p>
    
    <h2>Vulnerable Endpoints:</h2>
    <ul>
        <li><a href="/search?q=test">Search (XSS)</a></li>
        <li><a href="/user?id=1">User Profile (SQL Injection)</a></li>
        <li><a href="/include?file=test.txt">File Viewer (LFI)</a></li>
        <li><a href="/execute?cmd=ls">Command Executor (Command Injection)</a></li>
        <li><a href="/fetch?url=http://example.com">URL Fetcher (SSRF)</a></li>
    </ul>
    
    <h3>Test Parameters:</h3>
    <p>Try these payloads to see vulnerabilities in action:</p>
    <ul>
        <li>XSS: <code>?q=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
        <li>SQL Injection: <code>?id=1' UNION SELECT 1,2,3,4--</code></li>
        <li>LFI: <code>?file=../../../../etc/passwd</code></li>
        <li>Command Injection: <code>?cmd=id; whoami</code></li>
        <li>SSRF: <code>?url=http://localhost:80</code></li>
    </ul>
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

if __name__ == '__main__':
    print("🚨 Starting Vulnerable Web Application for Educational Purposes!")
    print("⚠️  WARNING: This application contains intentional vulnerabilities!")
    print("🔒 Only run this in a controlled, isolated environment!")
    print("\n📋 Available vulnerable endpoints:")
    print("  • /user?id=1 (SQL Injection)")
    print("  • /search?q=test (XSS)")
    print("  • /include?file=test.txt (LFI)")
    print("  • /execute?cmd=ls (Command Injection)")
    print("  • /fetch?url=http://example.com (SSRF)")
    print("\n🌐 Starting server on http://127.0.0.1:5000")
    
    init_db()
    app.run(host='127.0.0.1', port=5000, debug=True)