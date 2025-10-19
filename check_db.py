#!/usr/bin/env python3
"""
Enhanced Database Checker - Views the enhanced vulnerable database structure
"""

import sqlite3
import json

def check_enhanced_database():
    """Check the enhanced vulnerable database"""
    try:
        # Connect to the enhanced database
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()

        print("📊 Enhanced Vulnerable Database Status")
        print("=" * 50)

        # Get all tables
        cursor.execute('SELECT name FROM sqlite_master WHERE type="table"')
        tables = cursor.fetchall()

        print(f"📋 Total Tables: {len(tables)}")
        print("\nTable List:")
        
        for table in tables:
            table_name = table[0]
            print(f"\n🔍 {table_name.upper()}:")
            
            # Get column info
            cursor.execute(f'PRAGMA table_info({table_name})')
            columns = cursor.fetchall()
            print(f"  Columns: {[col[1] for col in columns]}")
            
            # Get row count
            cursor.execute(f'SELECT COUNT(*) FROM {table_name}')
            count = cursor.fetchone()[0]
            print(f"  Rows: {count}")
            
            # Get sample data
            cursor.execute(f'SELECT * FROM {table_name} LIMIT 2')
            rows = cursor.fetchall()
            if rows:
                print("  Sample Data:")
                for i, row in enumerate(rows):
                    print(f"    Row {i+1}: {row}")

        # Check for vulnerable data
        print("\n🚨 Vulnerable Data Analysis:")
        
        # Check for weak passwords
        cursor.execute('SELECT username, password FROM users WHERE password IN ("password123", "admin123", "123456", "password")')
        weak_passwords = cursor.fetchall()
        if weak_passwords:
            print(f"  ⚠️  Weak passwords found: {len(weak_passwords)}")
            for user, pwd in weak_passwords[:3]:
                print(f"    {user}: {pwd}")
        
        # Check for XSS payloads
        cursor.execute('SELECT user_id, comment FROM comments WHERE comment LIKE "%<%" OR comment LIKE "%script%"')
        xss_payloads = cursor.fetchall()
        if xss_payloads:
            print(f"  ⚠️  Potential XSS payloads in comments: {len(xss_payloads)}")
        
        # Check for credit card data
        cursor.execute('SELECT COUNT(*) FROM credit_cards')
        cc_count = cursor.fetchone()[0]
        print(f"  💳 Credit cards stored: {cc_count}")
        
        # Check for SQL injection attempts
        cursor.execute('SELECT COUNT(*) FROM search_history WHERE search_query LIKE "%UNION%" OR search_query LIKE "%SELECT%" OR search_query LIKE "%DROP%"')
        injection_attempts = cursor.fetchone()[0]
        print(f"  🔍 SQL injection attempts logged: {injection_attempts}")

        conn.close()
        
        print("\n✅ Enhanced vulnerable database is ready for testing!")
        print("🎯 Use the new API endpoints for advanced vulnerability testing")
        
    except Exception as e:
        print(f"❌ Error checking database: {e}")

if __name__ == "__main__":
    check_enhanced_database()