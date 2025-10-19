#!/usr/bin/env python3

"""
Enhanced Vulnerable Database Setup
Creates a comprehensive vulnerable database with multiple tables and vulnerability scenarios
"""

import sqlite3
import hashlib
import datetime
import random
import json

def create_enhanced_database():
    """Create an enhanced vulnerable database with multiple tables"""
    
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # Drop existing tables
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('DROP TABLE IF EXISTS products')
    cursor.execute('DROP TABLE IF EXISTS orders')
    cursor.execute('DROP TABLE IF EXISTS comments')
    cursor.execute('DROP TABLE IF EXISTS sessions')
    cursor.execute('DROP TABLE IF EXISTS admin_logs')
    cursor.execute('DROP TABLE IF EXISTS credit_cards')
    cursor.execute('DROP TABLE IF EXISTS user_profiles')
    
    # 1. Users table with weak password storage
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    ''')
    
    # 2. Products table for e-commerce simulation
    cursor.execute('''
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            category TEXT,
            stock_quantity INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 3. Orders table with sensitive data
    cursor.execute('''
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            total_price REAL,
            shipping_address TEXT,
            credit_card_last4 TEXT,
            order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    ''')
    
    # 4. Comments table for XSS testing
    cursor.execute('''
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            comment TEXT,
            rating INTEGER CHECK (rating >= 1 AND rating <= 5),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_approved INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    ''')
    
    # 5. Sessions table for session management vulnerabilities
    cursor.execute('''
        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            session_token TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # 6. Admin logs for information disclosure
    cursor.execute('''
        CREATE TABLE admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            action TEXT,
            target_user_id INTEGER,
            details TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_id) REFERENCES users(id),
            FOREIGN KEY (target_user_id) REFERENCES users(id)
        )
    ''')
    
    # 7. Credit cards table (simulated)
    cursor.execute('''
        CREATE TABLE credit_cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            card_number TEXT,
            card_holder TEXT,
            expiry_month INTEGER,
            expiry_year INTEGER,
            cvv TEXT,
            billing_address TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # 8. User profiles with sensitive information
    cursor.execute('''
        CREATE TABLE user_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE,
            full_name TEXT,
            date_of_birth DATE,
            phone_number TEXT,
            address TEXT,
            city TEXT,
            country TEXT,
            postal_code TEXT,
            security_question TEXT,
            security_answer TEXT,
            profile_picture TEXT,
            bio TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Insert sample data
    
    # Users with weak passwords
    users_data = [
        ('admin', 'admin123', 'admin@vulnerable.local', 'admin'),
        ('administrator', 'password', 'admin@company.com', 'admin'),
        ('root', 'toor', 'root@system.local', 'admin'),
        ('user1', 'password123', 'user1@email.com', 'user'),
        ('john_doe', 'john123', 'john@example.com', 'user'),
        ('jane_smith', 'jane456', 'jane@example.com', 'user'),
        ('test_user', 'test', 'test@test.com', 'user'),
        ('guest', 'guest', 'guest@guest.com', 'guest'),
        ('demo', 'demo123', 'demo@demo.com', 'user'),
        ('support', 'support123', 'support@help.com', 'support')
    ]
    
    cursor.executemany('''
        INSERT INTO users (username, password, email, role) 
        VALUES (?, ?, ?, ?)
    ''', users_data)
    
    # Products
    products_data = [
        ('iPhone 14 Pro', 'Latest Apple smartphone with advanced features', 999.99, 'Electronics', 50),
        ('MacBook Pro 16"', 'High-performance laptop for professionals', 2499.99, 'Electronics', 25),
        ('AirPods Pro', 'Wireless earbuds with noise cancellation', 249.99, 'Electronics', 100),
        ('iPad Air', 'Versatile tablet for work and entertainment', 599.99, 'Electronics', 75),
        ('Apple Watch Series 8', 'Smartwatch with health monitoring', 399.99, 'Electronics', 60),
        ('Samsung Galaxy S23', 'Android flagship smartphone', 899.99, 'Electronics', 40),
        ('Sony WH-1000XM5', 'Premium noise-canceling headphones', 399.99, 'Electronics', 30),
        ('Dell XPS 13', 'Ultra-portable Windows laptop', 1299.99, 'Electronics', 20),
        ('Nintendo Switch', 'Portable gaming console', 299.99, 'Gaming', 80),
        ('PlayStation 5', 'Next-generation gaming console', 499.99, 'Gaming', 15)
    ]
    
    cursor.executemany('''
        INSERT INTO products (name, description, price, category, stock_quantity) 
        VALUES (?, ?, ?, ?, ?)
    ''', products_data)
    
    # Orders with sensitive data
    orders_data = [
        (1, 1, 1, 999.99, '123 Main St, Anytown, USA', '1234', 'completed'),
        (2, 2, 1, 2499.99, '456 Oak Ave, Somewhere, USA', '5678', 'shipped'),
        (3, 3, 2, 499.98, '789 Pine Rd, Nowhere, USA', '9012', 'processing'),
        (4, 4, 1, 599.99, '321 Elm St, Anywhere, USA', '3456', 'pending'),
        (5, 5, 1, 399.99, '654 Maple Dr, Everywhere, USA', '7890', 'completed')
    ]
    
    cursor.executemany('''
        INSERT INTO orders (user_id, product_id, quantity, total_price, shipping_address, credit_card_last4, status) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', orders_data)
    
    # Comments for XSS testing
    comments_data = [
        (1, 1, 'Great product! Highly recommend it.', 5, 1),
        (2, 1, 'Amazing phone with excellent camera quality.', 5, 1),
        (3, 2, 'Perfect for my development work. Fast and reliable.', 5, 1),
        (4, 3, 'Sound quality is incredible!', 4, 1),
        (5, 4, 'Love the screen size and battery life.', 4, 1),
        (1, 5, 'This is <script>alert("XSS")</script> a test!', 1, 0),  # XSS payload
        (2, 6, 'Check this out: <img src=x onerror=alert("XSS")>', 2, 0),  # XSS payload
        (3, 7, 'Normal comment without any issues.', 3, 1)
    ]
    
    cursor.executemany('''
        INSERT INTO comments (user_id, product_id, comment, rating, is_approved) 
        VALUES (?, ?, ?, ?, ?)
    ''', comments_data)
    
    # Sessions
    sessions_data = [
        (1, 'abc123def456', '192.168.1.100', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 
         datetime.datetime.now() + datetime.timedelta(days=7)),
        (2, 'def456ghi789', '192.168.1.101', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 
         datetime.datetime.now() + datetime.timedelta(days=7)),
        (3, 'ghi789jkl012', '192.168.1.102', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36', 
         datetime.datetime.now() + datetime.timedelta(days=1))
    ]
    
    cursor.executemany('''
        INSERT INTO sessions (user_id, session_token, ip_address, user_agent, expires_at) 
        VALUES (?, ?, ?, ?, ?)
    ''', sessions_data)
    
    # Admin logs
    logs_data = [
        (1, 'user_ban', 5, 'Banned user for suspicious activity', '192.168.1.1'),
        (1, 'password_reset', 2, 'Reset password for user', '192.168.1.1'),
        (1, 'admin_access', 1, 'Accessed admin panel', '192.168.1.1'),
        (2, 'user_edit', 3, 'Modified user profile', '192.168.1.2'),
        (1, 'system_backup', None, 'Performed system backup', '192.168.1.1')
    ]
    
    cursor.executemany('''
        INSERT INTO admin_logs (admin_id, action, target_user_id, details, ip_address) 
        VALUES (?, ?, ?, ?, ?)
    ''', logs_data)
    
    # Credit cards (simulated)
    credit_cards_data = [
        (1, '4532123456789012', 'John Admin', 12, 2025, '123', '123 Admin St, Admin City', 1),
        (2, '5555444433332222', 'Jane Administrator', 6, 2024, '456', '456 Admin Ave, Admin Town', 1),
        (3, '4111111111111111', 'Bob Root', 3, 2026, '789', '789 Root Rd, Root City', 1),
        (4, '378282246310005', 'Alice User', 9, 2023, '321', '321 User Ln, User Town', 0),
        (5, '6011111111111117', 'Charlie Demo', 11, 2027, '654', '654 Demo Dr, Demo City', 1)
    ]
    
    cursor.executemany('''
        INSERT INTO credit_cards (user_id, card_number, card_holder, expiry_month, expiry_year, cvv, billing_address, is_active) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', credit_cards_data)
    
    # User profiles
    profiles_data = [
        (1, 'John Admin', '1980-01-15', '+1-555-ADMIN', '123 Admin Street', 'Admin City', 'USA', '12345', 
         'What is your favorite color?', 'blue', 'admin.jpg', 'System administrator'),
        (2, 'Jane Administrator', '1985-03-20', '+1-555-ADMIN2', '456 Admin Avenue', 'Admin Town', 'USA', '67890', 
         'What is your pet name?', 'fluffy', 'admin2.jpg', 'Senior administrator'),
        (3, 'Bob Root', '1990-07-10', '+1-555-ROOT', '789 Root Road', 'Root City', 'USA', '13579', 
         'What city were you born in?', 'rootcity', 'root.jpg', 'Root user'),
        (4, 'Alice User', '1992-11-25', '+1-555-USER1', '321 User Lane', 'User Town', 'USA', '24680', 
         'What is your mothers maiden name?', 'smith', 'user1.jpg', 'Regular user'),
        (5, 'Charlie Demo', '1988-05-30', '+1-555-DEMO', '654 Demo Drive', 'Demo City', 'USA', '97531', 
         'What was your first car?', 'toyota', 'demo.jpg', 'Demo account')
    ]
    
    cursor.executemany('''
        INSERT INTO user_profiles (user_id, full_name, date_of_birth, phone_number, address, city, country, postal_code, security_question, security_answer, profile_picture, bio) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', profiles_data)
    
    conn.commit()
    conn.close()
    
    print("✅ Enhanced vulnerable database created successfully!")
    print("📊 Database contains the following tables:")
    print("   • users - User accounts with weak passwords")
    print("   • products - E-commerce products")
    print("   • orders - Order history with sensitive data")
    print("   • comments - User comments (some with XSS payloads)")
    print("   • sessions - Session management data")
    print("   • admin_logs - Administrative actions")
    print("   • credit_cards - Credit card information (simulated)")
    print("   • user_profiles - Detailed user profiles")
    
    return True

def add_vulnerable_stored_procedures():
    """Add vulnerable stored procedures (simulated)"""
    
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # Create a vulnerable user search function
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS search_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            search_query TEXT,
            search_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            results_count INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Insert some search history with injection attempts
    search_data = [
        (1, 'iPhone', 3),
        (2, 'MacBook', 2),
        (3, "' OR 1=1--", 10),  # SQL injection attempt
        (4, '" OR ""="', 8),     # SQL injection attempt
        (5, 'admin\'--', 1),    # SQL injection attempt
        (1, 'SELECT * FROM users', 5),  # SQL injection attempt
        (2, 'products WHERE 1=1', 7)    # SQL injection attempt
    ]
    
    cursor.executemany('''
        INSERT INTO search_history (user_id, search_query, results_count) 
        VALUES (?, ?, ?)
    ''', search_data)
    
    conn.commit()
    conn.close()
    
    print("✅ Added vulnerable search history table!")

def generate_database_report():
    """Generate a report of the database contents"""
    
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    report = {}
    
    # Get table names
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    
    for table in tables:
        table_name = table[0]
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        count = cursor.fetchone()[0]
        report[table_name] = count
    
    conn.close()
    
    # Save report
    with open('vulnerable_database_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("📋 Database Report Generated:")
    for table, count in report.items():
        print(f"   • {table}: {count} records")
    
    return report

if __name__ == "__main__":
    print("🔧 Enhancing Vulnerable Database...")
    print("=" * 50)
    
    # Create enhanced database
    create_enhanced_database()
    
    # Add vulnerable stored procedures
    add_vulnerable_stored_procedures()
    
    # Generate report
    generate_database_report()
    
    print("\n" + "=" * 50)
    print("🎉 Database enhancement completed!")
    print("⚠️  This database contains intentionally vulnerable data for educational purposes only!")
    print("🔒 Never use this in a production environment!")