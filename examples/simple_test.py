#!/usr/bin/env python3
"""
Simple test script with intentional security vulnerabilities
for demonstrating the AI Security Analyzer capabilities
"""

import os
import sqlite3
import subprocess
import hashlib

# 🚨 Hardcoded secret - should be detected by Secrets Agent
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "password123"

# 🚨 SQL Injection vulnerability - should be detected by Injection Agent
def get_user_data(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable: Direct string concatenation in SQL query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    
    result = cursor.fetchall()
    conn.close()
    return result

# 🚨 Command Injection vulnerability - should be detected by Injection Agent
def process_file(filename):
    # Vulnerable: User input directly in shell command
    command = f"cat {filename}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

# 🚨 Weak cryptography - should be detected by Crypto Agent
def hash_password(password):
    # Vulnerable: Using MD5 for password hashing (weak)
    return hashlib.md5(password.encode()).hexdigest()

# 🚨 Path traversal vulnerability - should be detected by General Agent
def read_config_file(config_name):
    # Vulnerable: No path validation
    config_path = f"configs/{config_name}"
    with open(config_path, 'r') as f:
        return f.read()

# 🚨 Authentication bypass - should be detected by Auth Agent
def login(username, password):
    # Vulnerable: Always returns True for admin
    if username == "admin":
        return True
    
    # Vulnerable: Weak password check
    if len(password) > 3:
        return True
    
    return False

# 🚨 Information disclosure - should be detected by General Agent
def debug_info():
    # Vulnerable: Exposing sensitive system information
    return {
        "database_url": f"postgresql://user:{DATABASE_PASSWORD}@localhost/db",
        "api_key": API_KEY,
        "system_info": os.uname(),
        "environment": dict(os.environ)
    }

if __name__ == "__main__":
    print("🧪 Test script with security vulnerabilities")
    print("This script contains intentional vulnerabilities for testing purposes")
    
    # Test functions (don't actually run in production!)
    # user_data = get_user_data("test' OR '1'='1")
    # file_content = process_file("../../../etc/passwd")
    # weak_hash = hash_password("secret123")
    # config = read_config_file("../../../etc/passwd")
    # auth_result = login("admin", "")
    # debug_data = debug_info() 