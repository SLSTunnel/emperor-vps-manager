#!/usr/bin/env python3
"""
Emperor DevSupport VPS Manager - Command Line Interface
"""

import argparse
import sqlite3
import subprocess
import sys
import os
from werkzeug.security import generate_password_hash, check_password_hash

def init_db():
    """Initialize database"""
    conn = sqlite3.connect('emperor_vps.db')
    c = conn.cursor()
    
    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  email TEXT,
                  role TEXT DEFAULT 'user',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  is_active BOOLEAN DEFAULT 1)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS vpn_accounts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL,
                  service_type TEXT NOT NULL,
                  port INTEGER,
                  password TEXT,
                  config_data TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  is_active BOOLEAN DEFAULT 1)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS system_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  action TEXT NOT NULL,
                  user TEXT,
                  details TEXT,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    conn.commit()
    conn.close()
    print("Database initialized successfully!")

def add_user(username, password, email=None, role='user'):
    """Add a new user"""
    try:
        conn = sqlite3.connect('emperor_vps.db')
        c = conn.cursor()
        
        password_hash = generate_password_hash(password)
        c.execute('INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)',
                  (username, password_hash, email, role))
        conn.commit()
        conn.close()
        
        print(f"User '{username}' created successfully!")
        
        # Log the action
        log_action('add_user', 'CLI', f'Created user: {username}')
        
    except sqlite3.IntegrityError:
        print(f"Error: User '{username}' already exists!")
    except Exception as e:
        print(f"Error creating user: {e}")

def del_user(username):
    """Delete a user"""
    try:
        # Delete system user if exists
        try:
            subprocess.run(['userdel', '-r', username], check=True)
            print(f"System user '{username}' deleted.")
        except subprocess.CalledProcessError:
            print(f"System user '{username}' not found or already deleted.")
        
        # Delete from database
        conn = sqlite3.connect('emperor_vps.db')
        c = conn.cursor()
        c.execute('DELETE FROM users WHERE username = ?', (username,))
        c.execute('DELETE FROM vpn_accounts WHERE username = ?', (username,))
        
        if c.rowcount > 0:
            conn.commit()
            print(f"User '{username}' deleted from database!")
        else:
            print(f"User '{username}' not found in database!")
        
        conn.close()
        
        # Log the action
        log_action('del_user', 'CLI', f'Deleted user: {username}')
        
    except Exception as e:
        print(f"Error deleting user: {e}")

def create_ssh(username, password=None):
    """Create SSH account"""
    try:
        if not password:
            import random
            import string
            password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
        
        # Create system user
        subprocess.run(['useradd', '-m', '-s', '/bin/bash', username], check=True)
        subprocess.run(['echo', f'{username}:{password}', '|', 'chpasswd'], shell=True, check=True)
        
        print(f"SSH account created for '{username}'")
        print(f"Password: {password}")
        
        # Log the action
        log_action('create_ssh', 'CLI', f'Created SSH account for: {username}')
        
    except subprocess.CalledProcessError as e:
        print(f"Error creating SSH account: {e}")
    except Exception as e:
        print(f"Error: {e}")

def create_v2ray(username, port=443):
    """Create V2Ray account"""
    try:
        import uuid
        import json
        
        config = {
            'username': username,
            'port': port,
            'uuid': str(uuid.uuid4()),
            'protocol': 'vmess'
        }
        
        # Save to database
        conn = sqlite3.connect('emperor_vps.db')
        c = conn.cursor()
        c.execute('''INSERT INTO vpn_accounts (username, service_type, port, config_data)
                     VALUES (?, ?, ?, ?)''', (username, 'v2ray', port, json.dumps(config)))
        conn.commit()
        conn.close()
        
        print(f"V2Ray account created for '{username}'")
        print(f"Port: {port}")
        print(f"UUID: {config['uuid']}")
        
        # Log the action
        log_action('create_v2ray', 'CLI', f'Created V2Ray account for: {username}')
        
    except Exception as e:
        print(f"Error creating V2Ray account: {e}")

def create_wireguard(username, port=51820):
    """Create WireGuard account"""
    try:
        import json
        
        # Generate WireGuard keys
        private_key = subprocess.check_output(['wg', 'genkey']).decode().strip()
        public_key = subprocess.check_output(['wg', 'pubkey'], input=private_key.encode()).decode().strip()
        
        config = {
            'username': username,
            'private_key': private_key,
            'public_key': public_key,
            'port': port
        }
        
        # Save to database
        conn = sqlite3.connect('emperor_vps.db')
        c = conn.cursor()
        c.execute('''INSERT INTO vpn_accounts (username, service_type, port, config_data)
                     VALUES (?, ?, ?, ?)''', (username, 'wireguard', port, json.dumps(config)))
        conn.commit()
        conn.close()
        
        print(f"WireGuard account created for '{username}'")
        print(f"Port: {port}")
        print(f"Public Key: {public_key}")
        
        # Log the action
        log_action('create_wireguard', 'CLI', f'Created WireGuard account for: {username}')
        
    except Exception as e:
        print(f"Error creating WireGuard account: {e}")

def list_users():
    """List all users"""
    try:
        conn = sqlite3.connect('emperor_vps.db')
        c = conn.cursor()
        c.execute('SELECT username, email, role, created_at, is_active FROM users ORDER BY created_at DESC')
        users = c.fetchall()
        conn.close()
        
        if users:
            print("\nUsers:")
            print("-" * 80)
            print(f"{'Username':<15} {'Email':<25} {'Role':<10} {'Status':<8} {'Created'}")
            print("-" * 80)
            for user in users:
                status = "Active" if user[4] else "Inactive"
                print(f"{user[0]:<15} {user[1] or 'N/A':<25} {user[2]:<10} {status:<8} {user[3]}")
        else:
            print("No users found.")
            
    except Exception as e:
        print(f"Error listing users: {e}")

def list_vpn_accounts():
    """List all VPN accounts"""
    try:
        conn = sqlite3.connect('emperor_vps.db')
        c = conn.cursor()
        c.execute('SELECT username, service_type, port, created_at, is_active FROM vpn_accounts ORDER BY created_at DESC')
        accounts = c.fetchall()
        conn.close()
        
        if accounts:
            print("\nVPN Accounts:")
            print("-" * 70)
            print(f"{'Username':<15} {'Service':<12} {'Port':<8} {'Status':<8} {'Created'}")
            print("-" * 70)
            for account in accounts:
                status = "Active" if account[4] else "Inactive"
                print(f"{account[0]:<15} {account[1]:<12} {account[2]:<8} {status:<8} {account[3]}")
        else:
            print("No VPN accounts found.")
            
    except Exception as e:
        print(f"Error listing VPN accounts: {e}")

def log_action(action, user, details):
    """Log system action"""
    try:
        conn = sqlite3.connect('emperor_vps.db')
        c = conn.cursor()
        c.execute('INSERT INTO system_logs (action, user, details) VALUES (?, ?, ?)',
                  (action, user, details))
        conn.commit()
        conn.close()
    except Exception:
        pass  # Ignore logging errors

def main():
    parser = argparse.ArgumentParser(description='Emperor DevSupport VPS Manager CLI')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Init command
    subparsers.add_parser('init', help='Initialize database')
    
    # User management
    user_parser = subparsers.add_parser('add-user', help='Add a new user')
    user_parser.add_argument('username', help='Username')
    user_parser.add_argument('password', help='Password')
    user_parser.add_argument('--email', help='Email address')
    user_parser.add_argument('--role', default='user', choices=['user', 'admin'], help='User role')
    
    del_user_parser = subparsers.add_parser('del-user', help='Delete a user')
    del_user_parser.add_argument('username', help='Username to delete')
    
    subparsers.add_parser('list-users', help='List all users')
    
    # VPN account creation
    ssh_parser = subparsers.add_parser('create-ssh', help='Create SSH account')
    ssh_parser.add_argument('username', help='Username')
    ssh_parser.add_argument('--password', help='Password (auto-generated if not provided)')
    
    v2ray_parser = subparsers.add_parser('create-v2ray', help='Create V2Ray account')
    v2ray_parser.add_argument('username', help='Username')
    v2ray_parser.add_argument('--port', type=int, default=443, help='Port number')
    
    wg_parser = subparsers.add_parser('create-wireguard', help='Create WireGuard account')
    wg_parser.add_argument('username', help='Username')
    wg_parser.add_argument('--port', type=int, default=51820, help='Port number')
    
    subparsers.add_parser('list-vpn', help='List all VPN accounts')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Execute command
    if args.command == 'init':
        init_db()
    elif args.command == 'add-user':
        add_user(args.username, args.password, args.email, args.role)
    elif args.command == 'del-user':
        del_user(args.username)
    elif args.command == 'list-users':
        list_users()
    elif args.command == 'create-ssh':
        create_ssh(args.username, args.password)
    elif args.command == 'create-v2ray':
        create_v2ray(args.username, args.port)
    elif args.command == 'create-wireguard':
        create_wireguard(args.username, args.port)
    elif args.command == 'list-vpn':
        list_vpn_accounts()

if __name__ == '__main__':
    main() 