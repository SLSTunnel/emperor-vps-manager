#!/usr/bin/env python3
"""
Emperor DevSupport VPS Manager
Main Flask Application
"""

import os
import json
import psutil
import subprocess
import uuid
import base64
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, disconnect
import sqlite3
import threading
import time

app = Flask(__name__)
app.secret_key = 'emperor_devsupport_secret_key_2024'

# SocketIO setup for WebSocket support
socketio = SocketIO(app, cors_allowed_origins="*")

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database setup
def init_db():
    conn = sqlite3.connect('emperor_vps.db')
    c = conn.cursor()
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
                  config_file TEXT,
                  expire_date DATE,
                  max_connections INTEGER DEFAULT 1,
                  current_connections INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  is_active BOOLEAN DEFAULT 1)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS system_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  action TEXT NOT NULL,
                  user TEXT,
                  details TEXT,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create default admin user
    admin_password = generate_password_hash('emperor2024')
    c.execute('INSERT OR IGNORE INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)',
              ('admin', admin_password, 'admin@emperor.com', 'admin'))
    
    conn.commit()
    conn.close()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, username, role):
        self.id = user_id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('emperor_vps.db')
    c = conn.cursor()
    c.execute('SELECT id, username, role FROM users WHERE id = ?', (user_id,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1], user_data[2])
    return None

# VPN Service Manager
class VPNManager:
    def __init__(self):
        self.services = {
            'ssh': {'port': 22, 'enabled': True},
            'sshws': {'port': 80, 'enabled': True},
            'ws_alt': {'port': 8080, 'enabled': True},
            'v2ray': {'port': 443, 'enabled': True},
            'wireguard': {'port': 51820, 'enabled': True},
            'openvpn_tcp': {'port': 1194, 'enabled': True},
            'openvpn_udp': {'port': 1195, 'enabled': True},
            'shadowsocks': {'port': 8388, 'enabled': True},
            'badvpn_udpgw': {'port': 7300, 'enabled': True},
            'slowdns': {'port': 53, 'enabled': True}
        }
        self.server_ip = self.get_server_ip()
    
    def get_server_ip(self):
        """Get server IP address"""
        try:
            return subprocess.check_output(['curl', '-s', 'ifconfig.me']).decode().strip()
        except:
            return 'your-server-ip.com'
    
    def create_ssh_account(self, username, password=None, expire_days=30, max_connections=1):
        """Create SSH account with expiration and connection limits"""
        if not password:
            password = self.generate_password()
        
        try:
            # Calculate expiration date
            from datetime import datetime, timedelta
            expire_date = (datetime.now() + timedelta(days=expire_days)).strftime('%Y-%m-%d')
            
            # Create system user
            subprocess.run(['useradd', '-m', '-s', '/bin/bash', username], check=True)
            subprocess.run(['echo', f'{username}:{password}', '|', 'chpasswd'], shell=True, check=True)
            
            # Create SSH config for apps with all VPN options
            ssh_config = f"""Host {username}-ssh
    HostName {self.server_ip}
    Port 22
    User {username}
    PasswordAuthentication yes
    ServerAliveInterval 60
    ServerAliveCountMax 3

# SSH + SSL + WebSocket + OpenVPN Configuration
# This account supports multiple VPN protocols:

# 1. SSH Direct Connection
# Use any SSH client with:
# Host: {self.server_ip}
# Port: 22
# Username: {username}
# Password: {password}

# 2. SSH over WebSocket (SSHWS)
# Use SSHWS client with:
# Host: {self.server_ip}
# Port: 80
# Username: {username}
# Password: {password}

# 3. OpenVPN Configuration
# Download OpenVPN config from dashboard

# 4. V2Ray Configuration
# Use V2Ray client with config from dashboard

# 5. WireGuard Configuration
# Use WireGuard client with config from dashboard

# 6. BadVPN UDP Gateway
# Use BadVPN UDPGW on port 7300 for UDP tunneling

# Account Details:
# Username: {username}
# Password: {password}
# Expires: {expire_date}
# Max Connections: {max_connections}
# Server IP: {self.server_ip}

# Banner Message:
# ╔══════════════════════════════════════════════════════════════╗
# ║                    VPS By [Emperor] DevSupport               ║
# ║                                                              ║
# ║              Support YouTube: SlidAk4                        ║
# ║                                                              ║
# ║              Enjoy Mocked Location Server High Speed         ║
# ║                                                              ║
# ║              Server IP: {self.server_ip}                           ║
# ╚══════════════════════════════════════════════════════════════╝"""
            
            # Create comprehensive config data
            config_data = {
                'host': self.server_ip,
                'port': 22,
                'username': username,
                'password': password,
                'expire_date': expire_date,
                'max_connections': max_connections,
                'current_connections': 0,
                'config': ssh_config,
                'services_enabled': {
                    'ssh': True,
                    'sshws': True,
                    'ws_alt': True,
                    'openvpn_tcp': True,
                    'openvpn_udp': True,
                    'v2ray': True,
                    'wireguard': True,
                    'shadowsocks': True,
                    'badvpn_udpgw': True
                },
                'connection_info': {
                    'ssh': {'port': 22, 'protocol': 'SSH'},
                    'sshws': {'port': 80, 'protocol': 'SSH over WebSocket'},
                    'ws_alt': {'port': 8080, 'protocol': 'WebSocket Alternative'},
                    'openvpn_tcp': {'port': 1194, 'protocol': 'OpenVPN TCP'},
                    'openvpn_udp': {'port': 1195, 'protocol': 'OpenVPN UDP'},
                    'v2ray': {'port': 443, 'protocol': 'V2Ray VMess'},
                    'wireguard': {'port': 51820, 'protocol': 'WireGuard'},
                    'shadowsocks': {'port': 8388, 'protocol': 'Shadowsocks'},
                    'badvpn_udpgw': {'port': 7300, 'protocol': 'BadVPN UDP Gateway'}
                }
            }
            
            # Save to database with new fields
            conn = sqlite3.connect('emperor_vps.db')
            c = conn.cursor()
            c.execute('''INSERT INTO vpn_accounts 
                         (username, service_type, port, password, config_data, expire_date, max_connections)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                      (username, 'ssh', 22, password, json.dumps(config_data), expire_date, max_connections))
            conn.commit()
            conn.close()
            
            self.log_action('create_ssh', username, f'SSH account created for {username} (expires: {expire_date}, max connections: {max_connections})')
            
            return {
                'success': True, 
                'username': username, 
                'password': password, 
                'config': ssh_config,
                'expire_date': expire_date,
                'max_connections': max_connections,
                'config_data': config_data
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def create_v2ray_account(self, username, port=None):
        """Create V2Ray account with proper config"""
        if not port:
            port = self.services['v2ray']['port']
        
        try:
            # Generate V2Ray configuration
            user_uuid = str(uuid.uuid4())
            
            # VMess configuration
            vmess_config = {
                "v": "2",
                "ps": f"{username}-vmess",
                "add": self.server_ip,
                "port": port,
                "id": user_uuid,
                "aid": "0",
                "net": "tcp",
                "type": "none",
                "host": "",
                "path": "",
                "tls": "tls"
            }
            
            # Generate VMess link
            vmess_link = "vmess://" + base64.b64encode(json.dumps(vmess_config).encode()).decode()
            
            # V2Ray server config (to be added to server)
            v2ray_server_config = {
                "protocol": "vmess",
                "settings": {
                    "clients": [
                        {
                            "id": user_uuid,
                            "alterId": 0
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "certificates": [
                            {
                                "certificateFile": "/etc/ssl/emperor-vps/nginx.crt",
                                "keyFile": "/etc/ssl/emperor-vps/nginx.key"
                            }
                        ]
                    }
                }
            }
            
            config = {
                'username': username,
                'port': port,
                'uuid': user_uuid,
                'protocol': 'vmess',
                'vmess_link': vmess_link,
                'server_config': v2ray_server_config,
                'instructions': f"""
V2Ray Configuration for {username}

1. Download V2Ray app (V2RayNG for Android, V2RayX for macOS, etc.)
2. Import this VMess link:
{vmess_link}

3. Or manually configure:
   - Address: {self.server_ip}
   - Port: {port}
   - UUID: {user_uuid}
   - Protocol: VMess
   - Security: TLS
   - Network: TCP
"""
            }
            
            # Save to database
            conn = sqlite3.connect('emperor_vps.db')
            c = conn.cursor()
            c.execute('''INSERT INTO vpn_accounts (username, service_type, port, config_data)
                         VALUES (?, ?, ?, ?)''', (username, 'v2ray', port, json.dumps(config)))
            conn.commit()
            conn.close()
            
            self.log_action('create_v2ray', username, f'V2Ray account created for {username}')
            
            return {'success': True, 'config': config}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def create_wireguard_account(self, username):
        """Create WireGuard account with proper config"""
        try:
            # Generate WireGuard keys
            private_key = subprocess.check_output(['wg', 'genkey']).decode().strip()
            public_key = subprocess.check_output(['wg', 'pubkey'], input=private_key.encode()).decode().strip()
            
            # Generate client IP
            client_ip = f"10.0.0.{100 + hash(username) % 155}"
            
            # Create WireGuard client config
            wg_config = f"""[Interface]
PrivateKey = {private_key}
Address = {client_ip}/24
DNS = 8.8.8.8, 1.1.1.1

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = {self.server_ip}:{self.services['wireguard']['port']}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25"""
            
            # Generate QR code data
            qr_data = base64.b64encode(wg_config.encode()).decode()
            
            config = {
                'username': username,
                'private_key': private_key,
                'public_key': public_key,
                'client_ip': client_ip,
                'port': self.services['wireguard']['port'],
                'config_file': wg_config,
                'qr_data': qr_data,
                'instructions': f"""
WireGuard Configuration for {username}

1. Download WireGuard app
2. Scan QR code or import config file
3. Or manually configure:
   - Private Key: {private_key}
   - Address: {client_ip}/24
   - DNS: 8.8.8.8, 1.1.1.1
   - Endpoint: {self.server_ip}:{self.services['wireguard']['port']}
   - Public Key: [Server Public Key]
"""
            }
            
            # Save to database
            conn = sqlite3.connect('emperor_vps.db')
            c = conn.cursor()
            c.execute('''INSERT INTO vpn_accounts (username, service_type, port, config_data)
                         VALUES (?, ?, ?, ?)''', (username, 'wireguard', config['port'], json.dumps(config)))
            conn.commit()
            conn.close()
            
            self.log_action('create_wireguard', username, f'WireGuard account created for {username}')
            
            return {'success': True, 'config': config}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def create_openvpn_account(self, username, port=None):
        """Create OpenVPN account with proper config"""
        if not port:
            port = self.services['openvpn']['port']
        
        try:
            # Generate OpenVPN client config
            ovpn_config = f"""client
dev tun
proto udp
remote {self.server_ip} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
key-direction 1
verb 3

<ca>
# CA Certificate will be here
</ca>

<cert>
# Client Certificate will be here
</cert>

<key>
# Client Key will be here
</key>

<tls-auth>
# TLS Auth Key will be here
</tls-auth>"""
            
            config = {
                'username': username,
                'port': port,
                'protocol': 'udp',
                'config_file': ovpn_config,
                'instructions': f"""
OpenVPN Configuration for {username}

1. Download OpenVPN app
2. Import .ovpn config file
3. Or manually configure:
   - Server: {self.server_ip}
   - Port: {port}
   - Protocol: UDP
   - Cipher: AES-256-CBC
   - Auth: SHA256
"""
            }
            
            # Save to database
            conn = sqlite3.connect('emperor_vps.db')
            c = conn.cursor()
            c.execute('''INSERT INTO vpn_accounts (username, service_type, port, config_data)
                         VALUES (?, ?, ?, ?)''', (username, 'openvpn', port, json.dumps(config)))
            conn.commit()
            conn.close()
            
            self.log_action('create_openvpn', username, f'OpenVPN account created for {username}')
            
            return {'success': True, 'config': config}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def create_shadowsocks_account(self, username, port=None):
        """Create Shadowsocks account with proper config"""
        if not port:
            port = self.services['shadowsocks']['port']
        
        try:
            # Generate password
            password = self.generate_password(16)
            
            # Generate Shadowsocks config
            ss_config = {
                "server": self.server_ip,
                "server_port": port,
                "password": password,
                "method": "aes-256-gcm",
                "plugin": "",
                "plugin_opts": "",
                "remarks": f"{username}-ss"
            }
            
            # Generate Shadowsocks link
            ss_link = "ss://" + base64.b64encode(f"aes-256-gcm:{password}@{self.server_ip}:{port}".encode()).decode() + f"#{username}-ss"
            
            config = {
                'username': username,
                'port': port,
                'password': password,
                'method': 'aes-256-gcm',
                'ss_link': ss_link,
                'config': ss_config,
                'instructions': f"""
Shadowsocks Configuration for {username}

1. Download Shadowsocks app
2. Scan QR code or import link:
{ss_link}

3. Or manually configure:
   - Server: {self.server_ip}
   - Port: {port}
   - Password: {password}
   - Method: aes-256-gcm
"""
            }
            
            # Save to database
            conn = sqlite3.connect('emperor_vps.db')
            c = conn.cursor()
            c.execute('''INSERT INTO vpn_accounts (username, service_type, port, password, config_data)
                         VALUES (?, ?, ?, ?, ?)''', (username, 'shadowsocks', port, password, json.dumps(config)))
            conn.commit()
            conn.close()
            
            self.log_action('create_shadowsocks', username, f'Shadowsocks account created for {username}')
            
            return {'success': True, 'config': config}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def delete_user(self, username):
        """Delete user and all their VPN accounts"""
        try:
            # Delete system user
            subprocess.run(['userdel', '-r', username], check=True)
            
            # Delete from database
            conn = sqlite3.connect('emperor_vps.db')
            c = conn.cursor()
            c.execute('DELETE FROM users WHERE username = ?', (username,))
            c.execute('DELETE FROM vpn_accounts WHERE username = ?', (username,))
            conn.commit()
            conn.close()
            
            self.log_action('delete_user', current_user.username, f'User {username} deleted')
            
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_system_stats(self):
        """Get system statistics"""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_total': psutil.virtual_memory().total,
            'memory_used': psutil.virtual_memory().used,
            'memory_percent': psutil.virtual_memory().percent,
            'disk_total': psutil.disk_usage('/').total,
            'disk_used': psutil.disk_usage('/').used,
            'disk_percent': psutil.disk_usage('/').percent,
            'active_users': self.get_active_users_count()
        }
    
    def get_active_users_count(self):
        """Get count of active users"""
        conn = sqlite3.connect('emperor_vps.db')
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM users WHERE is_active = 1')
        count = c.fetchone()[0]
        conn.close()
        return count
    
    def generate_password(self, length=12):
        """Generate random password"""
        import random
        import string
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(random.choice(chars) for _ in range(length))
    
    def generate_uuid(self):
        """Generate UUID for V2Ray"""
        return str(uuid.uuid4())
    
    def log_action(self, action, user, details):
        """Log system actions"""
        conn = sqlite3.connect('emperor_vps.db')
        c = conn.cursor()
        c.execute('INSERT INTO system_logs (action, user, details) VALUES (?, ?, ?)',
                  (action, user, details))
        conn.commit()
        conn.close()

# Initialize VPN manager
vpn_manager = VPNManager()

# Routes
@app.route('/')
@login_required
def dashboard():
    stats = vpn_manager.get_system_stats()
    return render_template('dashboard.html', stats=stats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('emperor_vps.db')
        c = conn.cursor()
        c.execute('SELECT id, username, password_hash, role FROM users WHERE username = ? AND is_active = 1', (username,))
        user_data = c.fetchone()
        conn.close()
        
        if user_data and check_password_hash(user_data[2], password):
            user = User(user_data[0], user_data[1], user_data[3])
            login_user(user)
            vpn_manager.log_action('login', username, 'User logged in')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    vpn_manager.log_action('logout', current_user.username, 'User logged out')
    logout_user()
    return redirect(url_for('login'))

@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('emperor_vps.db')
    c = conn.cursor()
    c.execute('SELECT id, username, email, role, created_at, is_active FROM users ORDER BY created_at DESC')
    users_data = c.fetchall()
    conn.close()
    
    return render_template('users.html', users=users_data)

@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    username = request.form['username']
    password = request.form['password']
    email = request.form.get('email', '')
    
    try:
        conn = sqlite3.connect('emperor_vps.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                  (username, generate_password_hash(password), email))
        conn.commit()
        conn.close()
        
        vpn_manager.log_action('create_user', current_user.username, f'Created user: {username}')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    username = request.form['username']
    result = vpn_manager.delete_user(username)
    return jsonify(result)

@app.route('/create_vpn', methods=['POST'])
@login_required
def create_vpn():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    service_type = request.form['service_type']
    username = request.form['username']
    
    if service_type == 'ssh':
        result = vpn_manager.create_ssh_account(username)
    elif service_type == 'v2ray':
        result = vpn_manager.create_v2ray_account(username)
    elif service_type == 'wireguard':
        result = vpn_manager.create_wireguard_account(username)
    elif service_type == 'openvpn':
        result = vpn_manager.create_openvpn_account(username)
    elif service_type == 'shadowsocks':
        result = vpn_manager.create_shadowsocks_account(username)
    else:
        result = {'success': False, 'error': 'Unsupported service type'}
    
    return jsonify(result)

@app.route('/create_enhanced_ssh', methods=['POST'])
@login_required
def create_enhanced_ssh():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    username = request.form['username']
    password = request.form.get('password', '')
    expire_days = int(request.form.get('expire_days', 30))
    max_connections = int(request.form.get('max_connections', 1))
    
    # Validate inputs
    if not username:
        return jsonify({'success': False, 'error': 'Username is required'})
    
    if expire_days < 1 or expire_days > 365:
        return jsonify({'success': False, 'error': 'Expire days must be between 1 and 365'})
    
    if max_connections < 1 or max_connections > 10:
        return jsonify({'success': False, 'error': 'Max connections must be between 1 and 10'})
    
    result = vpn_manager.create_ssh_account(username, password, expire_days, max_connections)
    return jsonify(result)

@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify(vpn_manager.get_system_stats())

@app.route('/api/vpn_accounts')
@login_required
def api_vpn_accounts():
    conn = sqlite3.connect('emperor_vps.db')
    c = conn.cursor()
    c.execute('''SELECT username, service_type, port, created_at, is_active, 
                  expire_date, max_connections, current_connections 
                  FROM vpn_accounts ORDER BY created_at DESC''')
    accounts = []
    for row in c.fetchall():
        accounts.append({
            'username': row[0],
            'service_type': row[1],
            'port': row[2],
            'created_at': row[3],
            'is_active': bool(row[4]),
            'expire_date': row[5],
            'max_connections': row[6],
            'current_connections': row[7]
        })
    conn.close()
    return jsonify({'accounts': accounts})

@app.route('/api/vpn_config/<username>/<service_type>')
@login_required
def api_vpn_config(username, service_type):
    conn = sqlite3.connect('emperor_vps.db')
    c = conn.cursor()
    c.execute('SELECT config_data FROM vpn_accounts WHERE username = ? AND service_type = ?', (username, service_type))
    result = c.fetchone()
    conn.close()
    
    if result:
        config = json.loads(result[0])
        return jsonify({'success': True, 'config': config})
    else:
        return jsonify({'success': False, 'error': 'Configuration not found'})

@app.route('/api/toggle_service', methods=['POST'])
@login_required
def api_toggle_service():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    data = request.get_json()
    service_name = data.get('service')
    
    if service_name in vpn_manager.services:
        vpn_manager.services[service_name]['enabled'] = not vpn_manager.services[service_name]['enabled']
        return jsonify({'success': True, 'enabled': vpn_manager.services[service_name]['enabled']})
    else:
        return jsonify({'success': False, 'error': 'Service not found'})

@app.route('/api/change_port', methods=['POST'])
@login_required
def api_change_port():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    service_name = request.form['service_name']
    new_port = int(request.form['new_port'])
    
    if service_name in vpn_manager.services:
        vpn_manager.services[service_name]['port'] = new_port
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Service not found'})

@app.route('/api/delete_vpn_account', methods=['POST'])
@login_required
def api_delete_vpn_account():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    data = request.get_json()
    username = data.get('username')
    service_type = data.get('service_type')
    
    try:
        conn = sqlite3.connect('emperor_vps.db')
        c = conn.cursor()
        c.execute('DELETE FROM vpn_accounts WHERE username = ? AND service_type = ?', (username, service_type))
        conn.commit()
        conn.close()
        
        vpn_manager.log_action('delete_vpn_account', current_user.username, f'Deleted {service_type} account for {username}')
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/logs')
@login_required
def api_logs():
    conn = sqlite3.connect('emperor_vps.db')
    c = conn.cursor()
    c.execute('SELECT action, user, details, timestamp FROM system_logs ORDER BY timestamp DESC LIMIT 50')
    logs = []
    for row in c.fetchall():
        logs.append({
            'action': row[0],
            'user': row[1],
            'details': row[2],
            'timestamp': row[3]
        })
    conn.close()
    return jsonify({'logs': logs})

@app.route('/services')
@login_required
def services():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('services.html', services=vpn_manager.services)

@app.route('/accounts')
@login_required
def accounts():
    return render_template('accounts.html')

# WebSocket events
@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')
    emit('status', {'message': 'Connected to Emperor VPS Manager'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')

@socketio.on('get_stats')
def handle_get_stats():
    """Send real-time system stats via WebSocket"""
    stats = vpn_manager.get_system_stats()
    emit('stats_update', stats)

@socketio.on('ssh_connect')
def handle_ssh_connect(data):
    """Handle SSH connection via WebSocket"""
    username = data.get('username')
    password = data.get('password')
    
    # Validate credentials
    conn = sqlite3.connect('emperor_vps.db')
    c = conn.cursor()
    c.execute('SELECT * FROM vpn_accounts WHERE username = ? AND service_type = "ssh"', (username,))
    account = c.fetchone()
    conn.close()
    
    if account:
        emit('ssh_status', {'status': 'connected', 'message': 'SSH connection established'})
    else:
        emit('ssh_status', {'status': 'error', 'message': 'Invalid credentials'})

if __name__ == '__main__':
    init_db()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True) 