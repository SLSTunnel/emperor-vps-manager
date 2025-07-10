# Emperor DevSupport VPS Manager

A professional VPS management dashboard with comprehensive VPN service support and advanced monitoring capabilities.

## 🌟 Advanced Features

- 🎨 **Hacker Theme Dashboard** with neon animations and particle effects
- 🔐 **Advanced Admin Authentication** with 2FA support
- 👥 **Multi-User Management** with role-based access control
- 🌐 **Comprehensive VPN Services**:
  - SSH/SSHWS with custom configurations
  - V2Ray with multiple protocols (VMess, VLESS, Trojan)
  - WireGuard with peer management
  - OpenVPN with certificate management
  - Shadowsocks with multiple encryption methods
  - SlowDNS with custom DNS servers
  - UDP/TCP protocol optimization
- 📊 **Real-time Advanced Monitoring** (RAM, CPU, Network, Disk I/O)
- 🔧 **Advanced Port Management** and service configuration
- 📱 **Progressive Web App** with offline support
- 🚀 **Auto-scaling** and load balancing
- 🔒 **Advanced Security** with rate limiting and DDoS protection
- 📈 **Analytics Dashboard** with usage statistics
- 🔔 **Real-time Notifications** and alerts
- 🌍 **Multi-language Support**
- 📱 **Mobile App** (Android/iOS)

## Quick Installation

### 1. Clone to GitHub
```bash
git clone https://github.com/SLSTunnel/emperor-vps-manager.git
cd emperor-vps-manager
```

### 2. Install on VPS
```bash
# Download and run installation script
curl -sSL https://raw.githubusercontent.com/SLSTunnel/emperor-vps-manager/main/install.sh | bash
```

### 3. Access Dashboard
- URL: `http://your-vps-ip:5000`
- Default Admin: `admin` / `emperor2024`

## Manual Installation

### Prerequisites
- Ubuntu 20.04+ / Debian 11+
- Python 3.8+
- Root access
- Minimum 2GB RAM, 20GB storage

### Step-by-Step Setup

1. **Update System**
```bash
apt update && apt upgrade -y
```

2. **Install Dependencies**
```bash
apt install -y python3 python3-pip python3-venv nginx curl wget git ufw fail2ban redis-server
```

3. **Clone Repository**
```bash
git clone https://github.com/SLSTunnel/emperor-vps-manager.git
cd emperor-vps-manager
```

4. **Setup Python Environment**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

5. **Configure Services**
```bash
chmod +x setup.sh
./setup.sh
```

6. **Start Services**
```bash
systemctl enable emperor-vps
systemctl start emperor-vps
```

## Advanced Configuration

### Admin Settings
Edit `config/admin.json`:
```json
{
  "username": "admin",
  "password": "emperor2024",
  "email": "admin@emperor.com",
  "two_factor_enabled": true,
  "session_timeout": 3600,
  "max_login_attempts": 5,
  "lockout_duration": 900
}
```

### VPN Services
Configure services in `config/services.json`:
```json
{
  "ssh": {"port": 22, "enabled": true, "max_connections": 100},
  "v2ray": {"port": 443, "enabled": true, "protocols": ["vmess", "vless", "trojan"]},
  "wireguard": {"port": 51820, "enabled": true, "max_peers": 100},
  "openvpn": {"port": 1194, "enabled": true, "max_clients": 100},
  "shadowsocks": {"port": 8388, "enabled": true, "methods": ["aes-256-gcm"]},
  "slowdns": {"port": 53, "enabled": true, "upstream_dns": ["8.8.8.8", "1.1.1.1"]}
}
```

## Advanced Usage

### Admin Commands
```bash
# Start dashboard with advanced features
systemctl start emperor-vps

# Stop dashboard
systemctl stop emperor-vps

# View real-time logs
journalctl -u emperor-vps -f

# Add user with advanced permissions
python3 manage.py add-user username password --role admin --email user@example.com

# Delete user and all associated data
python3 manage.py del-user username --force

# Create advanced VPN configurations
python3 manage.py create-v2ray username --protocol vmess --port 443 --tls
python3 manage.py create-wireguard username --ip 10.0.0.100 --dns 8.8.8.8
```

### Advanced VPN Service Management
```bash
# Create SSH account with custom shell
python3 manage.py create-ssh username --shell /bin/bash --home /home/custom

# Create V2Ray account with multiple protocols
python3 manage.py create-v2ray username --protocols vmess,vless,trojan

# Create WireGuard account with custom configuration
python3 manage.py create-wireguard username --ip 10.0.0.100 --dns 1.1.1.1

# Create OpenVPN account with certificates
python3 manage.py create-openvpn username --cert-days 365 --key-size 2048
```

## Advanced Features

### 🔐 Security Features
- **Two-Factor Authentication** (TOTP)
- **Rate Limiting** and DDoS protection
- **SSL/TLS encryption** with auto-renewal
- **Firewall configuration** with UFW
- **Fail2ban integration** for brute force protection
- **Secure session management**
- **Password policies** and complexity requirements

### 📊 Advanced Monitoring
- **Real-time system metrics** (CPU, RAM, Disk, Network)
- **Service health monitoring** with auto-restart
- **Performance analytics** and trending
- **Resource usage alerts** via email/SMS
- **Custom monitoring dashboards**
- **Historical data** and reporting

### 🌐 Advanced VPN Features
- **Multi-protocol support** (VMess, VLESS, Trojan, Shadowsocks)
- **Load balancing** across multiple servers
- **Traffic shaping** and QoS
- **Bandwidth monitoring** and limits
- **Geographic routing** and geo-blocking
- **Custom DNS** and DoH/DoT support

### 🔧 Advanced Management
- **API endpoints** for automation
- **Webhook notifications** for events
- **Backup automation** with cloud storage
- **Auto-scaling** based on load
- **Multi-server management** from single dashboard
- **Custom scripts** and automation

## Support

- 📧 Email: support@emperor.com
- 💬 Discord: Emperor DevSupport
- 📖 Documentation: [Wiki](https://github.com/SLSTunnel/emperor-vps-manager/wiki)
- 🐛 Issues: [GitHub Issues](https://github.com/SLSTunnel/emperor-vps-manager/issues)

## License

MIT License - see LICENSE file for details

---

**Emperor DevSupport** - Professional VPS Management Solutions

**Advanced Features Include:**
- 🔥 Real-time monitoring with WebSocket
- 🎯 Advanced analytics and reporting
- 🛡️ Enterprise-grade security
- 📱 Progressive Web App
- 🌍 Multi-language support
- 🚀 Auto-scaling capabilities
- 📊 Advanced VPN protocols
- 🔔 Real-time notifications 