# Emperor DevSupport VPS Manager

A comprehensive VPN management system with advanced features, Cloudflare CDN integration, and multi-protocol support.

![Emperor VPS Manager](https://img.shields.io/badge/Emperor-VPS%20Manager-green)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Flask](https://img.shields.io/badge/Flask-2.0+-lightgrey)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 🌟 Features

### **Multi-Protocol VPN Support**
- ✅ **SSH** (Port 22) - Standard SSH connections
- ✅ **SSH + SSL** - Encrypted SSH connections
- ✅ **SSH + WebSocket** (Port 80) - SSH over WebSocket
- ✅ **WebSocket Alternative** (Port 8080) - Alternative WebSocket port
- ✅ **OpenVPN TCP** (Port 1194) - OpenVPN over TCP
- ✅ **OpenVPN UDP** (Port 1195) - OpenVPN over UDP
- ✅ **V2Ray VMess** (Port 443) - Modern VMess protocol
- ✅ **WireGuard** (Port 51820) - Next-generation VPN
- ✅ **Shadowsocks** (Port 8388) - SOCKS5 proxy
- ✅ **BadVPN UDPGW** (Port 7300) - UDP tunneling gateway
- ✅ **SlowDNS** (Port 53) - DNS tunneling

### **Advanced Management Features**
- ✅ **Web-based Dashboard** - Modern, responsive interface
- ✅ **User Management** - Create, manage, and delete users
- ✅ **Account Expiration** - Set custom expiration dates (1-365 days)
- ✅ **Connection Limits** - Control max simultaneous connections (1-10)
- ✅ **Real-time Monitoring** - System stats and service status
- ✅ **Automatic Backups** - Daily automated backups
- ✅ **Service Management** - Start/stop/restart all services
- ✅ **Connection Banners** - Custom welcome messages

### **Cloudflare Integration**
- ✅ **CDN Support** - Full Cloudflare CDN integration
- ✅ **WebSocket Support** - Native WebSocket through Cloudflare
- ✅ **TLS/SSL Encryption** - Automatic SSL certificate generation
- ✅ **Security Headers** - HSTS, XSS protection, frame options
- ✅ **Real IP Detection** - Proper Cloudflare IP handling

### **Security & Reliability**
- ✅ **Firewall Configuration** - UFW with all necessary ports
- ✅ **Service Monitoring** - Automatic restart on failure
- ✅ **Log Management** - Comprehensive logging and rotation
- ✅ **SSL/TLS Encryption** - Modern cipher suites
- ✅ **User Authentication** - Secure login system

## 🚀 Quick Installation

### **Automatic Installation**
```bash
# Download and run the installation script
wget https://raw.githubusercontent.com/your-repo/emperor-vps/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

### **Manual Installation**
```bash
# 1. Clone the repository
git clone https://github.com/your-repo/emperor-vps.git
cd emperor-vps

# 2. Make scripts executable
chmod +x setup.sh install.sh troubleshoot.sh

# 3. Run setup as root
sudo ./setup.sh
```

## 📋 Prerequisites

- **Operating System**: Ubuntu 18.04+ / Debian 9+
- **Python**: 3.8 or higher
- **Root Access**: Required for installation
- **Domain** (Optional): For Cloudflare CDN integration

## 🔧 Installation Process

### **1. System Requirements**
The setup script will automatically install:
- Python 3.8+ and pip
- Nginx web server
- OpenVPN, WireGuard, V2Ray, Shadowsocks
- BadVPN UDPGW
- All required dependencies

### **2. Cloudflare Domain Setup** (Optional)
During installation, you'll be prompted for your Cloudflare domain:
```
Enter your Cloudflare domain (e.g., vpn.yourdomain.com):
```

**Required Cloudflare Settings:**
- DNS A record pointing to your server IP
- SSL/TLS mode: Full (strict)
- Always Use HTTPS: On
- WebSocket: Enabled

### **3. Port Configuration**
The system configures these ports automatically:
- **22** - SSH
- **80** - WebSocket / HTTP (redirects to HTTPS)
- **443** - SSL/V2Ray
- **8080** - WebSocket Alternative
- **1194** - OpenVPN TCP
- **1195** - OpenVPN UDP
- **51820** - WireGuard
- **7300** - BadVPN UDPGW
- **8388** - Shadowsocks
- **53** - SlowDNS

## 🎯 Usage

### **Access Dashboard**
- **With Domain**: `https://yourdomain.com`
- **Without Domain**: `http://your-server-ip` or `https://your-server-ip`

### **Default Credentials**
- **Username**: `admin`
- **Password**: `emperor2024`

⚠️ **Important**: Change the default password after first login!

### **Create Enhanced SSH Accounts**
1. Login to dashboard
2. Click "Create Enhanced SSH"
3. Fill in:
   - Username
   - Password (optional - auto-generates if empty)
   - Expire Days (1-365)
   - Max Connections (1-10)
4. Click "Create Enhanced SSH Account"

**Enhanced SSH Features:**
- SSH Direct (Port 22)
- SSH + SSL encryption
- SSH + WebSocket (Port 80)
- OpenVPN TCP/UDP access
- V2Ray VMess support
- WireGuard configuration
- Shadowsocks proxy
- BadVPN UDPGW tunneling

## 🛠️ Management Commands

### **Service Management**
```bash
# Start all services
sudo vpn-services start-all

# Stop all services
sudo vpn-services stop-all

# Restart all services
sudo vpn-services restart-all

# Check all services status
sudo vpn-services status-all
```

### **Individual Service Control**
```bash
# Emperor VPS Manager
sudo systemctl start emperor-vps
sudo systemctl status emperor-vps
sudo journalctl -u emperor-vps -f

# VPN Services
sudo systemctl status openvpn@server-tcp
sudo systemctl status openvpn@server-udp
sudo systemctl status v2ray
sudo systemctl status wireguard
sudo systemctl status badvpn-udpgw
```

### **Banner Management**
```bash
# Display banner
emperor-banner

# Test all banner configurations
./test-banner.sh
```

### **Backup & Maintenance**
```bash
# Create manual backup
sudo /opt/emperor-vps/backup.sh

# View monitoring logs
sudo tail -f /var/log/emperor-vps-monitor.log

# Run troubleshooting
sudo ./troubleshoot.sh
```

## 🔍 Troubleshooting

### **Common Issues**

#### **Dashboard Not Loading**
```bash
# Check if services are running
sudo vpn-services status-all

# Check if ports are open
sudo netstat -tlnp | grep -E "(80|443|5000)"

# Check firewall
sudo ufw status
```

#### **VPN Services Not Working**
```bash
# Check specific service
sudo systemctl status openvpn@server-tcp
sudo systemctl status v2ray

# View service logs
sudo journalctl -u openvpn@server-tcp -f
sudo journalctl -u v2ray -f
```

#### **SSL Certificate Issues**
```bash
# Check certificate files
ls -la /etc/ssl/emperor-vps/

# Regenerate certificates
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/emperor-vps/nginx.key \
    -out /etc/ssl/emperor-vps/nginx.crt \
    -subj "/C=US/ST=State/L=City/O=Emperor DevSupport/CN=$(curl -s ifconfig.me)"
```

### **Log Files**
- **Application logs**: `/var/log/emperor-vps-monitor.log`
- **Nginx logs**: `/var/log/nginx/error.log`
- **System logs**: `journalctl -u emperor-vps -f`
- **VPN logs**: `journalctl -u openvpn@server-tcp -f`

## 🗂️ File Structure

```
/opt/emperor-vps/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/            # HTML templates
├── static/              # CSS/JS files
├── emperor_vps.db       # SQLite database
├── setup.sh             # Setup script
├── install.sh           # Installation script
├── troubleshoot.sh      # Troubleshooting script
├── test-banner.sh       # Banner test script
├── banner.sh            # Banner display script
├── monitor.sh           # Monitoring script
└── backup.sh            # Backup script

/etc/
├── nginx/sites-available/emperor-vps  # Nginx configuration
├── ssl/emperor-vps/                   # SSL certificates
├── openvpn/server/                    # OpenVPN configurations
├── v2ray/                             # V2Ray configuration
├── wireguard/                         # WireGuard configuration
├── shadowsocks-libev/                 # Shadowsocks configuration
└── systemd/system/                    # Service files
```

## 🔧 Configuration

### **Nginx Configuration**
- Reverse proxy to Flask app (port 5000)
- SSL/TLS termination
- WebSocket support
- Cloudflare integration
- Security headers

### **Database Schema**
```sql
-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT 1
);

-- VPN accounts table
CREATE TABLE vpn_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    is_active BOOLEAN DEFAULT 1
);
```

## 🚀 API Endpoints

### **Authentication**
- `POST /login` - User login
- `POST /logout` - User logout

### **User Management**
- `GET /users` - List all users (admin only)
- `POST /create_user` - Create new user (admin only)
- `POST /delete_user` - Delete user (admin only)

### **VPN Management**
- `POST /create_vpn` - Create VPN account
- `POST /create_enhanced_ssh` - Create enhanced SSH account
- `POST /api/delete_vpn_account` - Delete VPN account
- `GET /api/vpn_accounts` - List VPN accounts
- `GET /api/vpn_config/<username>/<service_type>` - Get VPN config

### **System Monitoring**
- `GET /api/stats` - System statistics
- `GET /api/logs` - System logs
- `POST /api/toggle_service` - Toggle service (admin only)
- `POST /api/change_port` - Change service port (admin only)

## 🔒 Security Considerations

### **1. Change Default Password**
After installation, immediately change the default admin password through the web interface.

### **2. Firewall Configuration**
The setup script configures UFW with basic rules. Consider adding additional security:
```bash
# Allow only specific IPs for SSH
sudo ufw allow from your-ip-address to any port 22
sudo ufw deny 22
```

### **3. SSL Certificates**
For production use, replace self-signed certificates with Let's Encrypt:
```bash
sudo certbot --nginx -d your-domain.com
```

### **4. Regular Updates**
Keep the system updated:
```bash
sudo apt update && sudo apt upgrade -y
```

## 🗑️ Uninstallation

To completely remove Emperor VPS Manager:
```bash
# Run the removal script
sudo ./remove.sh
```

This will remove:
- All application files
- Systemd services
- Configuration files
- SSL certificates
- Database files
- Log files
- Cron jobs

## 📞 Support

### **YouTube Channel**
- **Support**: [SlidAk4](https://youtube.com/@SlidAk4)

### **Banner Message**
```
╔══════════════════════════════════════════════════════════════╗
║                    VPS By [Emperor] DevSupport               ║
║                                                              ║
║              Support YouTube: SlidAk4                        ║
║                                                              ║
║              Enjoy Mocked Location Server High Speed         ║
║                                                              ║
║              Server IP: [YOUR_SERVER_IP]                     ║
║              Date: [CURRENT_DATE_TIME]                       ║
╚══════════════════════════════════════════════════════════════╝
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 Changelog

### **v2.0.0** - Major Update
- ✅ Added Cloudflare CDN integration
- ✅ Added BadVPN UDPGW support
- ✅ Enhanced SSH accounts with expiration and connection limits
- ✅ Added connection banners
- ✅ Improved WebSocket support
- ✅ Added comprehensive monitoring
- ✅ Enhanced security features

### **v1.0.0** - Initial Release
- ✅ Basic VPN management
- ✅ Multi-protocol support
- ✅ Web-based dashboard
- ✅ User management system

---

**Made with ❤️ by Emperor DevSupport** 