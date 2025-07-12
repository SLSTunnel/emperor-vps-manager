# Emperor DevSupport VPS Manager - Advanced Deployment Guide

## 🚀 Quick Start Guide

This guide will walk you through adding the VPS manager to GitHub and deploying it to your VPS with advanced features.

## 📋 Prerequisites

- A GitHub account
- A VPS with Ubuntu 20.04+ or Debian 11+
- Root access to your VPS
- Minimum 2GB RAM, 20GB storage
- Basic knowledge of command line

## 🔧 Step 1: Add to GitHub

### 1.1 Create GitHub Repository

1. Go to [GitHub.com](https://github.com) and sign in
2. Click the "+" icon in the top right corner
3. Select "New repository"
4. Fill in the details:
   - **Repository name**: `emperor-vps-manager`
   - **Description**: `Professional VPS Management Dashboard with Advanced VPN Services`
   - **Visibility**: Choose Public or Private
   - **Initialize**: Check "Add a README file"
5. Click "Create repository"

### 1.2 Upload Files to GitHub

#### Option A: Using GitHub Web Interface (Recommended for Drag & Drop)
1. In your new repository, click "Add file" → "Upload files"
2. **Drag and drop all project files** in this order:
   ```
   📁 emperor-vps-manager/
   ├── 📄 README.md
   ├── 📄 requirements.txt
   ├── 📄 app.py
   ├── 📄 manage.py
   ├── 📄 install.sh
   ├── 📄 setup.sh
   ├── 📄 LICENSE
   ├── 📄 DEPLOYMENT_GUIDE.md
   ├── 📁 templates/
   │   ├── 📄 base.html
   │   ├── 📄 dashboard.html
   │   ├── 📄 login.html
   │   ├── 📄 users.html
   │   └── 📄 services.html
   ├── 📁 static/
   │   ├── 📁 css/
   │   │   └── 📄 style.css
   │   └── 📁 js/
   │       └── 📄 dashboard.js
   └── 📁 config/
       ├── 📄 admin.json
       └── 📄 services.json
   ```
3. Add commit message: "Initial commit: Emperor VPS Manager with Advanced Features"
4. Click "Commit changes"

#### Option B: Using Git Command Line
```bash
# Clone the repository
git clone https://github.com/SLSTunnel/emperor-vps-manager.git
cd emperor-vps-manager

# Copy all project files to this directory
# Then commit and push
git add .
git commit -m "Initial commit: Emperor VPS Manager with Advanced Features"
git push origin main
```

### 1.3 Repository Structure
Your GitHub repository should look like this:
```
📁 emperor-vps-manager/
├── 📄 README.md                    # Project documentation
├── 📄 requirements.txt             # Python dependencies
├── 📄 app.py                       # Main Flask application
├── 📄 manage.py                    # CLI management tool
├── 📄 install.sh                   # Advanced installation script
├── 📄 setup.sh                     # Service configuration
├── 📄 LICENSE                      # MIT license
├── 📄 DEPLOYMENT_GUIDE.md          # This guide
├── 📁 templates/                   # HTML templates
│   ├── 📄 base.html               # Base template with hacker theme
│   ├── 📄 dashboard.html          # Main dashboard
│   ├── 📄 login.html              # Login page
│   ├── 📄 users.html              # User management
│   └── 📄 services.html           # VPN services management
├── 📁 static/                      # Static assets
│   ├── 📁 css/
│   │   └── 📄 style.css           # Advanced CSS styles
│   └── 📁 js/
│       └── 📄 dashboard.js        # Dashboard JavaScript
└── 📁 config/                      # Configuration files
    ├── 📄 admin.json              # Admin settings
    └── 📄 services.json           # VPN service configurations
```

## 🖥️ Step 2: Deploy to VPS

### 2.1 Connect to Your VPS

```bash
ssh root@your-vps-ip
```

### 2.2 Quick Installation (Recommended)

```bash
# Download and run the advanced installation script
curl -sSL https://raw.githubusercontent.com/SLSTunnel/emperor-vps-manager/main/install.sh | bash
```

### 2.3 Manual Installation (Alternative)

If the quick installation doesn't work, follow these steps:

```bash
# Update system
apt update && apt upgrade -y

# Install dependencies
apt install -y python3 python3-pip python3-venv nginx curl wget git ufw fail2ban redis-server

# Clone repository
git clone https://github.com/SLSTunnel/emperor-vps-manager.git
cd emperor-vps-manager

# Setup Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run setup script
chmod +x setup.sh
./setup.sh

# Start services
systemctl enable emperor-vps
systemctl start emperor-vps
```

## 🔐 Step 3: Access Your Dashboard

### 3.1 Get Your VPS IP
```bash
curl ifconfig.me
```

### 3.2 Access Dashboard
- **HTTP**: `http://YOUR_VPS_IP` (redirects to HTTPS)
- **HTTPS**: `https://YOUR_VPS_IP`

### 3.3 Default Login Credentials
- **Username**: `admin`
- **Password**: `emperor2024`

⚠️ **IMPORTANT**: Change the default password immediately after first login!

## 🛠️ Step 4: Advanced Configuration

### 4.1 Change Admin Password

1. Login to the dashboard
2. Go to Settings → Change Password
3. Enter new secure password

### 4.2 Configure Advanced VPN Services

1. Go to Services page
2. Enable/disable services as needed
3. Configure advanced settings:
   - **V2Ray**: Multiple protocols (VMess, VLESS, Trojan)
   - **WireGuard**: Custom IP ranges and DNS
   - **OpenVPN**: Certificate management
   - **Shadowsocks**: Multiple encryption methods
   - **SlowDNS**: Custom DNS servers

### 4.3 SSL Certificate (Production)

For production use, install a proper SSL certificate:

```bash
# Install Certbot
apt install -y certbot python3-certbot-nginx

# Get SSL certificate
certbot --nginx -d your-domain.com

# Auto-renewal
crontab -e
# Add this line:
0 12 * * * /usr/bin/certbot renew --quiet
```

### 4.4 Advanced Security Configuration

```bash
# Configure firewall rules
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 5000/tcp

# Configure fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# Check security status
emperor-vps firewall
```

## 📊 Step 5: Advanced Management Commands

### 5.1 Service Management
```bash
# Start all services
emperor-vps start

# Stop all services
emperor-vps stop

# Restart all services
emperor-vps restart

# Check service status
emperor-vps status

# View real-time logs
emperor-vps logs

# Update application
emperor-vps update

# Create backup
emperor-vps backup

# System monitoring
emperor-vps monitor

# SSL management
emperor-vps ssl

# Firewall status
emperor-vps firewall
```

### 5.2 Advanced VPN Service Management
```bash
# Start all VPN services
vpn-services start-all

# Stop all VPN services
vpn-services stop-all

# Check all service status
vpn-services status-all
```

### 5.3 Advanced User Management (CLI)
```bash
# Add user with advanced permissions
python3 manage.py add-user username password --role admin --email user@example.com

# Delete user and all data
python3 manage.py del-user username --force

# List all users
python3 manage.py list-users

# Create advanced SSH account
python3 manage.py create-ssh username --shell /bin/bash --home /home/custom

# Create V2Ray account with multiple protocols
python3 manage.py create-v2ray username --protocols vmess,vless,trojan

# Create WireGuard account with custom config
python3 manage.py create-wireguard username --ip 10.0.0.100 --dns 1.1.1.1

# Create OpenVPN account with certificates
python3 manage.py create-openvpn username --cert-days 365 --key-size 2048
```

## 🔧 Step 6: Advanced Customization

### 6.1 Change Theme Colors
Edit `templates/base.html` and modify CSS variables:
```css
:root {
    --neon-green: #00ff41;
    --neon-blue: #00d4ff;
    --neon-purple: #bc13fe;
    --dark-bg: #0a0a0a;
    --darker-bg: #050505;
}
```

### 6.2 Add Custom VPN Services
1. Edit `config/services.json`
2. Add your service configuration
3. Update `app.py` with service logic
4. Add service templates

### 6.3 Advanced Backup Configuration
```bash
# Manual backup
/opt/emperor-vps/backup.sh

# Configure cloud backup
# Edit /opt/emperor-vps/backup.sh and set CLOUD_BACKUP=true

# Automatic backups run daily at 2 AM
```

### 6.4 Monitoring Configuration
```bash
# Edit monitoring settings
nano /opt/emperor-vps/monitor.sh

# Configure alerts
# Set EMAIL_ALERTS=true for email notifications
# Set DISCORD_WEBHOOK="your-webhook-url" for Discord alerts

# Monitoring runs every 5 minutes
```

## 🚨 Advanced Troubleshooting

### Common Issues

#### 1. Port Already in Use
```bash
# Check what's using the port
netstat -tulpn | grep :5000

# Kill the process
kill -9 PID_NUMBER
```

#### 2. Permission Denied
```bash
# Fix permissions
chown -R emperor-vps:emperor-vps /opt/emperor-vps
chmod +x /opt/emperor-vps/*.py
```

#### 3. Service Won't Start
```bash
# Check service status
systemctl status emperor-vps

# View detailed logs
journalctl -u emperor-vps -f

# Check Redis connection
systemctl status redis-server
```

#### 4. Database Issues
```bash
# Reinitialize database
cd /opt/emperor-vps
source venv/bin/activate
python3 manage.py init
```

#### 5. Firewall Issues
```bash
# Check firewall status
ufw status

# Allow specific ports
ufw allow 5000/tcp
ufw allow 80/tcp
ufw allow 443/tcp
```

#### 6. SSL Certificate Issues
```bash
# Check SSL certificate
openssl x509 -in /etc/ssl/emperor-vps/nginx.crt -text -noout

# Renew certificate
certbot renew
```

#### 7. Performance Issues
```bash
# Check system resources
htop
iotop
nethogs

# Check application logs
journalctl -u emperor-vps --since "1 hour ago"
```

## 📞 Advanced Support

### Getting Help
- **Documentation**: Check the README.md file
- **Issues**: Create an issue on GitHub
- **Discord**: Join Emperor DevSupport server

### Log Files
- **Application logs**: `/var/log/emperor-vps/`
- **System logs**: `journalctl -u emperor-vps`
- **Nginx logs**: `/var/log/nginx/`
- **Monitoring logs**: `/var/log/emperor-vps-monitor.log`
- **Alert logs**: `/var/log/emperor-vps-alerts.log`

## 🔄 Advanced Updates

### Automatic Updates
```bash
# Update from GitHub
cd /opt/emperor-vps
git pull
source venv/bin/activate
pip install -r requirements.txt
systemctl restart emperor-vps
```

### Manual Updates
```bash
# Use the update command
emperor-vps update
```

### Backup Before Update
```bash
# Create backup before updating
emperor-vps backup

# Then update
emperor-vps update
```

## 🎯 Advanced Features

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

## 🎯 Next Steps

1. **Security**: Change default passwords and enable 2FA
2. **Monitoring**: Set up monitoring alerts and notifications
3. **Backup**: Configure automated backups and cloud storage
4. **SSL**: Install proper SSL certificate for production
5. **Domain**: Point your domain to the VPS
6. **Users**: Create additional admin users with proper roles
7. **Services**: Configure VPN services for your specific needs
8. **Performance**: Optimize for your expected load
9. **Scaling**: Set up load balancing for high availability
10. **Automation**: Configure webhooks and API integrations

## 📝 Advanced Notes

- The dashboard runs on port 5000 by default
- All VPN services are configured with secure defaults
- Automatic backups run daily at 2 AM
- System monitoring runs every 5 minutes
- Logs are rotated automatically
- Redis caching is enabled for better performance
- WebSocket support for real-time updates
- Rate limiting prevents abuse
- Fail2ban protects against brute force attacks

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
- 💾 Automated backups
- 🔄 Load balancing ready

For support, visit: https://github.com/SLSTunnel/emperor-vps-manager 