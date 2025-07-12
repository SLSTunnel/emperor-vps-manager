# Emperor DevSupport VPS Manager - Installation Guide

## Quick Installation

### 1. Download and Install

```bash
# Download the application
wget https://github.com/your-repo/emperor-vps/archive/main.zip
unzip main.zip
cd emperor-vps-main

# Make scripts executable
chmod +x install.sh setup.sh troubleshoot.sh

# Run installation as root
sudo ./install.sh
```

### 2. Manual Installation

If you prefer to install manually:

```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install dependencies
sudo apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx

# 3. Install Python packages
sudo pip3 install flask flask-login werkzeug psutil

# 4. Copy files to /opt/emperor-vps/
sudo mkdir -p /opt/emperor-vps
sudo cp -r . /opt/emperor-vps/

# 5. Run setup
cd /opt/emperor-vps
sudo chmod +x setup.sh
sudo ./setup.sh
```

## What Gets Installed

### Services
- **Emperor VPS Manager** (Flask web app on port 5000)
- **Nginx** (Reverse proxy on ports 80/443)
- **V2Ray** (VPN service on port 443)
- **WireGuard** (VPN service on port 51820)
- **OpenVPN** (VPN service on port 1194)
- **Shadowsocks** (VPN service on port 8388)
- **SlowDNS** (DNS service on port 53)

### Features
- Web-based dashboard for managing VPN accounts
- User management system
- Service monitoring and auto-restart
- Automatic backups
- SSL/TLS encryption
- Firewall configuration

## Access Information

### Dashboard Access
- **HTTP**: http://your-server-ip
- **HTTPS**: https://your-server-ip

### Default Credentials
- **Username**: admin
- **Password**: emperor2024

⚠️ **Important**: Change the default password after first login!

## Management Commands

### Service Management
```bash
# Start/stop/restart Emperor VPS
sudo systemctl start emperor-vps
sudo systemctl stop emperor-vps
sudo systemctl restart emperor-vps

# Check status
sudo systemctl status emperor-vps

# View logs
sudo journalctl -u emperor-vps -f
```

### VPN Services Management
```bash
# Start all VPN services
sudo vpn-services start-all

# Stop all VPN services
sudo vpn-services stop-all

# Check all services status
sudo vpn-services status-all
```

### Backup and Monitoring
```bash
# Create manual backup
sudo /opt/emperor-vps/backup.sh

# View monitoring logs
sudo tail -f /var/log/emperor-vps-monitor.log
```

## Troubleshooting

### Run the Troubleshooter
```bash
sudo chmod +x troubleshoot.sh
sudo ./troubleshoot.sh
```

### Common Issues

#### 1. Dashboard Not Loading
```bash
# Check if services are running
sudo systemctl status emperor-vps nginx

# Check if ports are open
sudo netstat -tlnp | grep -E "(80|443|5000)"

# Check firewall
sudo ufw status
```

#### 2. VPN Services Not Working
```bash
# Check VPN service status
sudo vpn-services status-all

# Check specific service
sudo systemctl status v2ray
sudo systemctl status openvpn@server
```

#### 3. SSL Certificate Issues
```bash
# Check certificate files
ls -la /etc/ssl/emperor-vps/

# Regenerate certificates
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/emperor-vps/nginx.key \
    -out /etc/ssl/emperor-vps/nginx.crt \
    -subj "/C=US/ST=State/L=City/O=Emperor DevSupport/CN=$(curl -s ifconfig.me)"
```

### Log Files
- **Application logs**: `/var/log/emperor-vps-monitor.log`
- **Nginx logs**: `/var/log/nginx/error.log`
- **System logs**: `journalctl -u emperor-vps -f`

## Security Considerations

### 1. Change Default Password
After installation, immediately change the default admin password through the web interface.

### 2. Configure Firewall
The setup script configures UFW with basic rules. Consider adding additional security:
```bash
# Allow only specific IPs for SSH
sudo ufw allow from your-ip-address to any port 22
sudo ufw deny 22
```

### 3. SSL Certificates
For production use, replace self-signed certificates with Let's Encrypt:
```bash
sudo certbot --nginx -d your-domain.com
```

### 4. Regular Updates
Keep the system updated:
```bash
sudo apt update && sudo apt upgrade -y
```

## Support

If you encounter issues:

1. Run the troubleshooting script: `sudo ./troubleshoot.sh`
2. Check the logs for error messages
3. Ensure all services are running: `sudo vpn-services status-all`
4. Verify firewall configuration: `sudo ufw status`

## File Structure

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
├── monitor.sh           # Monitoring script
└── backup.sh            # Backup script
```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 