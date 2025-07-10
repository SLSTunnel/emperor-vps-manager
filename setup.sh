#!/bin/bash

# Emperor DevSupport VPS Manager Setup Script
# This script configures the VPS manager after installation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  Emperor DevSupport Setup${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

print_header
print_status "Starting setup..."

# Get server IP
SERVER_IP=$(curl -s ifconfig.me)
print_status "Server IP: $SERVER_IP"

# Configure SSH
print_status "Configuring SSH..."
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#Port 22/Port 22/' /etc/ssh/sshd_config
systemctl restart ssh

# Configure firewall
print_status "Configuring firewall..."
ufw --force enable
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 5000/tcp

# VPN service ports
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # SSHWS
ufw allow 443/tcp   # V2Ray
ufw allow 51820/udp # WireGuard
ufw allow 1194/udp  # OpenVPN
ufw allow 8388/tcp  # Shadowsocks
ufw allow 53/tcp    # SlowDNS
ufw allow 53/udp    # SlowDNS

# Install additional packages
print_status "Installing additional packages..."
apt install -y wireguard openvpn shadowsocks-libev dnsmasq

# Configure WireGuard
print_status "Configuring WireGuard..."
mkdir -p /etc/wireguard
wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key

# Create WireGuard configuration
cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $(cat /etc/wireguard/private.key)
Address = 10.0.0.1/24
ListenPort = 51820
SaveConfig = true
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Configure V2Ray
print_status "Configuring V2Ray..."
mkdir -p /etc/v2ray

# Create V2Ray configuration
cat > /etc/v2ray/config.json << EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vmess",
      "settings": {
        "clients": []
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
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF

# Create V2Ray service
cat > /etc/systemd/system/v2ray.service << EOF
[Unit]
Description=V2Ray Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/v2ray -config /etc/v2ray/config.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Install V2Ray if not present
if ! command -v v2ray &> /dev/null; then
    print_status "Installing V2Ray..."
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
fi

# Configure OpenVPN
print_status "Configuring OpenVPN..."
mkdir -p /etc/openvpn/server

# Generate OpenVPN keys
openssl genrsa -out /etc/openvpn/server/ca.key 2048
openssl req -new -x509 -days 365 -key /etc/openvpn/server/ca.key -out /etc/openvpn/server/ca.crt -subj "/C=US/ST=State/L=City/O=Emperor DevSupport/CN=VPN CA"

# Create OpenVPN server configuration
cat > /etc/openvpn/server/server.conf << EOF
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
tls-auth ta.key 0
cipher AES-256-CBC
auth SHA256
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
explicit-exit-notify 1
EOF

# Configure Shadowsocks
print_status "Configuring Shadowsocks..."
cat > /etc/shadowsocks-libev/config.json << EOF
{
    "server":"0.0.0.0",
    "server_port":8388,
    "password":"emperor2024",
    "timeout":300,
    "method":"aes-256-gcm",
    "fast_open": false,
    "mode": "tcp_and_udp"
}
EOF

# Configure SlowDNS
print_status "Configuring SlowDNS..."
cat > /etc/dnsmasq.conf << EOF
# Emperor DevSupport SlowDNS Configuration
port=53
domain-needed
bogus-priv
no-resolv
no-poll
server=8.8.8.8
server=8.8.4.4
cache-size=1000
local-ttl=3600
neg-ttl=3600
EOF

# Create service management script
cat > /usr/local/bin/vpn-services << EOF
#!/bin/bash

case "\$1" in
    start-all)
        systemctl start emperor-vps
        systemctl start nginx
        systemctl start v2ray
        systemctl start openvpn@server
        systemctl start shadowsocks-libev
        systemctl start dnsmasq
        ;;
    stop-all)
        systemctl stop emperor-vps
        systemctl stop nginx
        systemctl stop v2ray
        systemctl stop openvpn@server
        systemctl stop shadowsocks-libev
        systemctl stop dnsmasq
        ;;
    restart-all)
        systemctl restart emperor-vps
        systemctl restart nginx
        systemctl restart v2ray
        systemctl restart openvpn@server
        systemctl restart shadowsocks-libev
        systemctl restart dnsmasq
        ;;
    status-all)
        echo "=== Emperor VPS Manager ==="
        systemctl status emperor-vps --no-pager -l
        echo ""
        echo "=== Nginx ==="
        systemctl status nginx --no-pager -l
        echo ""
        echo "=== V2Ray ==="
        systemctl status v2ray --no-pager -l
        echo ""
        echo "=== OpenVPN ==="
        systemctl status openvpn@server --no-pager -l
        echo ""
        echo "=== Shadowsocks ==="
        systemctl status shadowsocks-libev --no-pager -l
        echo ""
        echo "=== DNS ==="
        systemctl status dnsmasq --no-pager -l
        ;;
    *)
        echo "Usage: \$0 {start-all|stop-all|restart-all|status-all}"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/vpn-services

# Enable services
print_status "Enabling services..."
systemctl enable v2ray
systemctl enable openvpn@server
systemctl enable shadowsocks-libev
systemctl enable dnsmasq

# Start services
print_status "Starting services..."
systemctl start v2ray
systemctl start openvpn@server
systemctl start shadowsocks-libev
systemctl start dnsmasq

# Create monitoring script
cat > /opt/emperor-vps/monitor.sh << EOF
#!/bin/bash

# Emperor DevSupport VPS Monitor
LOG_FILE="/var/log/emperor-vps-monitor.log"

log() {
    echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$1" >> \$LOG_FILE
}

# Check services
check_service() {
    local service=\$1
    if systemctl is-active --quiet \$service; then
        log "✓ \$service is running"
    else
        log "✗ \$service is down - restarting"
        systemctl restart \$service
    fi
}

# Monitor services
check_service emperor-vps
check_service nginx
check_service v2ray
check_service openvpn@server
check_service shadowsocks-libev
check_service dnsmasq

# Check disk space
DISK_USAGE=\$(df / | awk 'NR==2 {print \$5}' | sed 's/%//')
if [ \$DISK_USAGE -gt 80 ]; then
    log "⚠ High disk usage: \${DISK_USAGE}%"
fi

# Check memory usage
MEM_USAGE=\$(free | awk 'NR==2{printf "%.0f", \$3*100/\$2}')
if [ \$MEM_USAGE -gt 80 ]; then
    log "⚠ High memory usage: \${MEM_USAGE}%"
fi
EOF

chmod +x /opt/emperor-vps/monitor.sh

# Add monitoring to crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /opt/emperor-vps/monitor.sh") | crontab -

# Create backup script
cat > /opt/emperor-vps/backup.sh << EOF
#!/bin/bash

# Emperor DevSupport VPS Backup
BACKUP_DIR="/opt/backups/emperor-vps"
DATE=\$(date +%Y%m%d_%H%M%S)
mkdir -p \$BACKUP_DIR

# Backup database
cp /opt/emperor-vps/emperor_vps.db \$BACKUP_DIR/emperor_vps_\$DATE.db

# Backup configurations
tar -czf \$BACKUP_DIR/config_\$DATE.tar.gz \\
    /etc/nginx/sites-available/emperor-vps \\
    /etc/ssl/emperor-vps \\
    /etc/wireguard \\
    /etc/v2ray \\
    /etc/openvpn/server \\
    /etc/shadowsocks-libev \\
    /etc/dnsmasq.conf

# Keep only last 7 backups
find \$BACKUP_DIR -name "*.db" -mtime +7 -delete
find \$BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete

echo "Backup completed: \$BACKUP_DIR"
EOF

chmod +x /opt/emperor-vps/backup.sh

# Add backup to crontab (daily at 2 AM)
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/emperor-vps/backup.sh") | crontab -

# Create log rotation
cat > /etc/logrotate.d/emperor-vps << EOF
/var/log/emperor-vps-monitor.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 emperor-vps emperor-vps
}
EOF

# Final configuration
print_status "Final configuration..."
echo "emperor-vps" > /etc/hostname
hostnamectl set-hostname emperor-vps

# Print completion message
print_header
print_status "Setup completed successfully!"
echo ""
print_status "Services configured:"
echo "  ✓ SSH (Port 22)"
echo "  ✓ SSHWS (Port 80)"
echo "  ✓ V2Ray (Port 443)"
echo "  ✓ WireGuard (Port 51820)"
echo "  ✓ OpenVPN (Port 1194)"
echo "  ✓ Shadowsocks (Port 8388)"
echo "  ✓ SlowDNS (Port 53)"
echo ""
print_status "Management commands:"
echo "  emperor-vps start    - Start VPS manager"
echo "  vpn-services start-all    - Start all VPN services"
echo "  vpn-services status-all   - Check all services"
echo "  /opt/emperor-vps/backup.sh - Create backup"
echo ""
print_status "Access your dashboard:"
echo "  HTTP:  http://$SERVER_IP"
echo "  HTTPS: https://$SERVER_IP"
echo ""
print_warning "Default admin credentials: admin / emperor2024"
print_warning "Please change the default password after first login!"
echo ""
print_status "Setup completed at: \$(date)" 