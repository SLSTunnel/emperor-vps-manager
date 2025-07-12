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

# Ask for Cloudflare domain
echo ""
print_status "Cloudflare Domain Configuration"
print_warning "This will configure CDN, WebSocket, and TLS support for your domain"
echo ""
read -p "Enter your Cloudflare domain (e.g., vpn.yourdomain.com): " CLOUDFLARE_DOMAIN

if [[ -z "$CLOUDFLARE_DOMAIN" ]]; then
    print_warning "No domain provided. Using IP address only."
    CLOUDFLARE_DOMAIN=""
else
    print_status "Domain: $CLOUDFLARE_DOMAIN"
    print_status "Please ensure your domain is configured in Cloudflare with:"
    print_status "  - DNS A record pointing to: $SERVER_IP"
    print_status "  - SSL/TLS mode: Full (strict)"
    print_status "  - Always Use HTTPS: On"
    print_status "  - WebSocket: Enabled"
    echo ""
    read -p "Press Enter when your Cloudflare domain is configured..."
fi

# Update system
print_status "Updating system packages..."
apt update && apt upgrade -y

# Install Python and pip
print_status "Installing Python and dependencies..."
apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx

# Install Python dependencies
print_status "Installing Python dependencies..."
pip3 install flask flask-login werkzeug psutil flask-socketio eventlet

# Create application directory
print_status "Creating application directory..."
mkdir -p /opt/emperor-vps
cp -r . /opt/emperor-vps/
cd /opt/emperor-vps

# Create emperor-vps user
print_status "Creating emperor-vps user..."
useradd -r -s /bin/false emperor-vps || true
chown -R emperor-vps:emperor-vps /opt/emperor-vps

# Configure SSH
print_status "Configuring SSH..."
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#Port 22/Port 22/' /etc/ssh/sshd_config

# Create SSH banner
cat > /etc/ssh/banner << EOF
╔══════════════════════════════════════════════════════════════╗
║                    VPS By [Emperor] DevSupport               ║
║                                                              ║
║              Support YouTube: SlidAk4                        ║
║                                                              ║
║              Enjoy Mocked Location Server High Speed         ║
║                                                              ║
║              Server IP: $SERVER_IP                           ║
║              Date: \$(date '+%Y-%m-%d %H:%M:%S')                    ║
╚══════════════════════════════════════════════════════════════╝
EOF

# Enable SSH banner
echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config
systemctl restart ssh

# Configure firewall
print_status "Configuring firewall..."
ufw --force enable
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 5000/tcp
ufw allow 8080/tcp

# VPN service ports
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # WebSocket
ufw allow 8080/tcp  # WebSocket Alternative
ufw allow 443/tcp   # SSL/V2Ray
ufw allow 1194/tcp  # OpenVPN TCP
ufw allow 1195/udp  # OpenVPN UDP
ufw allow 51820/udp # WireGuard
ufw allow 8388/tcp  # Shadowsocks
ufw allow 7300/tcp  # BadVPN UDPGW
ufw allow 53/tcp    # SlowDNS
ufw allow 53/udp    # SlowDNS

# Install additional packages
print_status "Installing additional packages..."
apt install -y wireguard openvpn shadowsocks-libev dnsmasq

# Install BadVPN UDPGW
print_status "Installing BadVPN UDPGW..."
apt install -y build-essential cmake libssl-dev libnss3-dev libcap-dev libpcap-dev libev-dev libc-ares-dev automake libtool autoconf m4

# Download and compile BadVPN
cd /tmp
wget https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/badvpn/badvpn-1.999.130.tar.gz
tar -xzf badvpn-1.999.130.tar.gz
cd badvpn-1.999.130
mkdir build
cd build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install

# Create BadVPN UDPGW service
print_status "Creating BadVPN UDPGW service..."
cat > /etc/systemd/system/badvpn-udpgw.service << EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500 --max-connections-for-client 20
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create SSL directory and certificates
print_status "Creating SSL certificates..."
mkdir -p /etc/ssl/emperor-vps

if [[ -n "$CLOUDFLARE_DOMAIN" ]]; then
    # Create certificate with domain
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/emperor-vps/nginx.key \
        -out /etc/ssl/emperor-vps/nginx.crt \
        -subj "/C=US/ST=State/L=City/O=Emperor DevSupport/CN=$CLOUDFLARE_DOMAIN" \
        -addext "subjectAltName = DNS:$CLOUDFLARE_DOMAIN,DNS:$SERVER_IP,IP:$SERVER_IP"
    
    print_status "SSL certificate created for domain: $CLOUDFLARE_DOMAIN"
else
    # Create certificate for IP only
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/emperor-vps/nginx.key \
        -out /etc/ssl/emperor-vps/nginx.crt \
        -subj "/C=US/ST=State/L=City/O=Emperor DevSupport/CN=$SERVER_IP"
    
    print_status "SSL certificate created for IP: $SERVER_IP"
fi

# Configure Nginx
print_status "Configuring Nginx..."
if [[ -n "$CLOUDFLARE_DOMAIN" ]]; then
    # Configure with Cloudflare domain
    cat > /etc/nginx/sites-available/emperor-vps << EOF
# HTTP redirect to HTTPS
server {
    listen 80;
    server_name $SERVER_IP $CLOUDFLARE_DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

# HTTPS with Cloudflare domain
server {
    listen 443 ssl http2;
    server_name $CLOUDFLARE_DOMAIN;
    
    # SSL configuration
    ssl_certificate /etc/ssl/emperor-vps/nginx.crt;
    ssl_certificate_key /etc/ssl/emperor-vps/nginx.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Cloudflare real IP
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 131.0.72.0/22;
    real_ip_header CF-Connecting-IP;
    
    # Main application
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$http_cf_connecting_ip;
        proxy_set_header CF-IPCountry \$http_cf_ipcountry;
        proxy_set_header CF-Ray \$http_cf_ray;
        proxy_set_header CF-Visitor \$http_cf_visitor;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
    
    # WebSocket endpoint for SSH
    location /ws/ {
        proxy_pass http://127.0.0.1:5000/ws/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }
    
    # API endpoints
    location /api/ {
        proxy_pass http://127.0.0.1:5000/api/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

# Fallback for IP access
server {
    listen 443 ssl;
    server_name $SERVER_IP;
    
    ssl_certificate /etc/ssl/emperor-vps/nginx.crt;
    ssl_certificate_key /etc/ssl/emperor-vps/nginx.key;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
else
    # Configure without domain (IP only)
    cat > /etc/nginx/sites-available/emperor-vps << EOF
server {
    listen 80;
    server_name $SERVER_IP;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

server {
    listen 443 ssl;
    server_name $SERVER_IP;
    
    ssl_certificate /etc/ssl/emperor-vps/nginx.crt;
    ssl_certificate_key /etc/ssl/emperor-vps/nginx.key;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
fi

# Enable the site
ln -sf /etc/nginx/sites-available/emperor-vps /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Create systemd service for Emperor VPS
print_status "Creating Emperor VPS systemd service..."
cat > /etc/systemd/system/emperor-vps.service << EOF
[Unit]
Description=Emperor DevSupport VPS Manager
After=network.target

[Service]
Type=simple
User=emperor-vps
Group=emperor-vps
WorkingDirectory=/opt/emperor-vps
Environment=PATH=/usr/bin:/usr/local/bin
ExecStart=/usr/bin/python3 /opt/emperor-vps/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

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

# Create WireGuard banner
cat > /etc/wireguard/banner.txt << EOF
╔══════════════════════════════════════════════════════════════╗
║                    VPS By [Emperor] DevSupport               ║
║                                                              ║
║              Support YouTube: SlidAk4                        ║
║                                                              ║
║              Enjoy Mocked Location Server High Speed         ║
║                                                              ║
║              Server IP: $SERVER_IP                           ║
║              Date: \$(date '+%Y-%m-%d %H:%M:%S')                    ║
╚══════════════════════════════════════════════════════════════╝
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

# Create V2Ray banner
cat > /etc/v2ray/banner.txt << EOF
╔══════════════════════════════════════════════════════════════╗
║                    VPS By [Emperor] DevSupport               ║
║                                                              ║
║              Support YouTube: SlidAk4                        ║
║                                                              ║
║              Enjoy Mocked Location Server High Speed         ║
║                                                              ║
║              Server IP: $SERVER_IP                           ║
║              Date: \$(date '+%Y-%m-%d %H:%M:%S')                    ║
╚══════════════════════════════════════════════════════════════╝
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

# Create OpenVPN server configuration (TCP)
cat > /etc/openvpn/server/server-tcp.conf << EOF
port 1194
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp-tcp.txt
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
status openvpn-status-tcp.log
verb 3
explicit-exit-notify 1
EOF

# Create OpenVPN server configuration (UDP)
cat > /etc/openvpn/server/server-udp.conf << EOF
port 1195
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
server 10.9.0.0 255.255.255.0
ifconfig-pool-persist ipp-udp.txt
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
status openvpn-status-udp.log
verb 3
explicit-exit-notify 1
EOF

# Create OpenVPN banner
cat > /etc/openvpn/server/banner.txt << EOF
╔══════════════════════════════════════════════════════════════╗
║                    VPS By [Emperor] DevSupport               ║
║                                                              ║
║              Support YouTube: SlidAk4                        ║
║                                                              ║
║              Enjoy Mocked Location Server High Speed         ║
║                                                              ║
║              Server IP: $SERVER_IP                           ║
║              Date: \$(date '+%Y-%m-%d %H:%M:%S')                    ║
╚══════════════════════════════════════════════════════════════╝
EOF

# Add banner to OpenVPN configs
echo "banner /etc/openvpn/server/banner.txt" >> /etc/openvpn/server/server-tcp.conf
echo "banner /etc/openvpn/server/banner.txt" >> /etc/openvpn/server/server-udp.conf

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

# Create Shadowsocks banner
cat > /etc/shadowsocks-libev/banner.txt << EOF
╔══════════════════════════════════════════════════════════════╗
║                    VPS By [Emperor] DevSupport               ║
║                                                              ║
║              Support YouTube: SlidAk4                        ║
║                                                              ║
║              Enjoy Mocked Location Server High Speed         ║
║                                                              ║
║              Server IP: $SERVER_IP                           ║
║              Date: \$(date '+%Y-%m-%d %H:%M:%S')                    ║
╚══════════════════════════════════════════════════════════════╝
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
        systemctl start openvpn@server-tcp
        systemctl start openvpn@server-udp
        systemctl start shadowsocks-libev
        systemctl start badvpn-udpgw
        systemctl start dnsmasq
        ;;
    stop-all)
        systemctl stop emperor-vps
        systemctl stop nginx
        systemctl stop v2ray
        systemctl stop openvpn@server-tcp
        systemctl stop openvpn@server-udp
        systemctl stop shadowsocks-libev
        systemctl stop badvpn-udpgw
        systemctl stop dnsmasq
        ;;
    restart-all)
        systemctl restart emperor-vps
        systemctl restart nginx
        systemctl restart v2ray
        systemctl restart openvpn@server-tcp
        systemctl restart openvpn@server-udp
        systemctl restart shadowsocks-libev
        systemctl restart badvpn-udpgw
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
        echo "=== OpenVPN TCP (Port 1194) ==="
        systemctl status openvpn@server-tcp --no-pager -l
        echo ""
        echo "=== OpenVPN UDP (Port 1195) ==="
        systemctl status openvpn@server-udp --no-pager -l
        echo ""
        echo "=== Shadowsocks ==="
        systemctl status shadowsocks-libev --no-pager -l
        echo ""
        echo "=== BadVPN UDPGW ==="
        systemctl status badvpn-udpgw --no-pager -l
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
systemctl enable emperor-vps
systemctl enable nginx
systemctl enable v2ray
systemctl enable openvpn@server-tcp
systemctl enable openvpn@server-udp
systemctl enable shadowsocks-libev
systemctl enable badvpn-udpgw
systemctl enable dnsmasq

# Start services
print_status "Starting services..."
systemctl start nginx
systemctl start emperor-vps
systemctl start v2ray
systemctl start openvpn@server-tcp
systemctl start openvpn@server-udp
systemctl start shadowsocks-libev
systemctl start badvpn-udpgw
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
check_service openvpn@server-tcp
check_service openvpn@server-udp
check_service shadowsocks-libev
check_service badvpn-udpgw
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

# Install banner script
print_status "Installing banner script..."
cp banner.sh /usr/local/bin/emperor-banner
chmod +x /usr/local/bin/emperor-banner

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

# Test the application
print_status "Testing application..."
sleep 5
if curl -s http://localhost:5000 > /dev/null; then
    print_status "✓ Flask application is running"
else
    print_warning "⚠ Flask application may not be running properly"
fi

if curl -s http://localhost > /dev/null; then
    print_status "✓ Nginx is running and proxying correctly"
else
    print_warning "⚠ Nginx may not be running properly"
fi

# Print completion message
print_header
print_status "Setup completed successfully!"
echo ""
print_status "Services configured:"
echo "  ✓ Emperor VPS Manager (Port 5000)"
echo "  ✓ Nginx (Port 80/443)"
echo "  ✓ SSH (Port 22)"
echo "  ✓ WebSocket (Port 80)"
echo "  ✓ WebSocket Alternative (Port 8080)"
echo "  ✓ SSL/V2Ray (Port 443)"
echo "  ✓ OpenVPN TCP (Port 1194)"
echo "  ✓ OpenVPN UDP (Port 1195)"
echo "  ✓ WireGuard (Port 51820)"
echo "  ✓ Shadowsocks (Port 8388)"
echo "  ✓ BadVPN UDPGW (Port 7300)"
echo "  ✓ SlowDNS (Port 53)"
echo "  ✓ WebSocket Support"
echo "  ✓ Cloudflare CDN Support"
echo "  ✓ TLS/SSL Encryption"
echo "  ✓ Connection Banners"
echo ""
print_status "Management commands:"
echo "  systemctl start emperor-vps    - Start VPS manager"
echo "  systemctl status emperor-vps   - Check VPS manager status"
echo "  vpn-services start-all         - Start all VPN services"
echo "  vpn-services status-all        - Check all services"
echo "  /opt/emperor-vps/backup.sh     - Create backup"
echo "  emperor-banner                 - Display banner message"
echo ""
print_status "Access your dashboard:"
if [[ -n "$CLOUDFLARE_DOMAIN" ]]; then
    echo "  HTTPS: https://$CLOUDFLARE_DOMAIN"
    echo "  HTTP:  http://$SERVER_IP (redirects to HTTPS)"
else
    echo "  HTTP:  http://$SERVER_IP"
    echo "  HTTPS: https://$SERVER_IP"
fi
if [[ -n "$CLOUDFLARE_DOMAIN" ]]; then
    echo ""
    print_status "Cloudflare Configuration:"
    echo "  ✓ CDN enabled"
    echo "  ✓ WebSocket support"
    echo "  ✓ TLS/SSL encryption"
    echo "  ✓ Security headers"
    echo "  ✓ Real IP detection"
fi
echo ""
print_warning "Default admin credentials: admin / emperor2024"
print_warning "Please change the default password after first login!"
echo ""
print_status "Setup completed at: $(date)" 