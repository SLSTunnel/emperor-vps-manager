#!/bin/bash

# Emperor DevSupport VPS Manager - Advanced Installation Script
# This script will install and configure the VPS manager on your server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
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
    echo -e "${BLUE}  Emperor DevSupport VPS Manager${NC}"
    echo -e "${BLUE}     Advanced Installation${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

print_header
print_status "Starting advanced installation..."

# Get server information
SERVER_IP=$(curl -s ifconfig.me)
SERVER_HOSTNAME=$(hostname)
print_info "Server IP: $SERVER_IP"
print_info "Hostname: $SERVER_HOSTNAME"

# Check system requirements
print_status "Checking system requirements..."
TOTAL_RAM=$(free -m | awk 'NR==2{printf "%.0f", $2/1024}')
if [ $TOTAL_RAM -lt 2 ]; then
    print_warning "Recommended minimum RAM: 2GB (Current: ${TOTAL_RAM}GB)"
fi

TOTAL_DISK=$(df -BG / | awk 'NR==2{print $2}' | sed 's/G//')
if [ $TOTAL_DISK -lt 20 ]; then
    print_warning "Recommended minimum disk: 20GB (Current: ${TOTAL_DISK}GB)"
fi

# Update system
print_status "Updating system packages..."
apt update && apt upgrade -y

# Install required packages
print_status "Installing required packages..."
apt install -y python3 python3-pip python3-venv nginx curl wget git ufw fail2ban redis-server \
    certbot python3-certbot-nginx htop iotop nethogs vnstat \
    wireguard openvpn shadowsocks-libev dnsmasq \
    build-essential libssl-dev libffi-dev python3-dev \
    supervisor logrotate

# Create application directory
print_status "Creating application directory..."
mkdir -p /opt/emperor-vps
cd /opt/emperor-vps

# Clone repository (if not already present)
if [ ! -d ".git" ]; then
    print_status "Cloning repository..."
    git clone https://github.com/SLSTunnel/emperor-vps-manager.git .
fi

# Create Python virtual environment
print_status "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
print_status "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create system user
print_status "Creating system user..."
useradd -r -s /bin/false emperor-vps || true

# Set permissions
print_status "Setting permissions..."
chown -R emperor-vps:emperor-vps /opt/emperor-vps
chmod +x /opt/emperor-vps/app.py

# Create systemd service
print_status "Creating systemd service..."
cat > /etc/systemd/system/emperor-vps.service << EOF
[Unit]
Description=Emperor DevSupport VPS Manager
After=network.target redis.service

[Service]
Type=simple
User=emperor-vps
Group=emperor-vps
WorkingDirectory=/opt/emperor-vps
Environment=PATH=/opt/emperor-vps/venv/bin
Environment=FLASK_ENV=production
Environment=REDIS_URL=redis://localhost:6379/0
ExecStart=/opt/emperor-vps/venv/bin/python app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Configure Redis
print_status "Configuring Redis..."
systemctl enable redis-server
systemctl start redis-server

# Configure Nginx with advanced settings
print_status "Configuring Nginx..."
cat > /etc/nginx/sites-available/emperor-vps << EOF
# Rate limiting
limit_req_zone \$binary_remote_addr zone=emperor:10m rate=10r/s;
limit_req_zone \$binary_remote_addr zone=login:10m rate=1r/s;

# Upstream for load balancing (future use)
upstream emperor_backend {
    server 127.0.0.1:5000;
    # Add more servers here for load balancing
}

server {
    listen 80;
    server_name _;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    # Rate limiting
    limit_req zone=emperor burst=20 nodelay;
    
    # Login rate limiting
    location /login {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location /static {
        alias /opt/emperor-vps/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied expired no-cache no-store private must-revalidate auth;
    gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/xml+rss application/javascript;
}
EOF

# Enable Nginx site
ln -sf /etc/nginx/sites-available/emperor-vps /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Configure firewall with advanced rules
print_status "Configuring firewall..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing

# Essential services
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

# Additional ports for advanced features
ufw allow 8080/tcp  # Alternative web port
ufw allow 8443/tcp  # Alternative SSL port

# Configure fail2ban with advanced rules
print_status "Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = auto

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3

[emperor-vps]
enabled = true
port = http,https
filter = emperor-vps
logpath = /var/log/emperor-vps/access.log
maxretry = 5
bantime = 7200
EOF

# Create fail2ban filter for emperor-vps
cat > /etc/fail2ban/filter.d/emperor-vps.conf << EOF
[Definition]
failregex = ^<HOST>.*"POST /login.*" 401
ignoreregex =
EOF

# Create SSL certificate (self-signed for now)
print_status "Creating SSL certificate..."
mkdir -p /etc/ssl/emperor-vps
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/emperor-vps/nginx.key \
    -out /etc/ssl/emperor-vps/nginx.crt \
    -subj "/C=US/ST=State/L=City/O=Emperor DevSupport/CN=localhost"

# Update Nginx config for SSL
cat > /etc/nginx/sites-available/emperor-vps << EOF
# Rate limiting
limit_req_zone \$binary_remote_addr zone=emperor:10m rate=10r/s;
limit_req_zone \$binary_remote_addr zone=login:10m rate=1r/s;

# Upstream for load balancing
upstream emperor_backend {
    server 127.0.0.1:5000;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name _;
    return 301 https://\$server_name\$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    server_name _;

    # SSL configuration
    ssl_certificate /etc/ssl/emperor-vps/nginx.crt;
    ssl_certificate_key /etc/ssl/emperor-vps/nginx.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Rate limiting
    limit_req zone=emperor burst=20 nodelay;
    
    # Login rate limiting
    location /login {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location /static {
        alias /opt/emperor-vps/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied expired no-cache no-store private must-revalidate auth;
    gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/xml+rss application/javascript;
}
EOF

# Create management script with advanced features
print_status "Creating advanced management script..."
cat > /usr/local/bin/emperor-vps << EOF
#!/bin/bash

# Emperor DevSupport VPS Manager - Advanced Management Script

case "\$1" in
    start)
        systemctl start emperor-vps
        systemctl start nginx
        systemctl start redis-server
        echo "✅ All services started"
        ;;
    stop)
        systemctl stop emperor-vps
        systemctl stop nginx
        systemctl stop redis-server
        echo "🛑 All services stopped"
        ;;
    restart)
        systemctl restart emperor-vps
        systemctl restart nginx
        systemctl restart redis-server
        echo "🔄 All services restarted"
        ;;
    status)
        echo "=== Emperor VPS Manager Status ==="
        systemctl status emperor-vps --no-pager -l
        echo ""
        echo "=== Nginx Status ==="
        systemctl status nginx --no-pager -l
        echo ""
        echo "=== Redis Status ==="
        systemctl status redis-server --no-pager -l
        ;;
    logs)
        journalctl -u emperor-vps -f
        ;;
    update)
        echo "🔄 Updating Emperor VPS Manager..."
        cd /opt/emperor-vps
        git pull
        source venv/bin/activate
        pip install -r requirements.txt
        systemctl restart emperor-vps
        echo "✅ Update completed"
        ;;
    backup)
        echo "💾 Creating backup..."
        /opt/emperor-vps/backup.sh
        ;;
    monitor)
        echo "📊 System monitoring..."
        htop
        ;;
    ssl)
        echo "🔒 SSL Certificate Management"
        echo "Usage: emperor-vps ssl [install|renew|status]"
        ;;
    firewall)
        echo "🔥 Firewall Management"
        ufw status
        ;;
    *)
        echo "Emperor DevSupport VPS Manager - Advanced Management"
        echo ""
        echo "Usage: \$0 {start|stop|restart|status|logs|update|backup|monitor|ssl|firewall}"
        echo ""
        echo "Commands:"
        echo "  start     - Start all services"
        echo "  stop      - Stop all services"
        echo "  restart   - Restart all services"
        echo "  status    - Show service status"
        echo "  logs      - View real-time logs"
        echo "  update    - Update from GitHub"
        echo "  backup    - Create system backup"
        echo "  monitor   - System monitoring"
        echo "  ssl       - SSL certificate management"
        echo "  firewall  - Firewall status"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/emperor-vps

# Create advanced monitoring script
print_status "Creating advanced monitoring script..."
cat > /opt/emperor-vps/monitor.sh << EOF
#!/bin/bash

# Emperor DevSupport VPS Manager - Advanced Monitoring

LOG_FILE="/var/log/emperor-vps-monitor.log"
ALERT_LOG="/var/log/emperor-vps-alerts.log"
EMAIL_ALERTS=false
DISCORD_WEBHOOK=""

log() {
    echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$1" >> \$LOG_FILE
}

alert() {
    echo "\$(date '+%Y-%m-%d %H:%M:%S') - ALERT: \$1" >> \$ALERT_LOG
    log "ALERT: \$1"
    
    if [ "\$EMAIL_ALERTS" = true ]; then
        echo "Alert: \$1" | mail -s "Emperor VPS Alert" admin@emperor.com
    fi
    
    if [ ! -z "\$DISCORD_WEBHOOK" ]; then
        curl -H "Content-Type: application/json" -X POST -d "{\\"content\\":\\"🚨 Emperor VPS Alert: \$1\\"}" \$DISCORD_WEBHOOK
    fi
}

# Check services
check_service() {
    local service=\$1
    local name=\$2
    
    if systemctl is-active --quiet \$service; then
        log "✓ \$name is running"
    else
        alert "✗ \$name is down - restarting"
        systemctl restart \$service
        sleep 5
        
        if systemctl is-active --quiet \$service; then
            log "✓ \$name restarted successfully"
        else
            alert "✗ \$name failed to restart"
        fi
    fi
}

# Check system resources
check_resources() {
    # CPU usage
    CPU_USAGE=\$(top -bn1 | grep "Cpu(s)" | awk '{print \$2}' | cut -d'%' -f1)
    if (( \$(echo "\$CPU_USAGE > 80" | bc -l) )); then
        alert "High CPU usage: \${CPU_USAGE}%"
    fi
    
    # Memory usage
    MEM_USAGE=\$(free | awk 'NR==2{printf "%.0f", \$3*100/\$2}')
    if [ \$MEM_USAGE -gt 80 ]; then
        alert "High memory usage: \${MEM_USAGE}%"
    fi
    
    # Disk usage
    DISK_USAGE=\$(df / | awk 'NR==2 {print \$5}' | sed 's/%//')
    if [ \$DISK_USAGE -gt 80 ]; then
        alert "High disk usage: \${DISK_USAGE}%"
    fi
    
    # Network monitoring
    NETWORK_ERRORS=\$(netstat -i | awk 'NR>2 {sum+=\$5} END {print sum}')
    if [ \$NETWORK_ERRORS -gt 100 ]; then
        alert "High network errors: \$NETWORK_ERRORS"
    fi
}

# Check VPN services
check_vpn_services() {
    # Check if VPN ports are listening
    local ports=(22 80 443 51820 1194 8388 53)
    
    for port in "\${ports[@]}"; do
        if ! netstat -tuln | grep -q ":\$port "; then
            alert "VPN port \$port is not listening"
        fi
    done
}

# Check database
check_database() {
    if [ ! -f "/opt/emperor-vps/emperor_vps.db" ]; then
        alert "Database file not found"
        return
    fi
    
    # Check database integrity
    if ! sqlite3 /opt/emperor-vps/emperor_vps.db "PRAGMA integrity_check;" | grep -q "ok"; then
        alert "Database integrity check failed"
    fi
}

# Check logs for errors
check_logs() {
    # Check for recent errors in application logs
    ERROR_COUNT=\$(journalctl -u emperor-vps --since "5 minutes ago" | grep -i error | wc -l)
    if [ \$ERROR_COUNT -gt 10 ]; then
        alert "High error count in logs: \$ERROR_COUNT errors in last 5 minutes"
    fi
}

# Main monitoring
log "Starting monitoring cycle"

# Check services
check_service emperor-vps "Emperor VPS Manager"
check_service nginx "Nginx"
check_service redis-server "Redis"
check_service fail2ban "Fail2ban"

# Check system resources
check_resources

# Check VPN services
check_vpn_services

# Check database
check_database

# Check logs
check_logs

log "Monitoring cycle completed"
EOF

chmod +x /opt/emperor-vps/monitor.sh

# Create advanced backup script
print_status "Creating advanced backup script..."
cat > /opt/emperor-vps/backup.sh << EOF
#!/bin/bash

# Emperor DevSupport VPS Manager - Advanced Backup Script

BACKUP_DIR="/opt/backups/emperor-vps"
DATE=\$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30
CLOUD_BACKUP=false
CLOUD_PATH=""

log() {
    echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$1"
}

# Create backup directory
mkdir -p \$BACKUP_DIR

log "Starting backup process..."

# Stop services for consistent backup
log "Stopping services..."
systemctl stop emperor-vps

# Database backup
log "Backing up database..."
cp /opt/emperor-vps/emperor_vps.db \$BACKUP_DIR/emperor_vps_\$DATE.db

# Configuration backup
log "Backing up configurations..."
tar -czf \$BACKUP_DIR/config_\$DATE.tar.gz \\
    /etc/nginx/sites-available/emperor-vps \\
    /etc/ssl/emperor-vps \\
    /etc/wireguard \\
    /etc/v2ray \\
    /etc/openvpn/server \\
    /etc/shadowsocks-libev \\
    /etc/dnsmasq.conf \\
    /etc/fail2ban/jail.local \\
    /etc/systemd/system/emperor-vps.service

# Application backup
log "Backing up application..."
tar -czf \$BACKUP_DIR/app_\$DATE.tar.gz \\
    /opt/emperor-vps/app.py \\
    /opt/emperor-vps/requirements.txt \\
    /opt/emperor-vps/templates \\
    /opt/emperor-vps/static \\
    /opt/emperor-vps/config \\
    /opt/emperor-vps/manage.py

# Log backup
log "Backing up logs..."
tar -czf \$BACKUP_DIR/logs_\$DATE.tar.gz \\
    /var/log/emperor-vps/ \\
    /var/log/nginx/ \\
    /var/log/fail2ban.log

# Create backup manifest
cat > \$BACKUP_DIR/manifest_\$DATE.txt << MANIFEST
Emperor VPS Manager Backup Manifest
===================================
Date: \$(date)
Server: \$(hostname)
IP: \$(curl -s ifconfig.me)

Backup Contents:
- Database: emperor_vps_\$DATE.db
- Configurations: config_\$DATE.tar.gz
- Application: app_\$DATE.tar.gz
- Logs: logs_\$DATE.tar.gz

System Information:
- OS: \$(lsb_release -d | cut -f2)
- Kernel: \$(uname -r)
- Disk Usage: \$(df -h / | awk 'NR==2 {print \$5}')
- Memory Usage: \$(free -h | awk 'NR==2 {print \$3 "/" \$2}')

Services Status:
- Emperor VPS: \$(systemctl is-active emperor-vps)
- Nginx: \$(systemctl is-active nginx)
- Redis: \$(systemctl is-active redis-server)
- Fail2ban: \$(systemctl is-active fail2ban)
MANIFEST

# Restart services
log "Restarting services..."
systemctl start emperor-vps

# Cloud backup (if enabled)
if [ "\$CLOUD_BACKUP" = true ] && [ ! -z "\$CLOUD_PATH" ]; then
    log "Uploading to cloud storage..."
    # Add your cloud backup logic here
    # Example: rclone copy \$BACKUP_DIR \$CLOUD_PATH
fi

# Cleanup old backups
log "Cleaning up old backups..."
find \$BACKUP_DIR -name "*.db" -mtime +\$RETENTION_DAYS -delete
find \$BACKUP_DIR -name "*.tar.gz" -mtime +\$RETENTION_DAYS -delete
find \$BACKUP_DIR -name "manifest_*.txt" -mtime +\$RETENTION_DAYS -delete

# Calculate backup size
BACKUP_SIZE=\$(du -sh \$BACKUP_DIR | cut -f1)
log "Backup completed successfully. Size: \$BACKUP_SIZE"

# Send notification
if [ ! -z "\$DISCORD_WEBHOOK" ]; then
    curl -H "Content-Type: application/json" -X POST -d "{\\"content\\":\\"💾 Emperor VPS backup completed. Size: \$BACKUP_SIZE\\"}" \$DISCORD_WEBHOOK
fi
EOF

chmod +x /opt/emperor-vps/backup.sh

# Enable and start services
print_status "Enabling and starting services..."
systemctl daemon-reload
systemctl enable emperor-vps
systemctl enable nginx
systemctl enable fail2ban
systemctl enable redis-server

systemctl start emperor-vps
systemctl start nginx
systemctl start fail2ban
systemctl start redis-server

# Create initial admin user
print_status "Creating initial admin user..."
cd /opt/emperor-vps
source venv/bin/activate
python3 -c "
import sqlite3
from werkzeug.security import generate_password_hash
conn = sqlite3.connect('emperor_vps.db')
c = conn.cursor()
c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, email TEXT, role TEXT DEFAULT \"user\", created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, is_active BOOLEAN DEFAULT 1)')
c.execute('INSERT OR IGNORE INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)', ('admin', generate_password_hash('emperor2024'), 'admin@emperor.com', 'admin'))
conn.commit()
conn.close()
print('Admin user created successfully!')
"

# Add monitoring to crontab
print_status "Setting up automated monitoring..."
(crontab -l 2>/dev/null; echo "*/5 * * * * /opt/emperor-vps/monitor.sh") | crontab -

# Add backup to crontab (daily at 2 AM)
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/emperor-vps/backup.sh") | crontab -

# Create log rotation
print_status "Setting up log rotation..."
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

/var/log/emperor-vps-alerts.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 emperor-vps emperor-vps
}

/opt/backups/emperor-vps/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
}
EOF

# Final configuration
print_status "Final configuration..."
echo "emperor-vps" > /etc/hostname
hostnamectl set-hostname emperor-vps

# Print completion message
print_header
print_success "Advanced installation completed successfully!"
echo ""
print_info "🎯 Advanced Features Installed:"
echo "  ✅ Real-time monitoring with alerts"
echo "  ✅ Advanced security with fail2ban"
echo "  ✅ SSL/TLS encryption"
echo "  ✅ Rate limiting and DDoS protection"
echo "  ✅ Automated backups"
echo "  ✅ Load balancing ready"
echo "  ✅ WebSocket support"
echo "  ✅ Redis caching"
echo ""
print_info "🌐 Access Information:"
echo "  HTTP:  http://$SERVER_IP"
echo "  HTTPS: https://$SERVER_IP"
echo ""
print_info "🔐 Default Login:"
echo "  Username: admin"
echo "  Password: emperor2024"
echo ""
print_info "🛠️ Advanced Management Commands:"
echo "  emperor-vps start    - Start all services"
echo "  emperor-vps status   - Check all services"
echo "  emperor-vps logs     - View real-time logs"
echo "  emperor-vps update   - Update from GitHub"
echo "  emperor-vps backup   - Create backup"
echo "  emperor-vps monitor  - System monitoring"
echo "  emperor-vps ssl      - SSL management"
echo "  emperor-vps firewall - Firewall status"
echo ""
print_warning "⚠️  Security Recommendations:"
echo "  • Change default admin password"
echo "  • Install proper SSL certificate"
echo "  • Configure firewall rules"
echo "  • Set up monitoring alerts"
echo "  • Enable 2FA for admin accounts"
echo ""
print_info "📊 Monitoring:"
echo "  • System monitoring runs every 5 minutes"
echo "  • Automated backups daily at 2 AM"
echo "  • Log rotation configured"
echo "  • Alert notifications ready"
echo ""
print_success "🚀 Emperor DevSupport VPS Manager is ready!"
print_info "Installation completed at: $(date)" 