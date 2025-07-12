#!/bin/bash

# Emperor DevSupport VPS Manager Troubleshooting Script

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
    echo -e "${BLUE}  Emperor VPS Troubleshooter${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_header

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_warning "Some checks may require root privileges"
fi

# Get server IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "unknown")
print_status "Server IP: $SERVER_IP"

echo ""
print_status "Checking services..."

# Check Emperor VPS service
if systemctl is-active --quiet emperor-vps; then
    print_status "✓ Emperor VPS service is running"
else
    print_error "✗ Emperor VPS service is not running"
    print_status "Starting Emperor VPS service..."
    systemctl start emperor-vps
    sleep 2
    if systemctl is-active --quiet emperor-vps; then
        print_status "✓ Emperor VPS service started successfully"
    else
        print_error "✗ Failed to start Emperor VPS service"
        print_status "Checking logs:"
        journalctl -u emperor-vps --no-pager -l | tail -10
    fi
fi

# Check Nginx service
if systemctl is-active --quiet nginx; then
    print_status "✓ Nginx service is running"
else
    print_error "✗ Nginx service is not running"
    print_status "Starting Nginx service..."
    systemctl start nginx
    sleep 2
    if systemctl is-active --quiet nginx; then
        print_status "✓ Nginx service started successfully"
    else
        print_error "✗ Failed to start Nginx service"
        print_status "Checking logs:"
        journalctl -u nginx --no-pager -l | tail -10
    fi
fi

echo ""
print_status "Checking ports..."

# Check if Flask app is listening on port 5000
if netstat -tlnp 2>/dev/null | grep -q ":5000 "; then
    print_status "✓ Flask app is listening on port 5000"
else
    print_error "✗ Flask app is not listening on port 5000"
fi

# Check if Nginx is listening on port 80
if netstat -tlnp 2>/dev/null | grep -q ":80 "; then
    print_status "✓ Nginx is listening on port 80"
else
    print_error "✗ Nginx is not listening on port 80"
fi

# Check if Nginx is listening on port 443
if netstat -tlnp 2>/dev/null | grep -q ":443 "; then
    print_status "✓ Nginx is listening on port 443"
else
    print_error "✗ Nginx is not listening on port 443"
fi

echo ""
print_status "Checking firewall..."

# Check UFW status
if ufw status | grep -q "Status: active"; then
    print_status "✓ UFW firewall is active"
    print_status "UFW rules:"
    ufw status numbered | grep -E "(22|80|443|5000)"
else
    print_warning "⚠ UFW firewall is not active"
fi

echo ""
print_status "Testing connectivity..."

# Test local Flask app
if curl -s http://localhost:5000 > /dev/null; then
    print_status "✓ Flask app responds locally"
else
    print_error "✗ Flask app does not respond locally"
fi

# Test Nginx proxy
if curl -s http://localhost > /dev/null; then
    print_status "✓ Nginx proxy works locally"
else
    print_error "✗ Nginx proxy does not work locally"
fi

# Test external access
if curl -s http://$SERVER_IP > /dev/null; then
    print_status "✓ External HTTP access works"
else
    print_error "✗ External HTTP access does not work"
fi

echo ""
print_status "Checking files and permissions..."

# Check if app.py exists
if [ -f "/opt/emperor-vps/app.py" ]; then
    print_status "✓ app.py exists"
else
    print_error "✗ app.py not found in /opt/emperor-vps/"
fi

# Check if database exists
if [ -f "/opt/emperor-vps/emperor_vps.db" ]; then
    print_status "✓ Database exists"
else
    print_warning "⚠ Database does not exist (will be created on first run)"
fi

# Check Nginx configuration
if [ -f "/etc/nginx/sites-enabled/emperor-vps" ]; then
    print_status "✓ Nginx site configuration exists"
    if nginx -t > /dev/null 2>&1; then
        print_status "✓ Nginx configuration is valid"
    else
        print_error "✗ Nginx configuration has errors"
        nginx -t
    fi
else
    print_error "✗ Nginx site configuration not found"
fi

echo ""
print_status "Checking SSL certificates..."

# Check SSL certificates
if [ -f "/etc/ssl/emperor-vps/nginx.crt" ] && [ -f "/etc/ssl/emperor-vps/nginx.key" ]; then
    print_status "✓ SSL certificates exist"
else
    print_error "✗ SSL certificates not found"
fi

echo ""
print_status "Quick fixes..."

# Restart services if needed
print_status "Restarting services..."
systemctl restart emperor-vps
systemctl restart nginx

# Reload UFW
print_status "Reloading firewall..."
ufw reload

# Check if banner script exists
print_status "Testing banner script..."
if [ -f "/usr/local/bin/emperor-banner" ]; then
    print_status "✓ Banner script exists"
else
    print_error "✗ Banner script not found"
fi

# Test banner display
print_status "Testing banner display..."
/usr/local/bin/emperor-banner

echo ""
print_status "Troubleshooting completed!"
echo ""
print_status "If issues persist, check:"
echo "  - System logs: journalctl -u emperor-vps -f"
echo "  - Nginx logs: tail -f /var/log/nginx/error.log"
echo "  - Application logs: tail -f /var/log/emperor-vps-monitor.log"
echo ""
print_status "Access your dashboard:"
echo "  HTTP:  http://$SERVER_IP"
echo "  HTTPS: https://$SERVER_IP"
echo ""
print_warning "Default admin credentials: admin / emperor2024" 