#!/bin/bash

# Emperor DevSupport Banner Test Script
# This script tests all banner configurations

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

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}  Emperor Banner Test${NC}"
echo -e "${BLUE}================================${NC}"

# Test SSH banner
print_status "Testing SSH banner..."
if [ -f "/etc/ssh/banner" ]; then
    print_status "✓ SSH banner file exists"
    echo "SSH Banner content:"
    cat /etc/ssh/banner
    echo ""
else
    print_error "✗ SSH banner file not found"
fi

# Test OpenVPN banner
print_status "Testing OpenVPN banner..."
if [ -f "/etc/openvpn/server/banner.txt" ]; then
    print_status "✓ OpenVPN banner file exists"
    echo "OpenVPN Banner content:"
    cat /etc/openvpn/server/banner.txt
    echo ""
else
    print_error "✗ OpenVPN banner file not found"
fi

# Test V2Ray banner
print_status "Testing V2Ray banner..."
if [ -f "/etc/v2ray/banner.txt" ]; then
    print_status "✓ V2Ray banner file exists"
    echo "V2Ray Banner content:"
    cat /etc/v2ray/banner.txt
    echo ""
else
    print_error "✗ V2Ray banner file not found"
fi

# Test WireGuard banner
print_status "Testing WireGuard banner..."
if [ -f "/etc/wireguard/banner.txt" ]; then
    print_status "✓ WireGuard banner file exists"
    echo "WireGuard Banner content:"
    cat /etc/wireguard/banner.txt
    echo ""
else
    print_error "✗ WireGuard banner file not found"
fi

# Test Shadowsocks banner
print_status "Testing Shadowsocks banner..."
if [ -f "/etc/shadowsocks-libev/banner.txt" ]; then
    print_status "✓ Shadowsocks banner file exists"
    echo "Shadowsocks Banner content:"
    cat /etc/shadowsocks-libev/banner.txt
    echo ""
else
    print_error "✗ Shadowsocks banner file not found"
fi

# Test banner script
print_status "Testing banner script..."
if [ -f "/usr/local/bin/emperor-banner" ]; then
    print_status "✓ Banner script exists"
    echo "Running banner script:"
    /usr/local/bin/emperor-banner
else
    print_error "✗ Banner script not found"
fi

# Test SSH configuration
print_status "Testing SSH configuration..."
if grep -q "Banner /etc/ssh/banner" /etc/ssh/sshd_config; then
    print_status "✓ SSH banner is configured"
else
    print_error "✗ SSH banner not configured"
fi

# Test OpenVPN configuration
print_status "Testing OpenVPN configuration..."
if grep -q "banner /etc/openvpn/server/banner.txt" /etc/openvpn/server/server-tcp.conf; then
    print_status "✓ OpenVPN TCP banner is configured"
else
    print_error "✗ OpenVPN TCP banner not configured"
fi

if grep -q "banner /etc/openvpn/server/banner.txt" /etc/openvpn/server/server-udp.conf; then
    print_status "✓ OpenVPN UDP banner is configured"
else
    print_error "✗ OpenVPN UDP banner not configured"
fi

echo -e "${BLUE}================================${NC}"
print_status "Banner test completed!"
echo -e "${BLUE}================================${NC}" 