# VPN Testing Guide - Emperor DevSupport VPS Manager

## 🧪 Testing VPN Connections

This guide will help you test all VPN services to ensure they work properly with VPN apps.

## 📱 VPN Apps for Testing

### Android Apps
- **V2Ray**: V2RayNG, V2Ray for Android
- **WireGuard**: WireGuard (official)
- **Shadowsocks**: Shadowsocks (official), ShadowsocksR
- **OpenVPN**: OpenVPN Connect (official)
- **SSH**: Termius, JuiceSSH

### iOS Apps
- **V2Ray**: Shadowrocket, Quantumult X
- **WireGuard**: WireGuard (official)
- **Shadowsocks**: Shadowrocket, Quantumult X
- **OpenVPN**: OpenVPN Connect (official)

### Desktop Apps
- **V2Ray**: V2RayN (Windows), V2RayX (macOS), Qv2ray
- **WireGuard**: WireGuard (official)
- **Shadowsocks**: Shadowsocks (official)
- **OpenVPN**: OpenVPN (official)

## 🔧 Service-Specific Testing

### 1. V2Ray (VMess) Testing

#### Create Account
1. Go to Services page
2. Click "Create VPN Account"
3. Select "V2Ray Account (VMess)"
4. Enter username and click "Create VPN"

#### Test Configuration
1. **Copy VMess Link**: Click "Copy" button next to VMess link
2. **Import to App**:
   - **V2RayNG**: Tap + → Import from clipboard
   - **Shadowrocket**: Tap + → VMess → Paste link
   - **V2RayN**: Right-click → Import from clipboard

#### Expected Results
- ✅ Connection established
- ✅ Internet traffic routed through VPN
- ✅ IP address changed to server IP
- ✅ No DNS leaks

#### Troubleshooting
```bash
# Check V2Ray service status
systemctl status v2ray

# Check V2Ray logs
journalctl -u v2ray -f

# Check port 443
netstat -tuln | grep :443

# Test connectivity
curl -I https://www.google.com
```

### 2. WireGuard Testing

#### Create Account
1. Go to Services page
2. Click "Create VPN Account"
3. Select "WireGuard Account"
4. Enter username and click "Create VPN"

#### Test Configuration
1. **Scan QR Code**: Use WireGuard app to scan QR code
2. **Manual Import**: Copy config file and import manually
3. **Connect**: Tap the connection in WireGuard app

#### Expected Results
- ✅ Connection established
- ✅ Internet traffic routed through VPN
- ✅ IP address changed to server IP
- ✅ Fast connection speed

#### Troubleshooting
```bash
# Check WireGuard service
systemctl status wg-quick@wg0

# Check WireGuard interface
ip link show wg0

# Check WireGuard peers
wg show

# Check firewall rules
ufw status
```

### 3. Shadowsocks Testing

#### Create Account
1. Go to Services page
2. Click "Create VPN Account"
3. Select "Shadowsocks Account"
4. Enter username and click "Create VPN"

#### Test Configuration
1. **Copy SS Link**: Click "Copy" button next to Shadowsocks link
2. **Import to App**:
   - **Shadowsocks**: Tap + → Scan QR code or import link
   - **Shadowrocket**: Tap + → Shadowsocks → Paste link

#### Expected Results
- ✅ Connection established
- ✅ Internet traffic routed through VPN
- ✅ IP address changed to server IP

#### Troubleshooting
```bash
# Check Shadowsocks service
systemctl status shadowsocks-libev

# Check Shadowsocks config
cat /etc/shadowsocks-libev/config.json

# Check port 8388
netstat -tuln | grep :8388

# Test connectivity
curl -I http://www.google.com
```

### 4. SSH Testing

#### Create Account
1. Go to Services page
2. Click "Create VPN Account"
3. Select "SSH Account"
4. Enter username and click "Create VPN"

#### Test Configuration
1. **Use SSH Client**:
   - **Termius**: Add new host with server IP, username, password
   - **JuiceSSH**: Create new connection with credentials
   - **Desktop**: `ssh username@server-ip`

#### Expected Results
- ✅ SSH connection established
- ✅ Can execute commands on server
- ✅ Secure encrypted connection

#### Troubleshooting
```bash
# Check SSH service
systemctl status ssh

# Check SSH logs
tail -f /var/log/auth.log

# Test SSH connection
ssh username@localhost

# Check SSH config
cat /etc/ssh/sshd_config
```

### 5. OpenVPN Testing

#### Create Account
1. Go to Services page
2. Click "Create VPN Account"
3. Select "OpenVPN Account"
4. Enter username and click "Create VPN"

#### Test Configuration
1. **Download Config**: Click "Download Config" button
2. **Import to App**:
   - **OpenVPN Connect**: Import .ovpn file
   - **Desktop**: Import config file

#### Expected Results
- ✅ Connection established
- ✅ Internet traffic routed through VPN
- ✅ IP address changed to server IP

#### Troubleshooting
```bash
# Check OpenVPN service
systemctl status openvpn@server

# Check OpenVPN logs
journalctl -u openvpn@server -f

# Check port 1194
netstat -tuln | grep :1194

# Check certificates
ls -la /etc/openvpn/server/
```

## 🌐 Connection Testing

### Basic Connectivity Test
```bash
# Test internet connectivity
curl -I https://www.google.com

# Test DNS resolution
nslookup google.com

# Test speed
curl -o /dev/null -s -w "Download: %{speed_download} bytes/sec\n" https://speed.cloudflare.com/__down
```

### VPN Leak Testing
```bash
# Test DNS leaks
nslookup whoami.akamai.net

# Test WebRTC leaks
curl -s https://am.i.mullvad.net/ip

# Test IPv6 leaks
curl -6 -s https://ipv6.google.com
```

### Performance Testing
```bash
# Test download speed
wget -O /dev/null http://speedtest.wdc01.softlayer.com/downloads/test100.zip

# Test upload speed
curl -T /dev/zero http://speedtest.wdc01.softlayer.com/upload.php

# Test latency
ping -c 10 google.com
```

## 🔍 Common Issues and Solutions

### 1. Connection Refused
**Symptoms**: App shows "Connection refused" or "Cannot connect"
**Solutions**:
```bash
# Check if service is running
systemctl status v2ray
systemctl status wg-quick@wg0
systemctl status shadowsocks-libev

# Check if port is open
netstat -tuln | grep :443
netstat -tuln | grep :51820
netstat -tuln | grep :8388

# Check firewall
ufw status
ufw allow 443/tcp
ufw allow 51820/udp
ufw allow 8388/tcp
```

### 2. Slow Connection
**Symptoms**: VPN connects but internet is slow
**Solutions**:
```bash
# Check server resources
htop
df -h
free -h

# Check network interface
ip link show
ethtool eth0

# Optimize TCP settings
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
sysctl -p
```

### 3. DNS Leaks
**Symptoms**: IP changes but DNS requests go through ISP
**Solutions**:
```bash
# Configure DNS
echo 'nameserver 8.8.8.8' > /etc/resolv.conf
echo 'nameserver 1.1.1.1' >> /etc/resolv.conf

# Block DNS leaks in firewall
ufw deny out 53/tcp
ufw deny out 53/udp
```

### 4. Certificate Errors
**Symptoms**: SSL/TLS errors in V2Ray
**Solutions**:
```bash
# Check certificate
openssl x509 -in /etc/ssl/emperor-vps/nginx.crt -text -noout

# Renew certificate
certbot renew

# Update V2Ray config
systemctl restart v2ray
```

## 📊 Monitoring VPN Usage

### Check Active Connections
```bash
# V2Ray connections
ss -tuln | grep :443

# WireGuard connections
wg show

# Shadowsocks connections
ss -tuln | grep :8388

# OpenVPN connections
cat /var/log/openvpn-status.log
```

### Monitor Bandwidth
```bash
# Install monitoring tools
apt install -y vnstat iftop nethogs

# Monitor bandwidth
vnstat -i eth0
iftop -i eth0
nethogs eth0
```

### Check Logs
```bash
# V2Ray logs
journalctl -u v2ray -f

# WireGuard logs
journalctl -u wg-quick@wg0 -f

# Shadowsocks logs
journalctl -u shadowsocks-libev -f

# OpenVPN logs
journalctl -u openvpn@server -f
```

## 🎯 Testing Checklist

### Before Testing
- [ ] All services are running
- [ ] Firewall allows necessary ports
- [ ] SSL certificates are valid
- [ ] DNS is properly configured

### During Testing
- [ ] VPN connects successfully
- [ ] Internet traffic is routed through VPN
- [ ] IP address changes to server IP
- [ ] No DNS leaks detected
- [ ] Connection speed is acceptable
- [ ] No connection drops

### After Testing
- [ ] All VPN apps work correctly
- [ ] Configurations are saved
- [ ] Users can connect independently
- [ ] Monitoring is set up
- [ ] Backups are configured

## 🚀 Performance Optimization

### Server Optimization
```bash
# Enable TCP BBR
echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
sysctl -p

# Optimize memory
echo 'vm.swappiness=10' >> /etc/sysctl.conf
sysctl -p

# Optimize disk I/O
echo 'vm.dirty_ratio=15' >> /etc/sysctl.conf
echo 'vm.dirty_background_ratio=5' >> /etc/sysctl.conf
sysctl -p
```

### Network Optimization
```bash
# Optimize TCP settings
echo 'net.ipv4.tcp_fastopen=3' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_slow_start_after_idle=0' >> /etc/sysctl.conf
sysctl -p

# Enable TCP window scaling
echo 'net.ipv4.tcp_window_scaling=1' >> /etc/sysctl.conf
sysctl -p
```

---

**Emperor DevSupport** - Professional VPS Management Solutions

For support, visit: https://github.com/SLSTunnel/emperor-vps-manager 