#!/bin/bash

# Emperor DevSupport VPS Manager Installation Script
# This script downloads and installs the VPS manager

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
    echo -e "${BLUE}  Emperor DevSupport Installer${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

print_header
print_status "Starting installation..."

# Update system
print_status "Updating system packages..."
apt update && apt upgrade -y

# Install required packages
print_status "Installing required packages..."
apt install -y curl wget git python3 python3-pip python3-venv nginx certbot python3-certbot-nginx

# Create application directory
print_status "Creating application directory..."
mkdir -p /opt/emperor-vps
cd /opt/emperor-vps

# Download application files (if not already present)
if [ ! -f "app.py" ]; then
    print_status "Downloading application files..."
    # If you have a git repository, use:
    # git clone https://github.com/your-repo/emperor-vps.git .
    # Otherwise, copy files manually or download them
    print_warning "Please ensure all application files are in /opt/emperor-vps/"
    print_warning "Files needed: app.py, requirements.txt, templates/, static/"
fi

# Install Python dependencies
print_status "Installing Python dependencies..."
pip3 install flask flask-login werkzeug psutil

# Create emperor-vps user
print_status "Creating emperor-vps user..."
useradd -r -s /bin/false emperor-vps || true
chown -R emperor-vps:emperor-vps /opt/emperor-vps

# Run the setup script
print_status "Running setup script..."
if [ -f "setup.sh" ]; then
    chmod +x setup.sh
    ./setup.sh
else
    print_error "Setup script not found!"
    exit 1
fi

print_header
print_status "Installation completed successfully!"
print_status "Your Emperor VPS Manager is now ready to use." 