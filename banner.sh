#!/bin/bash

# Emperor DevSupport Banner Script
# This script displays the banner message for VPN connections

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get server IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "unknown")

# Display banner
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    VPS By [Emperor] DevSupport               ║"
echo "║                                                              ║"
echo "║              Support YouTube: SlidAk4                        ║"
echo "║                                                              ║"
echo "║              Enjoy Mocked Location Server High Speed         ║"
echo "║                                                              ║"
echo "║              Server IP: $SERVER_IP                           ║"
echo "║              Date: $(date '+%Y-%m-%d %H:%M:%S')                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Additional information
echo -e "${GREEN}Welcome to Emperor DevSupport VPS!${NC}"
echo -e "${YELLOW}For support, visit: https://youtube.com/@SlidAk4${NC}"
echo -e "${BLUE}Server Status: Online${NC}"
echo "" 