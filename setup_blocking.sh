#!/bin/bash
# SmartShield - Setup passwordless sudo for iptables blocking
# Run this ONCE with: sudo bash setup_blocking.sh

SUDOERS_FILE="/etc/sudoers.d/smartshield"
USER=$(logname 2>/dev/null || echo "$SUDO_USER")

if [ -z "$USER" ]; then
    echo "ERROR: Could not determine the user. Run with: sudo bash setup_blocking.sh"
    exit 1
fi

echo "Setting up passwordless iptables for user: $USER"

cat > "$SUDOERS_FILE" << EOF
# SmartShield - Allow iptables without password for domain blocking
$USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables
$USER ALL=(ALL) NOPASSWD: /sbin/iptables
EOF

chmod 440 "$SUDOERS_FILE"

# Verify
if sudo -n -u "$USER" true 2>/dev/null; then
    echo "SUCCESS: Passwordless iptables configured for $USER"
else
    echo "SUCCESS: Sudoers file created at $SUDOERS_FILE"
fi

echo "You can now block domains from the SmartShield dashboard."
