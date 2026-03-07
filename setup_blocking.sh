#!/bin/bash
# SmartShield - Setup passwordless sudo for iptables blocking
# Run this ONCE with: sudo bash setup_blocking.sh

SUDOERS_FILE="/etc/sudoers.d/smartshield"
USER=$(logname 2>/dev/null || echo "$SUDO_USER")

if [ -z "$USER" ]; then
    echo "ERROR: Could not determine the user. Run with: sudo bash setup_blocking.sh"
    exit 1
fi

echo "Setting up passwordless iptables + hosts-file management for user: $USER"

# Helper script that safely writes /etc/hosts while preserving non-SmartShield entries
HOSTS_HELPER="/usr/local/bin/smartshield-hosts"
cat > "$HOSTS_HELPER" << 'SCRIPT'
#!/bin/bash
# SmartShield /etc/hosts manager — called via sudo by the backend.
# Usage:
#   smartshield-hosts write <file>   — replace SmartShield section with contents of <file>
#   smartshield-hosts clear          — remove SmartShield section
BEGIN_MARKER="# >>> SmartShield blocked domains >>>"
END_MARKER="# <<< SmartShield blocked domains <<<"
HOSTS="/etc/hosts"

case "$1" in
  write)
    INPUT="$2"
    [ -f "$INPUT" ] || { echo "ERROR: input file not found"; exit 1; }
    # Remove old SmartShield section
    sed -i "/^${BEGIN_MARKER}$/,/^${END_MARKER}$/d" "$HOSTS"
    # Append new section
    echo "$BEGIN_MARKER" >> "$HOSTS"
    cat "$INPUT"         >> "$HOSTS"
    echo "$END_MARKER"   >> "$HOSTS"
    ;;
  clear)
    sed -i "/^${BEGIN_MARKER}$/,/^${END_MARKER}$/d" "$HOSTS"
    ;;
  *)
    echo "Usage: smartshield-hosts {write <file>|clear}"; exit 1;;
esac
SCRIPT
chmod 755 "$HOSTS_HELPER"

cat > "$SUDOERS_FILE" << EOF
# SmartShield - Allow iptables + hosts-file management without password
$USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables
$USER ALL=(ALL) NOPASSWD: /sbin/iptables
$USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables-restore
$USER ALL=(ALL) NOPASSWD: /sbin/iptables-restore
$USER ALL=(ALL) NOPASSWD: /usr/local/bin/smartshield-hosts
$USER ALL=(ALL) NOPASSWD: /usr/bin/tcpdump
$USER ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump
EOF

chmod 440 "$SUDOERS_FILE"

# Verify
if sudo -n iptables -L -n > /dev/null 2>&1; then
    echo "SUCCESS: Passwordless iptables configured for $USER"
else
    echo "SUCCESS: Sudoers file created at $SUDOERS_FILE"
fi
echo "SUCCESS: /etc/hosts helper installed at $HOSTS_HELPER"

echo "You can now block domains from the SmartShield dashboard."
