#!/bin/bash

# Function to list all users and groups, and check for non-standard users with UID 0
audit_users_groups() {
  echo "Users and Groups:"
  cut -d: -f1 /etc/passwd
  cut -d: -f1 /etc/group
  
  echo "Checking for non-standard users with UID 0:"
  awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v "root"

  echo "Checking for users without passwords or with weak passwords:"
  # You may use 'pwck' or 'chage' for detailed checks
}

# Function to scan for world-writable files and directories
audit_file_permissions() {
  echo "Scanning for world-writable files and directories:"
  find / -type d -perm -0002 -print
  find / -type f -perm -0002 -print
  
  echo "Checking for insecure SSH directory permissions:"
  find / -type d -name ".ssh" -exec chmod 700 {} \;
  
  echo "Checking for files with SUID or SGID bits set:"
  find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \;
}

# Function to audit running services
audit_services() {
  echo "List of running services:"
  service --status-all | grep "+"
  
  echo "Checking for critical services (e.g., sshd, iptables):"
  systemctl is-active sshd iptables
  
  echo "Checking for services listening on non-standard or insecure ports:"
  netstat -tuln | grep -Ev '(:22|:80|:443)'
}

# Function to verify firewall and network security
audit_firewall_network() {
  echo "Verifying firewall status:"
  ufw status
  iptables -L
  
  echo "Checking for open ports and their associated services:"
  netstat -tuln
  
  echo "Checking for IP forwarding or insecure network configurations:"
  sysctl net.ipv4.ip_forward
}

# Function to check public vs. private IP configurations
audit_ip_config() {
  echo "Identifying public vs. private IP addresses:"
  ip -4 addr show | grep inet
  
  echo "Checking that sensitive services (e.g., SSH) are not exposed on public IPs:"
  netstat -tuln | grep ':22'
}

# Function to check for security updates
audit_security_updates() {
  echo "Checking for available security updates:"
  apt-get -s upgrade | grep -i security
  
  echo "Ensuring the server is configured to receive security updates:"
  grep -r "Unattended-Upgrade::Allowed-Origins" /etc/apt/apt.conf.d/
}

# Function to monitor logs for suspicious activity
audit_log_monitoring() {
  echo "Checking for suspicious log entries (e.g., too many login attempts):"
  grep "Failed password" /var/log/auth.log
}

# Function to apply server hardening steps
apply_hardening() {
  echo "Applying SSH configuration hardening:"
  sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
  sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
  systemctl reload sshd
  
  echo "Disabling IPv6 (if not required):"
  sysctl -w net.ipv6.conf.all.disable_ipv6=1
  sysctl -w net.ipv6.conf.default.disable_ipv6=1
  
  echo "Securing the bootloader (GRUB):"
  echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
  echo "password_pbkdf2 root $(grub-mkpasswd-pbkdf2 | grep grub.pbkdf2)" >> /etc/grub.d/40_custom
  update-grub
  
  echo "Configuring iptables:"
  iptables -P INPUT DROP
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  iptables-save > /etc/iptables/rules.v4
  
  echo "Setting up automatic security updates:"
  apt-get install unattended-upgrades -y
  dpkg-reconfigure --priority=low unattended-upgrades
}

# Function to generate a summary report
generate_report() {
  echo "Generating summary report:"
  # Placeholder for report generation logic
}

# Command-line switches for modularity
case $1 in
  -audit-users)
    audit_users_groups ;;
  -audit-files)
    audit_file_permissions ;;
  -audit-services)
    audit_services ;;
  -audit-firewall)
    audit_firewall_network ;;
  -audit-ip)
    audit_ip_config ;;
  -audit-updates)
    audit_security_updates ;;
  -audit-logs)
    audit_log_monitoring ;;
  -harden)
    apply_hardening ;;
  -report)
    generate_report ;;
  *)
    echo "Usage: $0 {-audit-users|-audit-files|-audit-services|-audit-firewall|-audit-ip|-audit-updates|-audit-logs|-harden|-report}"
    ;;
esac
