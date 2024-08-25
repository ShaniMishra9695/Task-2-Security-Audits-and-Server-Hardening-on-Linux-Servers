# Task-2-Security-Audits-and-Server-Hardening-on-Linux-Servers

# Linux Server Security Audit and Hardening Script

## Overview
This Bash script automates security audits and the hardening process for Linux servers. It is modular and can be easily deployed across multiple servers to ensure compliance with security standards.

## Features
- **User and Group Audits**: Identifies users with root privileges, weak passwords, etc.
- **File and Directory Permissions**: Scans for insecure permissions and files with SUID/SGID bits set.
- **Service Audits**: Lists running services, checks for unauthorized services, and more.
- **Firewall and Network Security**: Verifies firewall status, checks for open ports, etc.
- **IP Configuration Checks**: Identifies public vs. private IPs, ensures SSH is secure.
- **Security Updates**: Checks for available security updates.
- **Log Monitoring**: Monitors logs for suspicious activities.
- **Server Hardening**: Applies hardening steps like SSH configuration, disabling IPv6, securing GRUB, etc.
- **Custom Security Checks**: Allows for custom security checks via configuration files.

## Usage
```bash
./security_audit_hardening.sh [OPTION]
