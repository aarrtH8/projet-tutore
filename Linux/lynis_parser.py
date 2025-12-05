#!/usr/bin/env python3
"""
Lynis Report Parser
Parse Lynis security audit reports and extract key security metrics
"""

import re
import json
from datetime import datetime
from typing import Dict, List, Any, Optional


class LynisParser:
    def __init__(self, report_path: str):
        self.report_path = report_path
        self.raw_content = ""
        self.parsed_data = {}
        
    def read_report(self) -> str:
        """Read the Lynis report file"""
        with open(self.report_path, 'r', encoding='utf-8', errors='ignore') as f:
            self.raw_content = f.read()
        # Clean any remaining ANSI codes
        self.raw_content = self._strip_ansi(self.raw_content)
        return self.raw_content
    
    def _strip_ansi(self, text: str) -> str:
        """Remove ANSI escape codes"""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    def parse(self) -> Dict[str, Any]:
        """Main parsing function"""
        self.read_report()
        
        self.parsed_data = {
            "metadata": self._parse_metadata(),
            "score": self._parse_score(),
            "critical_issues": self._parse_critical_issues(),
            "security_status": self._parse_security_status(),
            "boot_and_services": self._parse_boot_services(),
            "ssh_hardening": self._parse_ssh_config(),
            "kernel_hardening": self._parse_kernel_hardening(),
            "authentication": self._parse_authentication(),
            "filesystem": self._parse_filesystem(),
            "network": self._parse_network(),
            "services": self._parse_services(),
            "installed_software": self._parse_installed_software(),
            "logging": self._parse_logging(),
            "insecure_services": self._parse_insecure_services(),
            "banners": self._parse_banners(),
            "scheduled_tasks": self._parse_scheduled_tasks(),
            "accounting": self._parse_accounting(),
            "time_sync": self._parse_time_sync(),
            "crypto": self._parse_crypto(),
            "virtualization": self._parse_virtualization(),
            "containers": self._parse_containers(),
            "file_permissions": self._parse_file_permissions(),
            "home_directories": self._parse_home_directories(),
            "hardening_tools": self._parse_hardening_tools(),
            "missing_tools": self._parse_missing_tools(),
            "warnings": self._parse_warnings(),
            "suggestions": self._parse_suggestions(),
            "scan_timestamp": datetime.now().isoformat()
        }
        
        return self.parsed_data
    
    def _parse_metadata(self) -> Dict[str, str]:
        """Parse system and scan metadata"""
        metadata = {}
        
        patterns = {
            "lynis_version": r"Program version:\s*(\S+)",
            "os": r"Operating system:\s*(.+?)(?=\n)",
            "os_name": r"Operating system name:\s*(.+?)(?=\n)",
            "os_version": r"Operating system version:\s*(.+?)(?=\n)",
            "kernel_version": r"Kernel version:\s*(.+?)(?=\n)",
            "hardware_platform": r"Hardware platform:\s*(\S+)",
            "hostname": r"Hostname:\s*(\S+)",
            "profile": r"Profiles:\s*(.+?)(?=\n)",
            "log_file": r"Log file:\s*(.+?)(?=\n)",
            "report_file": r"Report file:\s*(.+?)(?=\n)"
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, self.raw_content)
            if match:
                metadata[key] = match.group(1).strip()
        
        return metadata
    
    def _parse_score(self) -> Dict[str, Any]:
        """Parse hardening score and test statistics"""
        score = {}
        
        # Hardening index
        hardening_match = re.search(r"Hardening index\s*:\s*(\d+)", self.raw_content)
        if hardening_match:
            score["hardening_index"] = int(hardening_match.group(1))
        
        # Tests performed
        tests_match = re.search(r"Tests performed\s*:\s*(\d+)", self.raw_content)
        if tests_match:
            score["tests_performed"] = int(tests_match.group(1))
        
        # Plugins enabled
        plugins_match = re.search(r"Plugins enabled\s*:\s*(\d+)", self.raw_content)
        if plugins_match:
            score["plugins_enabled"] = int(plugins_match.group(1))
        
        return score
    
    def _parse_critical_issues(self) -> Dict[str, Any]:
        """Parse critical security issues"""
        issues = {
            "reboot_needed": False,
            "vulnerable_packages": False,
            "no_firewall": False,
            "firewall_no_rules": False,
            "weak_password_policy": False
        }
        
        # Check for reboot needed
        if re.search(r"Check if reboot is needed\s*\[\s*YES\s*\]", self.raw_content):
            issues["reboot_needed"] = True
        
        # Check for vulnerable packages
        if re.search(r"Checking vulnerable packages\s*\[\s*WARNING\s*\]", self.raw_content):
            issues["vulnerable_packages"] = True
        
        # Check firewall status - differentiate between "not installed" and "no rules"
        if re.search(r"Checking (?:host based )?firewall\s*\[\s*NOT ACTIVE\s*\]", self.raw_content):
            issues["no_firewall"] = True
        elif re.search(r"iptables module\(s\) loaded, but no rules active", self.raw_content):
            issues["firewall_no_rules"] = True
        
        # Check password aging
        if re.search(r"User password aging \(maximum\)\s*\[\s*DISABLED\s*\]", self.raw_content):
            issues["weak_password_policy"] = True
        
        return issues
    
    def _parse_security_status(self) -> Dict[str, str]:
        """Parse security framework and tool status"""
        status = {}
        
        # Firewall - check for detailed status
        firewall_match = re.search(r"Checking (?:host based )?firewall\s*\[\s*(.+?)\s*\]", self.raw_content)
        if firewall_match:
            fw_status = firewall_match.group(1).lower().replace(" ", "_")
            # If firewall is detected but has no rules, mark as installed_not_configured
            if fw_status == "active" and re.search(r"iptables module\(s\) loaded, but no rules active", self.raw_content):
                status["firewall"] = "installed_not_configured"
            else:
                status["firewall"] = fw_status
        
        # AppArmor
        apparmor_match = re.search(r"Checking AppArmor status\s*\[\s*(.+?)\s*\]", self.raw_content)
        if apparmor_match:
            status["apparmor"] = apparmor_match.group(1).lower()
        
        # SELinux
        selinux_match = re.search(r"Checking (?:presence )?SELinux\s*\[\s*(.+?)\s*\]", self.raw_content)
        if selinux_match:
            status["selinux"] = selinux_match.group(1).lower().replace(" ", "_")
        
        # Malware scanner
        malware_match = re.search(r"Installed malware scanner\s*\[\s*(.+?)\s*\]", self.raw_content)
        if malware_match:
            status["malware_scanner"] = malware_match.group(1).lower().replace(" ", "_")
        
        # IDS/IPS
        ids_match = re.search(r"Checking for IDS/IPS tooling\s*\[\s*(.+?)\s*\]", self.raw_content)
        if ids_match:
            status["ids_ips"] = ids_match.group(1).lower()
        
        # File integrity tool
        integrity_match = re.search(r"Checking (?:presence )?integrity tool\s*\[\s*(.+?)\s*\]", self.raw_content)
        if integrity_match:
            status["file_integrity_tool"] = integrity_match.group(1).lower().replace(" ", "_")
        
        # Auditd
        auditd_match = re.search(r"Checking auditd\s*\[\s*(.+?)\s*\]", self.raw_content)
        if auditd_match:
            status["auditd"] = auditd_match.group(1).lower().replace(" ", "_")
        
        return status
    
    def _parse_boot_services(self) -> Dict[str, Any]:
        """Parse boot and services information"""
        boot = {}
        
        # Service manager
        manager_match = re.search(r"Service Manager\s*\[\s*(.+?)\s*\]", self.raw_content)
        if manager_match:
            boot["service_manager"] = manager_match.group(1).lower()
        
        # UEFI boot
        uefi_match = re.search(r"Checking UEFI boot\s*\[\s*(.+?)\s*\]", self.raw_content)
        if uefi_match:
            boot["uefi_boot"] = uefi_match.group(1).lower()
        
        # GRUB
        grub_match = re.search(r"Checking presence GRUB2?\s*\[\s*(.+?)\s*\]", self.raw_content)
        if grub_match:
            boot["grub"] = grub_match.group(1).lower()
        
        # GRUB password
        grub_pwd_match = re.search(r"Checking for password protection\s*\[\s*(.+?)\s*\]", self.raw_content)
        if grub_pwd_match:
            boot["grub_password"] = grub_pwd_match.group(1).lower()
        
        # Running services count
        running_match = re.search(r"found (\d+) running services", self.raw_content)
        if running_match:
            boot["running_services"] = int(running_match.group(1))
        
        # Enabled services count
        enabled_match = re.search(r"found (\d+) enabled services", self.raw_content)
        if enabled_match:
            boot["enabled_services"] = int(enabled_match.group(1))
        
        return boot
    
    def _parse_ssh_config(self) -> List[Dict[str, str]]:
        """Parse SSH configuration items - compatible with Lynis 2.x and 3.x"""
        ssh_items = []
        
        # Find all SSH option lines
        ssh_section = re.search(r"\[\+\] SSH Support.*?(?=\[\+\]|\Z)", self.raw_content, re.DOTALL)
        if ssh_section:
            section_text = ssh_section.group(0)
            
            # Try Lynis 2.x format first: "- SSH option:"
            option_pattern = r"- SSH option: (\w+)\s*\[\s*(.+?)\s*\]"
            matches = list(re.finditer(option_pattern, section_text))
            
            # If no matches, try Lynis 3.x format: "- OpenSSH option:"
            if not matches:
                option_pattern = r"- OpenSSH option: (\w+)\s*\[\s*(.+?)\s*\]"
                matches = list(re.finditer(option_pattern, section_text))
            
            for match in matches:
                option_name = match.group(1)
                status = match.group(2)
                
                ssh_items.append({
                    "option": option_name,
                    "status": status,
                    "secure": status == "OK" or status == "NOT FOUND"
                })
        
        return ssh_items
    
    def _parse_kernel_hardening(self) -> List[Dict[str, Any]]:
        """Parse kernel hardening (sysctl) parameters"""
        kernel_items = []
        
        # Find kernel hardening section
        kernel_section = re.search(r"\[\+\] Kernel Hardening.*?(?=\[\+\]|\Z)", self.raw_content, re.DOTALL)
        if kernel_section:
            section_text = kernel_section.group(0)
            
            # Parse sysctl parameters
            sysctl_pattern = r"- ([\w\.]+)\s+\(exp:\s*(.+?)\)\s*\[\s*(.+?)\s*\]"
            for match in re.finditer(sysctl_pattern, section_text):
                param_name = match.group(1)
                expected = match.group(2)
                status = match.group(3)
                
                kernel_items.append({
                    "parameter": param_name,
                    "expected": expected,
                    "status": status,
                    "compliant": status == "OK"
                })
        
        return kernel_items
    
    def _parse_authentication(self) -> Dict[str, Any]:
        """Parse authentication and user security settings"""
        auth = {}
        
        # Password aging
        min_age_match = re.search(r"Checking user password aging \(minimum\)\s*\[\s*(.+?)\s*\]", self.raw_content)
        if min_age_match:
            auth["password_min_age"] = min_age_match.group(1).lower()
        
        max_age_match = re.search(r"User password aging \(maximum\)\s*\[\s*(.+?)\s*\]", self.raw_content)
        if max_age_match:
            auth["password_max_age"] = max_age_match.group(1).lower()
        
        # PAM modules
        pam_match = re.search(r"PAM password strength tools\s*\[\s*(.+?)\s*\]", self.raw_content)
        if pam_match:
            auth["pam_strength_tools"] = pam_match.group(1).lower()
        
        # Accounts without password
        no_pwd_match = re.search(r"Accounts without password\s*\[\s*(.+?)\s*\]", self.raw_content)
        if no_pwd_match:
            auth["accounts_without_password"] = no_pwd_match.group(1).lower()
        
        # Failed login logging
        failed_login_match = re.search(r"Logging failed login attempts\s*\[\s*(.+?)\s*\]", self.raw_content)
        if failed_login_match:
            auth["failed_login_logging"] = failed_login_match.group(1).lower()
        
        # Sudoers file
        sudo_match = re.search(r"sudoers file\s*\[\s*(.+?)\s*\]", self.raw_content)
        if sudo_match:
            auth["sudoers"] = sudo_match.group(1).lower()
        
        # Check sudoers file permissions
        sudo_perms_match = re.search(r"Check sudoers file permissions\s*\[\s*(.+?)\s*\]", self.raw_content)
        if sudo_perms_match:
            auth["sudoers_permissions"] = sudo_perms_match.group(1).lower()
        
        return auth
    
    def _parse_filesystem(self) -> Dict[str, Any]:
        """Parse filesystem security settings"""
        fs = {}
        
        # Separate partitions
        partitions = {}
        for partition in ["/home", "/tmp", "/var"]:
            pattern = rf"Checking {re.escape(partition)} mount point\s*\[\s*(.+?)\s*\]"
            match = re.search(pattern, self.raw_content)
            if match:
                status = match.group(1)
                partitions[partition] = status != "SUGGESTION"
        
        fs["separate_partitions"] = partitions
        
        # Sticky bits
        tmp_sticky = re.search(r"Checking /tmp sticky bit\s*\[\s*(.+?)\s*\]", self.raw_content)
        if tmp_sticky:
            fs["tmp_sticky_bit"] = tmp_sticky.group(1) == "OK"
        
        var_tmp_sticky = re.search(r"Checking /var/tmp sticky bit\s*\[\s*(.+?)\s*\]", self.raw_content)
        if var_tmp_sticky:
            fs["var_tmp_sticky_bit"] = var_tmp_sticky.group(1) == "OK"
        
        # ACL support
        acl_match = re.search(r"ACL support root file system\s*\[\s*(.+?)\s*\]", self.raw_content)
        if acl_match:
            fs["acl_support"] = acl_match.group(1).lower()
        
        return fs
    
    def _parse_network(self) -> Dict[str, Any]:
        """Parse network configuration"""
        network = {}
        
        # IPv6
        ipv6_match = re.search(r"Checking IPv6 configuration\s*\[\s*(.+?)\s*\]", self.raw_content)
        if ipv6_match:
            network["ipv6_enabled"] = ipv6_match.group(1) == "ENABLED"
        
        # Nameservers
        nameservers = []
        ns_pattern = r"Nameserver:\s*(\S+)\s*\[\s*(.+?)\s*\]"
        for match in re.finditer(ns_pattern, self.raw_content):
            nameservers.append({
                "ip": match.group(1),
                "status": match.group(2)
            })
        network["nameservers"] = nameservers
        
        # Open ports
        ports_match = re.search(r"Found (\d+) ports?", self.raw_content)
        if ports_match:
            network["open_ports_count"] = int(ports_match.group(1))
        
        # DHCP
        dhcp_match = re.search(r"Checking status DHCP client\s*\[\s*(.+?)\s*\]", self.raw_content)
        if dhcp_match:
            network["dhcp_client"] = dhcp_match.group(1).lower()
        
        # Promiscuous mode
        promisc_match = re.search(r"Checking promiscuous interfaces\s*\[\s*(.+?)\s*\]", self.raw_content)
        if promisc_match:
            network["promiscuous_mode"] = promisc_match.group(1).lower()
        
        return network
    
    def _parse_services(self) -> Dict[str, Any]:
        """Parse running services"""
        services = {}
        
        # Running services
        running_match = re.search(r"found (\d+) running services", self.raw_content)
        if running_match:
            services["running_count"] = int(running_match.group(1))
        
        # Enabled services
        enabled_match = re.search(r"found (\d+) enabled services", self.raw_content)
        if enabled_match:
            services["enabled_count"] = int(enabled_match.group(1))
        
        # Service manager
        manager_match = re.search(r"Service Manager\s*\[\s*(.+?)\s*\]", self.raw_content)
        if manager_match:
            services["service_manager"] = manager_match.group(1).lower()
        
        return services
    
    def _parse_installed_software(self) -> Dict[str, Any]:
        """Parse installed software information"""
        software = {}
        
        # Web servers
        apache_match = re.search(r"Checking Apache\s*\[\s*(.+?)\s*\]", self.raw_content)
        if apache_match:
            software["apache"] = apache_match.group(1).lower().replace(" ", "_")
        
        nginx_match = re.search(r"Checking nginx\s*\[\s*(.+?)\s*\]", self.raw_content)
        if nginx_match:
            software["nginx"] = nginx_match.group(1).lower().replace(" ", "_")
        
        # Databases - check for specific databases
        mysql_match = re.search(r"MySQL\s*\[\s*(.+?)\s*\]", self.raw_content)
        if mysql_match:
            software["mysql"] = mysql_match.group(1).lower().replace(" ", "_")
        
        postgres_match = re.search(r"PostgreSQL\s*\[\s*(.+?)\s*\]", self.raw_content)
        if postgres_match:
            software["postgresql"] = postgres_match.group(1).lower().replace(" ", "_")
        
        # General database check
        db_section = re.search(r"\[\+\] Databases.*?(?=\[\+\]|\Z)", self.raw_content, re.DOTALL)
        if db_section and "No database engines found" not in db_section.group(0):
            software["database_engines"] = "found"
        else:
            software["database_engines"] = "none"
        
        # PHP
        php_match = re.search(r"Checking PHP\s*\[\s*(.+?)\s*\]", self.raw_content)
        if php_match:
            software["php"] = php_match.group(1).lower().replace(" ", "_")
        
        # Mail server
        mail_section = re.search(r"\[\+\] Software: e-mail", self.raw_content)
        if mail_section:
            software["mail_server"] = "found"
        
        return software
    
    def _parse_logging(self) -> Dict[str, Any]:
        """Parse logging configuration"""
        logging = {}
        
        # Log daemon
        log_daemon_match = re.search(r"Checking for a running log daemon\s*\[\s*(.+?)\s*\]", self.raw_content)
        if log_daemon_match:
            logging["log_daemon"] = log_daemon_match.group(1).lower()
        
        # Syslog-NG
        syslog_ng_match = re.search(r"Checking Syslog-NG status\s*\[\s*(.+?)\s*\]", self.raw_content)
        if syslog_ng_match:
            logging["syslog_ng"] = syslog_ng_match.group(1).lower().replace(" ", "_")
        
        # Systemd journal
        systemd_match = re.search(r"Checking systemd journal status\s*\[\s*(.+?)\s*\]", self.raw_content)
        if systemd_match:
            logging["systemd_journal"] = systemd_match.group(1).lower()
        
        # RSyslog
        rsyslog_match = re.search(r"Checking RSyslog status\s*\[\s*(.+?)\s*\]", self.raw_content)
        if rsyslog_match:
            logging["rsyslog"] = rsyslog_match.group(1).lower()
        
        # Logrotate
        logrotate_match = re.search(r"Checking logrotate presence\s*\[\s*(.+?)\s*\]", self.raw_content)
        if logrotate_match:
            logging["logrotate"] = logrotate_match.group(1).lower()
        
        return logging
    
    def _parse_insecure_services(self) -> Dict[str, Any]:
        """Parse insecure services"""
        insecure = {}
        
        # inetd
        inetd_match = re.search(r"Checking inetd status\s*\[\s*(.+?)\s*\]", self.raw_content)
        if inetd_match:
            insecure["inetd"] = inetd_match.group(1).lower().replace(" ", "_")
        
        return insecure
    
    def _parse_banners(self) -> Dict[str, Any]:
        """Parse banner information"""
        banners = {}
        
        # /etc/issue
        issue_match = re.search(r"/etc/issue\s*\[\s*(.+?)\s*\]", self.raw_content)
        if issue_match:
            banners["issue"] = issue_match.group(1).lower()
        
        issue_content_match = re.search(r"/etc/issue contents\s*\[\s*(.+?)\s*\]", self.raw_content)
        if issue_content_match:
            banners["issue_content"] = issue_content_match.group(1).lower()
        
        # /etc/issue.net
        issue_net_match = re.search(r"/etc/issue\.net\s*\[\s*(.+?)\s*\]", self.raw_content)
        if issue_net_match:
            banners["issue_net"] = issue_net_match.group(1).lower()
        
        issue_net_content_match = re.search(r"/etc/issue\.net contents\s*\[\s*(.+?)\s*\]", self.raw_content)
        if issue_net_content_match:
            banners["issue_net_content"] = issue_net_content_match.group(1).lower()
        
        return banners
    
    def _parse_scheduled_tasks(self) -> Dict[str, Any]:
        """Parse scheduled tasks"""
        tasks = {}
        
        # Cron
        cron_match = re.search(r"Checking crontab/cronjob\s*\[\s*(.+?)\s*\]", self.raw_content)
        if cron_match:
            tasks["cron"] = cron_match.group(1).lower()
        
        # atd
        atd_match = re.search(r"Checking atd status\s*\[\s*(.+?)\s*\]", self.raw_content)
        if atd_match:
            tasks["atd"] = atd_match.group(1).lower()
        
        return tasks
    
    def _parse_accounting(self) -> Dict[str, Any]:
        """Parse accounting information"""
        accounting = {}
        
        # Accounting info
        acct_match = re.search(r"Checking accounting information\s*\[\s*(.+?)\s*\]", self.raw_content)
        if acct_match:
            accounting["accounting"] = acct_match.group(1).lower().replace(" ", "_")
        
        # sysstat
        sysstat_match = re.search(r"Checking sysstat accounting data\s*\[\s*(.+?)\s*\]", self.raw_content)
        if sysstat_match:
            accounting["sysstat"] = sysstat_match.group(1).lower().replace(" ", "_")
        
        # auditd
        auditd_match = re.search(r"Checking auditd\s*\[\s*(.+?)\s*\]", self.raw_content)
        if auditd_match:
            accounting["auditd"] = auditd_match.group(1).lower().replace(" ", "_")
        
        return accounting
    
    def _parse_time_sync(self) -> Dict[str, Any]:
        """Parse time synchronization"""
        time_sync = {}
        
        # NTP/Chrony
        ntp_section = re.search(r"\[\+\] Time and Synchronization", self.raw_content)
        if ntp_section:
            time_sync["configured"] = True
        
        return time_sync
    
    def _parse_crypto(self) -> Dict[str, Any]:
        """Parse cryptography"""
        crypto = {}
        
        # SSL certificates
        ssl_match = re.search(r"Checking for expired SSL certificates \[(\d+)/(\d+)\]", self.raw_content)
        if ssl_match:
            crypto["expired_ssl_certs"] = int(ssl_match.group(1))
            crypto["total_ssl_certs"] = int(ssl_match.group(2))
        
        return crypto
    
    def _parse_virtualization(self) -> Dict[str, Any]:
        """Parse virtualization"""
        virt = {}
        
        virt_section = re.search(r"\[\+\] Virtualization", self.raw_content)
        if virt_section:
            virt["detected"] = True
        
        return virt
    
    def _parse_containers(self) -> Dict[str, Any]:
        """Parse containers"""
        containers = {}
        
        container_section = re.search(r"\[\+\] Containers", self.raw_content)
        if container_section:
            containers["detected"] = True
        
        return containers
    
    def _parse_file_permissions(self) -> Dict[str, Any]:
        """Parse file permissions"""
        perms = {}
        
        # Check /root/.ssh
        ssh_perms_match = re.search(r"/root/\.ssh\s*\[\s*(.+?)\s*\]", self.raw_content)
        if ssh_perms_match:
            perms["root_ssh"] = ssh_perms_match.group(1).lower()
        
        return perms
    
    def _parse_home_directories(self) -> Dict[str, Any]:
        """Parse home directories"""
        home = {}
        
        # Shell history
        history_match = re.search(r"Checking shell history files\s*\[\s*(.+?)\s*\]", self.raw_content)
        if history_match:
            home["shell_history"] = history_match.group(1).lower()
        
        return home
    
    def _parse_hardening_tools(self) -> Dict[str, Any]:
        """Parse hardening tools"""
        tools = {}
        
        # Compiler
        compiler_match = re.search(r"Installed compiler\(s\)\s*\[\s*(.+?)\s*\]", self.raw_content)
        if compiler_match:
            tools["compiler"] = compiler_match.group(1).lower().replace(" ", "_")
        
        return tools
    
    def _parse_missing_tools(self) -> List[str]:
        """Parse missing security tools"""
        missing = []
        
        tool_checks = [
            ("malware_scanner", r"Installed malware scanner\s*\[\s*NOT FOUND\s*\]"),
            ("file_integrity", r"Checking (?:presence )?integrity tool\s*\[\s*NOT FOUND\s*\]"),
            ("ids_ips", r"Checking for IDS/IPS tooling\s*\[\s*NONE\s*\]"),
            ("auditd", r"Checking auditd\s*\[\s*NOT FOUND\s*\]"),
            ("firewall", r"Checking (?:host based )?firewall\s*\[\s*NOT ACTIVE\s*\]"),
        ]
        
        for tool_name, pattern in tool_checks:
            if re.search(pattern, self.raw_content):
                missing.append(tool_name)
        
        return missing
    
    def _parse_warnings(self) -> List[Dict[str, str]]:
        """Parse warnings section - compatible with Lynis 2.x and 3.x"""
        warnings = []
        
        # Find warnings section
        warnings_section = re.search(r"Warnings \((\d+)\):.*?(?=Suggestions|\Z)", self.raw_content, re.DOTALL)
        if not warnings_section:
            return warnings
            
        section_text = warnings_section.group(0)
        
        # Split into blocks - each warning starts with "!"
        # Split on newline followed by "!" that has spaces before it
        warning_blocks = re.split(r'\n\s*(?=!\s)', section_text)
        
        for block in warning_blocks:
            block = block.strip()
            if not block or not block.startswith('!'):
                continue
            
            # Extract first line: "! Description [TEST-ID]"
            first_line_match = re.match(r'!\s+(.+?)\s+\[([A-Z]+-\d+)\]', block)
            if not first_line_match:
                continue
            
            description = first_line_match.group(1).strip()
            test_id = first_line_match.group(2)
            
            # Extract solution (if present) - only for this specific warning
            solution = ""
            solution_match = re.search(r'-\s*Solution\s*:\s*(.+?)(?=\n\s*-|\n\s*https://|\Z)', block, re.DOTALL)
            if solution_match:
                solution = solution_match.group(1).strip()
            
            # Extract URL - should be on its own line in this block
            url = ""
            url_match = re.search(r'^\s*(https://cisofy\.com/\S+)', block, re.MULTILINE)
            if url_match:
                url = url_match.group(1).strip()
            
            warnings.append({
                "test_id": test_id,
                "description": description,
                "solution": solution,
                "url": url
            })
        
        return warnings
    
    def _parse_suggestions(self) -> List[Dict[str, str]]:
        """Parse suggestions section - compatible with Lynis 2.x and 3.x"""
        suggestions = []
        
        # Find suggestions section - capture between "Suggestions (N):" and "Follow-up:"
        suggestions_match = re.search(r"Suggestions \(\d+\):\s*\n\s*-+\s*\n(.*?)(?=\n\s*Follow-up:|\n\s*=+\s*$)", self.raw_content, re.DOTALL)
        if not suggestions_match:
            return suggestions
            
        section_text = suggestions_match.group(1)
        
        # Split on lines starting with "  * " (2 spaces + asterisk + space)
        # Use a lookahead to keep the delimiter
        blocks = re.split(r'\n(?=  \* )', section_text)
        
        for block in blocks:
            block = block.strip()
            if not block or not re.match(r'^\*\s+', block):
                continue
            
            # Extract description and test_id from first line
            # Format: "  * Description [TEST-ID]"
            first_line_match = re.search(r'^\*\s+(.+?)\s+\[([A-Z]+-\d+(?::[^\]]+)?)\]', block, re.MULTILINE)
            if not first_line_match:
                continue
            
            description = first_line_match.group(1).strip()
            test_id = first_line_match.group(2)
            
            # Extract details if present
            details = ""
            details_match = re.search(r'-\s*Details\s*:\s*(.+?)(?=\n\s*-\s*(?:Solution|Related)|$)', block, re.DOTALL)
            if details_match:
                details = details_match.group(1).strip()
            
            # Extract solution if present
            solution = ""
            solution_match = re.search(r'-\s*Solution\s*:\s*(.+?)(?=\n\s*-\s*Related|\n\s*$)', block, re.DOTALL)
            if solution_match:
                solution = solution_match.group(1).strip()
            
            # Extract URL - look for "Website:" line
            # Pattern: any amount of whitespace + * + whitespace + Website: + URL
            url = ""
            url_match = re.search(r'^\s*\*\s+Website:\s+(https://cisofy\.com/lynis/controls/\S+)', block, re.MULTILINE)
            if url_match:
                url = url_match.group(1).strip()
            
            # Extract additional resources (articles)
            articles = []
            article_matches = re.finditer(r'^\s*\*\s+Article:\s*(.+?):\s+(https://\S+)', block, re.MULTILINE)
            for article_match in article_matches:
                articles.append({
                    "title": article_match.group(1).strip(),
                    "url": article_match.group(2).strip()
                })
            
            suggestion_data = {
                "test_id": test_id,
                "description": description,
                "details": details,
                "solution": solution,
                "url": url
            }
            
            # Add articles if present
            if articles:
                suggestion_data["articles"] = articles
            
            suggestions.append(suggestion_data)
        
        return suggestions
    
    def to_json(self, output_path: Optional[str] = None, indent: int = 2) -> str:
        """Export parsed data to JSON"""
        json_data = json.dumps(self.parsed_data, indent=indent, ensure_ascii=False)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_data)
        
        return json_data
    
    def get_risk_score(self) -> Dict[str, Any]:
        """Calculate overall risk assessment"""
        score = self.parsed_data.get("score", {})
        critical = self.parsed_data.get("critical_issues", {})
        warnings = self.parsed_data.get("warnings", [])
        
        hardening_index = score.get("hardening_index", 0)
        
        # Risk level based on hardening index and critical issues
        if hardening_index >= 80 and len(warnings) == 0:
            risk_level = "LOW"
        elif hardening_index >= 60 and len(warnings) <= 2:
            risk_level = "MEDIUM"
        elif hardening_index >= 40:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"
        
        return {
            "risk_level": risk_level,
            "hardening_index": hardening_index,
            "warnings_count": len(warnings),
            "critical_issues_count": sum(1 for v in critical.values() if v),
            "missing_tools_count": len(self.parsed_data.get("missing_tools", []))
        }


# Example usage
if __name__ == "__main__":
    import sys
    import os
    
    if len(sys.argv) < 2:
        print("Usage: python lynis_parser.py <lynis_report.txt> [output.json]")
        sys.exit(1)
    
    report_path = sys.argv[1]
    
    # Generate default output filename if not provided
    if len(sys.argv) > 2:
        output_path = sys.argv[2]
    else:
        # Create output filename based on input filename
        base_name = os.path.splitext(os.path.basename(report_path))[0]
        output_path = f"{base_name}_parsed.json"
    
    # Parse report
    print(f"📄 Parsing Lynis report: {report_path}")
    parser = LynisParser(report_path)
    parser.parse()
    
    # Export to JSON
    parser.to_json(output_path)
    
    print(f"✅ Parsing completed successfully!")
    print(f"\n📊 JSON report: {output_path}")
    print(f"\nRisk Level: {parser.get_risk_score()['risk_level']} | Hardening Index: {parser.get_risk_score()['hardening_index']}/100")