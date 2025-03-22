#!/usr/bin/env python3
"""
Heimdell Firewall Module

This module provides functionality to:
1. Configure and manage firewall rules across different operating systems
2. Create rule templates for common security practices
3. Monitor firewall logs and detect suspicious activity
4. Provide an easy-to-use interface for system administrators
"""

import os
import re
import sys
import json
import time
import socket
import platform
import subprocess
import shutil
from datetime import datetime
import ipaddress
import logging
from typing import Dict, Any, List, Tuple, Optional, Union
import csv

class FirewallModule:
    """
    Heimdell module for managing firewall configuration across different platforms.
    Supports iptables (Linux), pf (macOS), and Windows Firewall.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the Firewall module.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Set system type and choose appropriate firewall manager
        self.system = platform.system()
        if self.system == "Linux":
            self.firewall_type = self._detect_linux_firewall()
        elif self.system == "Darwin":  # macOS
            self.firewall_type = "pf"
        elif self.system == "Windows":
            self.firewall_type = "windows"
        else:
            self.firewall_type = "unknown"
            
        print(f"Detected system: {self.system}")
        print(f"Using firewall: {self.firewall_type}")
        
        # Initialize paths
        self._init_firewall_paths()
        
        # Rule templates for common configurations
        self.rule_templates = {
            'basic_protection': {
                'name': 'Basic Protection',
                'description': 'Essential firewall rules for basic system protection',
                'enabled': False,
                'rules': self._get_basic_protection_rules()
            },
            'web_server': {
                'name': 'Web Server',
                'description': 'Rules optimized for web servers (HTTP/HTTPS)',
                'enabled': False,
                'rules': self._get_web_server_rules()
            },
            'database_server': {
                'name': 'Database Server',
                'description': 'Rules optimized for database servers',
                'enabled': False,
                'rules': self._get_database_server_rules()
            },
            'workstation': {
                'name': 'Workstation',
                'description': 'Rules for end-user workstations',
                'enabled': False,
                'rules': self._get_workstation_rules()
            },
            'strict_protection': {
                'name': 'Strict Protection',
                'description': 'High-security rules with minimal open ports',
                'enabled': False,
                'rules': self._get_strict_protection_rules()
            }
        }
        
        # Settings
        self.logs_dir = self.config.get('logs_dir', '/var/log/heimdell/firewall')
        if self.system == "Windows":
            self.logs_dir = self.config.get('logs_dir', 'C:\\ProgramData\\Heimdell\\logs\\firewall')
        
        # Create log directory if it doesn't exist
        os.makedirs(self.logs_dir, exist_ok=True)
        
        # Configure logging
        self._setup_logging()
        
        # Load custom rules if available
        self._load_custom_rules()
    
    def _setup_logging(self):
        """Initialize logging for the firewall module."""
        try:
            # Create logs directory if it doesn't exist
            os.makedirs(self.logs_dir, exist_ok=True)
            
            # Set up logging
            log_file = os.path.join(self.logs_dir, 'firewall.log')
            logging.basicConfig(
                filename=log_file,
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            # Add console handler for terminal output
            console = logging.StreamHandler()
            console.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            console.setFormatter(formatter)
            logging.getLogger('').addHandler(console)
            
            logging.info("Firewall module logging initialized")
            
        except Exception as e:
            print(f"Error setting up logging: {e}")
    
    def _detect_linux_firewall(self) -> str:
        """
        Detect which firewall system is installed on Linux.
        
        Returns:
            str: Detected firewall type (iptables, nftables, firewalld, ufw)
        """
        firewall_types = {
            "iptables": ["iptables", "--version"],
            "nftables": ["nft", "--version"],
            "firewalld": ["firewall-cmd", "--version"],
            "ufw": ["ufw", "status"]
        }
        
        for fw_type, command in firewall_types.items():
            try:
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode == 0:
                    return fw_type
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
        
        # Default to iptables as it's most common
        return "iptables"
    
    def _init_firewall_paths(self):
        """Initialize paths for firewall configuration and logs based on system type."""
        if self.system == "Linux":
            if self.firewall_type == "iptables":
                self.config_path = "/etc/iptables/rules.v4"
                self.backup_dir = "/etc/iptables/backup"
                self.log_path = "/var/log/iptables.log"
            elif self.firewall_type == "nftables":
                self.config_path = "/etc/nftables.conf"
                self.backup_dir = "/etc/nftables/backup"
                self.log_path = "/var/log/nftables.log"
            elif self.firewall_type == "firewalld":
                self.config_path = "/etc/firewalld/zones/public.xml"
                self.backup_dir = "/etc/firewalld/backup"
                self.log_path = "/var/log/firewalld"
            elif self.firewall_type == "ufw":
                self.config_path = "/etc/ufw/user.rules"
                self.backup_dir = "/etc/ufw/backup"
                self.log_path = "/var/log/ufw.log"
        elif self.system == "Darwin":  # macOS
            self.config_path = "/etc/pf.conf"
            self.backup_dir = "/etc/pf/backup"
            self.log_path = "/var/log/pf.log"
        elif self.system == "Windows":
            self.config_path = "Windows Firewall Configuration"
            self.backup_dir = "C:\\ProgramData\\Heimdell\\firewall\\backup"
            self.log_path = "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log"
        
        # Override with custom paths if provided
        if 'config_path' in self.config:
            self.config_path = self.config['config_path']
        if 'backup_dir' in self.config:
            self.backup_dir = self.config['backup_dir']
        if 'log_path' in self.config:
            self.log_path = self.config['log_path']
        
        # Create backup directory if it doesn't exist
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def _load_custom_rules(self):
        """Load custom rules from configuration file."""
        custom_rules_path = os.path.join(self.logs_dir, 'custom_rules.json')
        
        if os.path.exists(custom_rules_path):
            try:
                with open(custom_rules_path, 'r') as f:
                    custom_rules = json.load(f)
                
                # Add custom rules to template dictionary
                if 'custom' not in self.rule_templates:
                    self.rule_templates['custom'] = {
                        'name': 'Custom Rules',
                        'description': 'User-defined custom firewall rules',
                        'enabled': False,
                        'rules': []
                    }
                
                self.rule_templates['custom']['rules'] = custom_rules
                logging.info(f"Loaded {len(custom_rules)} custom rules")
            except Exception as e:
                logging.error(f"Error loading custom rules: {e}")
    
    def _save_custom_rules(self):
        """Save custom rules to configuration file."""
        if 'custom' in self.rule_templates:
            custom_rules_path = os.path.join(self.logs_dir, 'custom_rules.json')
            
            try:
                with open(custom_rules_path, 'w') as f:
                    json.dump(self.rule_templates['custom']['rules'], f, indent=2)
                
                logging.info("Custom rules saved successfully")
            except Exception as e:
                logging.error(f"Error saving custom rules: {e}")
    
    def run(self):
        """
        Main entry point for running the Firewall module.
        This function is called when the module is executed through the 'runmodule' command.
        """
        print("\n" + "=" * 60)
        print("           HEIMDELL - FIREWALL MANAGEMENT MODULE")
        print("=" * 60)
        print("      \"Securing your perimeter, controlling access\"")
        print("-" * 60)
        
        # Main module menu
        while True:
            self._print_module_menu()
            choice = input("Heimdell(Select an option) #> ").strip()
            
            if choice == '0':
                print("Exiting Firewall module.")
                break
                
            elif choice == '1':
                # Firewall status
                self.check_firewall_status()
                
            elif choice == '2':
                # Configure rules
                self._configure_rules_menu()
                
            elif choice == '3':
                # Apply rule templates
                self._apply_rule_templates()
                
            elif choice == '4':
                # View logs/blocked traffic
                self._view_firewall_logs()
                
            elif choice == '5':
                # Backup/restore configuration
                self._backup_restore_menu()
                
            elif choice == '6':
                # Advanced settings
                self._advanced_settings()
                
            else:
                print("Invalid option. Please try again.")
    
    def _print_module_menu(self):
        """Display the main Firewall module menu."""
        print("\nFirewall Module Options:")
        print("1. Check Firewall Status")
        print("2. Configure Firewall Rules")
        print("3. Apply Rule Templates")
        print("4. View Logs and Blocked Traffic")
        print("5. Backup/Restore Configuration")
        print("6. Advanced Settings")
        print("0. Exit Module")
        print("")
    
    # ==== Firewall Status Functions ====
    
    def check_firewall_status(self) -> Dict[str, Any]:
        """
        Check the current status of the firewall.
        
        Returns:
            dict: Dictionary containing firewall status information
        """
        print("\n" + "=" * 50)
        print("           FIREWALL STATUS")
        print("=" * 50)
        
        status = {
            "enabled": False,
            "version": "Unknown",
            "active_rules_count": 0,
            "default_policy": "Unknown",
            "errors": []
        }
        
        try:
            if self.system == "Linux":
                if self.firewall_type == "iptables":
                    status = self._check_iptables_status()
                elif self.firewall_type == "nftables":
                    status = self._check_nftables_status()
                elif self.firewall_type == "firewalld":
                    status = self._check_firewalld_status()
                elif self.firewall_type == "ufw":
                    status = self._check_ufw_status()
            elif self.system == "Darwin":
                status = self._check_pf_status()
            elif self.system == "Windows":
                status = self._check_windows_firewall_status()
            
            # Display the status information
            self._display_firewall_status(status)
            
            return status
            
        except Exception as e:
            print(f"Error checking firewall status: {e}")
            status["errors"].append(str(e))
            return status
    
    def _check_iptables_status(self) -> Dict[str, Any]:
        """Check iptables firewall status on Linux."""
        status = {
            "enabled": False,
            "version": "Unknown",
            "active_rules_count": 0,
            "default_policy": "Unknown",
            "errors": []
        }
        
        try:
            # Get iptables version
            result = subprocess.run(["iptables", "--version"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            if result.returncode == 0:
                status["version"] = result.stdout.strip()
            
            # Check if firewall is enabled/active
            # Check INPUT chain policy
            result = subprocess.run(["iptables", "-L", "INPUT"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            
            if result.returncode == 0:
                status["enabled"] = True
                
                # Parse output to get default policy
                first_line = result.stdout.split('\n')[0]
                if "policy" in first_line:
                    policy_match = re.search(r'policy\s+(\w+)', first_line)
                    if policy_match:
                        status["default_policy"] = policy_match.group(1)
                
                # Count active rules
                rule_lines = [line for line in result.stdout.split('\n') 
                             if line and not line.startswith('Chain') and not line.startswith('target')]
                status["active_rules_count"] = len(rule_lines)
            else:
                status["errors"].append("Error reading iptables rules")
        
        except Exception as e:
            status["errors"].append(f"Error checking iptables status: {e}")
        
        return status
    
    def _check_nftables_status(self) -> Dict[str, Any]:
        """Check nftables firewall status on Linux."""
        status = {
            "enabled": False,
            "version": "Unknown",
            "active_rules_count": 0,
            "default_policy": "Unknown",
            "errors": []
        }
        
        try:
            # Get nftables version
            result = subprocess.run(["nft", "--version"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            if result.returncode == 0:
                status["version"] = result.stdout.strip()
            
            # Check if firewall is enabled/active by listing tables
            result = subprocess.run(["nft", "list", "tables"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                status["enabled"] = True
                
                # Count tables
                tables = [line for line in result.stdout.split('\n') if line.strip()]
                
                # Get rule count for each table
                rule_count = 0
                for table in tables:
                    # Extract table name and family
                    match = re.search(r'table\s+(\w+)\s+(\w+)', table)
                    if match:
                        family, name = match.groups()
                        
                        # List rules in this table
                        try:
                            result = subprocess.run(["nft", "list", "table", family, name], 
                                                   stdout=subprocess.PIPE, 
                                                   stderr=subprocess.PIPE,
                                                   text=True)
                            
                            if result.returncode == 0:
                                # Count lines that look like rules
                                rule_lines = [line for line in result.stdout.split('\n') 
                                             if line.strip() and '{' not in line and '}' not in line 
                                             and 'table' not in line and 'chain' not in line]
                                rule_count += len(rule_lines)
                        except Exception:
                            pass
                
                status["active_rules_count"] = rule_count
                
                # Try to determine default policy by looking at the base chain
                try:
                    result = subprocess.run(["nft", "list", "chains"], 
                                           stdout=subprocess.PIPE, 
                                           stderr=subprocess.PIPE,
                                           text=True)
                    
                    if result.returncode == 0:
                        # Look for type filter hook input
                        for line in result.stdout.split('\n'):
                            if "type filter hook input" in line:
                                if "policy drop" in line:
                                    status["default_policy"] = "DROP"
                                elif "policy accept" in line:
                                    status["default_policy"] = "ACCEPT"
                                break
                except Exception:
                    pass
            
        except Exception as e:
            status["errors"].append(f"Error checking nftables status: {e}")
        
        return status
    
    def _check_firewalld_status(self) -> Dict[str, Any]:
        """Check firewalld status on Linux."""
        status = {
            "enabled": False,
            "version": "Unknown",
            "active_rules_count": 0,
            "default_policy": "Unknown",
            "errors": []
        }
        
        try:
            # Get firewalld version
            result = subprocess.run(["firewall-cmd", "--version"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            if result.returncode == 0:
                status["version"] = result.stdout.strip()
            
            # Check if firewall is running
            result = subprocess.run(["firewall-cmd", "--state"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            
            if result.returncode == 0 and "running" in result.stdout.lower():
                status["enabled"] = True
                
                # Get default zone
                result = subprocess.run(["firewall-cmd", "--get-default-zone"], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE,
                                       text=True)
                
                if result.returncode == 0:
                    default_zone = result.stdout.strip()
                    
                    # Get zone target (policy)
                    result = subprocess.run(["firewall-cmd", f"--get-target-zone={default_zone}"], 
                                           stdout=subprocess.PIPE, 
                                           stderr=subprocess.PIPE,
                                           text=True)
                    
                    if result.returncode == 0:
                        status["default_policy"] = result.stdout.strip()
                
                # Count services, ports, and rich rules
                count = 0
                
                # Services
                result = subprocess.run(["firewall-cmd", "--get-services"], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE,
                                       text=True)
                
                if result.returncode == 0:
                    services = result.stdout.strip().split()
                    count += len(services)
                
                # Ports
                result = subprocess.run(["firewall-cmd", "--list-ports"], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE,
                                       text=True)
                
                if result.returncode == 0:
                    ports = result.stdout.strip().split()
                    count += len(ports)
                
                # Rich rules
                result = subprocess.run(["firewall-cmd", "--list-rich-rules"], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE,
                                       text=True)
                
                if result.returncode == 0:
                    rich_rules = [r for r in result.stdout.split('\n') if r.strip()]
                    count += len(rich_rules)
                
                status["active_rules_count"] = count
            
        except Exception as e:
            status["errors"].append(f"Error checking firewalld status: {e}")
        
        return status
    
    def _check_ufw_status(self) -> Dict[str, Any]:
        """Check ufw (Uncomplicated Firewall) status on Linux."""
        status = {
            "enabled": False,
            "version": "Unknown",
            "active_rules_count": 0,
            "default_policy": "Unknown",
            "errors": []
        }
        
        try:
            # Get ufw version
            result = subprocess.run(["ufw", "version"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            if result.returncode == 0:
                status["version"] = result.stdout.strip()
            
            # Check if firewall is enabled
            result = subprocess.run(["ufw", "status"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            
            if result.returncode == 0:
                status_output = result.stdout.lower()
                
                if "active" in status_output or "enabled" in status_output:
                    status["enabled"] = True
                    
                    # Count rules
                    rule_lines = [line for line in result.stdout.split('\n') 
                                 if line.strip() and "ALLOW" in line or "DENY" in line]
                    status["active_rules_count"] = len(rule_lines)
                    
                    # Get default policy
                    result = subprocess.run(["ufw", "status", "verbose"], 
                                           stdout=subprocess.PIPE, 
                                           stderr=subprocess.PIPE,
                                           text=True)
                    
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if "default:" in line.lower():
                                status["default_policy"] = line.split(':')[1].strip().upper()
                                break
            
        except Exception as e:
            status["errors"].append(f"Error checking ufw status: {e}")
        
        return status
    
    def _check_pf_status(self) -> Dict[str, Any]:
        """Check pf firewall status on macOS."""
        status = {
            "enabled": False,
            "version": "Built-in",
            "active_rules_count": 0,
            "default_policy": "Unknown",
            "errors": []
        }
        
        try:
            # Check if pf is enabled
            result = subprocess.run(["pfctl", "-s", "info"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            
            if result.returncode == 0:
                if "Status: Enabled" in result.stdout:
                    status["enabled"] = True
                
                # Extract version if available
                version_match = re.search(r'Version:\s+(.+)', result.stdout)
                if version_match:
                    status["version"] = version_match.group(1)
            
            # Count rules
            result = subprocess.run(["pfctl", "-s", "rules"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            
            if result.returncode == 0:
                rule_lines = [line for line in result.stdout.split('\n') 
                             if line.strip() and not line.startswith('@')]
                status["active_rules_count"] = len(rule_lines)
                
                # Try to determine default policy
                for line in rule_lines:
                    if "block drop all" in line.lower():
                        status["default_policy"] = "DROP"
                        break
                    elif "pass all" in line.lower():
                        status["default_policy"] = "ACCEPT"
                        break
            
        except Exception as e:
            status["errors"].append(f"Error checking pf status: {e}")
        
        return status
    
    def _check_windows_firewall_status(self) -> Dict[str, Any]:
        """Check Windows Firewall status."""
        status = {
            "enabled": False,
            "version": "Windows Defender Firewall",
            "active_rules_count": 0,
            "default_policy": "Unknown",
            "errors": []
        }
        
        try:
            # Check if firewall is enabled for domain profile
            result = subprocess.run(["netsh", "advfirewall", "show", "domainprofile"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if "State" in line:
                        if "ON" in line:
                            status["enabled"] = True
                            break
            
            # If domain profile is not enabled, check private profile
            if not status["enabled"]:
                result = subprocess.run(["netsh", "advfirewall", "show", "privateprofile"], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE,
                                       text=True)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if "State" in line:
                            if "ON" in line:
                                status["enabled"] = True
                                break
            
            # If still not enabled, check public profile
            if not status["enabled"]:
                result = subprocess.run(["netsh", "advfirewall", "show", "publicprofile"], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE,
                                       text=True)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if "State" in line:
                            if "ON" in line:
                                status["enabled"] = True
                                break
            
            # Count rules
            result = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            
            if result.returncode == 0:
                # Count lines with "Rule Name:"
                rule_count = result.stdout.count("Rule Name:")
                status["active_rules_count"] = rule_count
                
                # Get default policy
                result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE,
                                       text=True)
                
                if result.returncode == 0:
                    # Look for inbound action
                    inbound_match = re.search(r'Inbound connections\s+(\w+)', result.stdout)
                    if inbound_match:
                        action = inbound_match.group(1)
                        status["default_policy"] = "DROP" if action.lower() == "block" else "ACCEPT"
            
        except Exception as e:
            status["errors"].append(f"Error checking Windows Firewall status: {e}")
        
        return status
    
    def _display_firewall_status(self, status: Dict[str, Any]):
        """
        Display firewall status information in a user-friendly format.
        
        Args:
            status: Dictionary containing firewall status
        """
        print(f"Firewall Type: {self.firewall_type}")
        print(f"Version: {status['version']}")
        print(f"Status: {'✓ Enabled' if status['enabled'] else '✗ Disabled'}")
        print(f"Default Policy: {status['default_policy']}")
        print(f"Active Rules: {status['active_rules_count']}")
        
        # Display errors if any
        if status["errors"]:
            print("\nErrors/Warnings:")
            for error in status["errors"]:
                print(f"  - {error}")
        
        # Display overall assessment
        print("\nOverall Security Assessment:")
        if not status["enabled"]:
            print("❌ CRITICAL: Firewall is disabled! Enable immediately for protection.")
        elif status["default_policy"] == "ACCEPT" or status["default_policy"] == "Unknown":
            print("⚠️  WARNING: Default policy may not be secure. Consider setting to DROP/DENY for better security.")
        elif status["active_rules_count"] < 5:
            print("⚠️  WARNING: Few active rules detected. You may need additional rules for proper protection.")
        else:
            print("✅ GOOD: Firewall is enabled with a secure default policy and active rules.")
    
    # ==== Rule Configuration Functions ====
    
    def _configure_rules_menu(self):
        """Display and handle the rule configuration menu."""
        while True:
            print("\n" + "=" * 50)
            print("           CONFIGURE FIREWALL RULES")
            print("=" * 50)
            
            print("\nRule Configuration Options:")
            print("1. View Current Rules")
            print("2. Add New Rule")
            print("3. Remove Rule")
            print("4. Enable/Disable Firewall")
            print("5. Set Default Policy")
            print("0. Back to Main Menu")
            
            choice = input("Heimdell(Select an option) #> ").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                self._view_current_rules()
            elif choice == '2':
                self._add_rule_menu()
            elif choice == '3':
                self._remove_rule_menu()
            elif choice == '4':
                self._enable_disable_firewall()
            elif choice == '5':
                self._set_default_policy()
            else:
                print("Invalid option. Please try again.")
    
    def _view_current_rules(self):
        """View current firewall rules."""
        print("\n" + "=" * 50)
        print("           CURRENT FIREWALL RULES")
        print("=" * 50)
        
        try:
                rules = []
            
                if self.system == "Linux":
                    if self.firewall_type == "iptables":
                        rules = self._get_iptables_rules()
                    elif self.firewall_type == "nftables":
                        rules = self._get_nftables_rules()
                    elif self.firewall_type == "firewalld":
                        rules = self._get_firewalld_rules()
                    elif self.firewall_type == "ufw":
                        rules = self._get_ufw_rules()
                elif self.system == "Darwin":
                    rules = self._get_pf_rules()
                elif self.system == "Windows":
                    rules = self._get_windows_firewall_rules()
                
                if not rules:
                    print("No rules found or unable to retrieve rules.")
                    return
                
                # Display rules with pagination
                page_size = 10
                total_pages = (len(rules) + page_size - 1) // page_size
                current_page = 1
                
                while True:
                    start_idx = (current_page - 1) * page_size
                    end_idx = min(start_idx + page_size, len(rules))
                    
                    print(f"\nRules (Page {current_page}/{total_pages}):")
                    print("-" * 70)
                    
                    for i, rule in enumerate(rules[start_idx:end_idx], start_idx + 1):
                        print(f"{i}. {rule}")
                    
                    print("\nOptions:")
                    print("n: Next page, p: Previous page, d: Detailed view, 0: Back")
                    
                    cmd = input("Heimdell(Action) #> ").strip().lower()
                    
                    if cmd == '0':
                        return
                    elif cmd == 'n' and current_page < total_pages:
                        current_page += 1
                    elif cmd == 'p' and current_page > 1:
                        current_page -= 1
                    elif cmd == 'd':
                        # View detailed rule
                        rule_num = input("Heimdell(Enter rule number to view details) #> ").strip()
                        try:
                            rule_idx = int(rule_num) - 1
                            if 0 <= rule_idx < len(rules):
                                print("\nRule Details:")
                                print("-" * 70)
                                
                                # Display raw rule
                                print(f"Raw rule: {rules[rule_idx]}")
                                
                                # Try to parse and display in a more structured format
                                self._display_rule_details(rules[rule_idx])
                                
                                input("Press Enter to continue...")
                            else:
                                print("Invalid rule number.")
                        except ValueError:
                            print("Please enter a valid number.")
                    else:
                        print("Invalid command.")
                
        except Exception as e:
            print(f"Error viewing firewall rules: {e}")
    
    def _get_iptables_rules(self) -> List[str]:
        """Get current iptables rules."""
        rules = []
        
        try:
            result = subprocess.run(["sudo", "iptables", "-L", "-v", "--line-numbers"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line and re.match(r'^\s*\d+', line):  # Lines starting with a number
                        rules.append(line.strip())
            
            return rules
            
        except Exception as e:
            print(f"Error getting iptables rules: {e}")
            return []
    
    def _get_nftables_rules(self) -> List[str]:
        """Get current nftables rules."""
        rules = []
        
        try:
            result = subprocess.run(["sudo", "nft", "list", "ruleset"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            
            if result.returncode == 0:
                # Filter out table and chain definitions, keep only actual rules
                in_chain = False
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    
                    if line.startswith('table') or line.startswith('chain'):
                        in_chain = True
                        continue
                    
                    if line == '}':
                        in_chain = False
                        continue
                    
                    if in_chain and not line.startswith('{'):
                        rules.append(line)
            
            return rules
            
        except Exception as e:
            print(f"Error getting nftables rules: {e}")
            return []
    
    def _get_firewalld_rules(self) -> List[str]:
        """Get current firewalld rules."""
        rules = []
        
        try:
            # Get active zones
            result = subprocess.run(["firewall-cmd", "--get-active-zones"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            
            if result.returncode == 0:
                zones = []
                current_zone = None
                
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    
                    if not line.startswith(' '):  # Zone name
                        current_zone = line
                        zones.append(current_zone)
                
                # Get rules for each zone
                for zone in zones:
                    # Services
                    result = subprocess.run(["firewall-cmd", f"--zone={zone}", "--list-services"], 
                                           stdout=subprocess.PIPE, 
                                           stderr=subprocess.PIPE,
                                           text=True)
                    
                    if result.returncode == 0 and result.stdout.strip():
                        services = result.stdout.strip().split()
                        for service in services:
                            rules.append(f"Zone '{zone}': Allow service '{service}'")
                    
                    # Ports
                    result = subprocess.run(["firewall-cmd", f"--zone={zone}", "--list-ports"], 
                                           stdout=subprocess.PIPE, 
                                           stderr=subprocess.PIPE,
                                           text=True)
                    
                    if result.returncode == 0 and result.stdout.strip():
                        ports = result.stdout.strip().split()
                        for port in ports:
                            rules.append(f"Zone '{zone}': Allow port '{port}'")
                    
                    # Rich rules
                    result = subprocess.run(["firewall-cmd", f"--zone={zone}", "--list-rich-rules"], 
                                           stdout=subprocess.PIPE, 
                                           stderr=subprocess.PIPE,
                                           text=True)
                    
                    if result.returncode == 0:
                        rich_rules = [r for r in result.stdout.split('\n') if r.strip()]
                        for rich_rule in rich_rules:
                            rules.append(f"Zone '{zone}': {rich_rule}")
            
            return rules
            
        except Exception as e:
            print(f"Error getting firewalld rules: {e}")
            return []
    
    def _get_ufw_rules(self) -> List[str]:
        """Get current ufw rules."""
        rules = []
        
        try:
            result = subprocess.run(["sudo", "ufw", "status", "numbered"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line and re.match(r'^\s*\[\s*\d+\s*\]', line):  # Lines with [number]
                        rules.append(line.strip())
            
            return rules
            
        except Exception as e:
            print(f"Error getting ufw rules: {e}")
            return []
    
    def _get_pf_rules(self) -> List[str]:
        """Get current pf firewall rules on macOS."""
        rules = []
        
        try:
            result = subprocess.run(["sudo", "pfctl", "-s", "rules"], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line and not line.startswith('@'):
                        rules.append(line.strip())
            
            return rules
            
        except Exception as e:
            print(f"Error getting pf rules: {e}")
            return []
    
    def _get_windows_firewall_rules(self) -> List[str]:
        """Get current Windows Firewall rules."""
        rules = []
        
        try:
            # Get all enabled rules
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "status=enabled", "name=all"],
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                i = 0
                
                while i < len(lines):
                    line = lines[i].strip()
                    
                    if line.startswith("Rule Name:"):
                        rule_name = line[10:].strip()
                        rule_info = rule_name
                        
                        # Get more rule information
                        j = i + 1
                        while j < len(lines) and not lines[j].startswith("Rule Name:"):
                            info_line = lines[j].strip()
                            if info_line and ":" in info_line:
                                property_name = info_line.split(":", 1)[0].strip()
                                if property_name in ["Enabled", "Direction", "Action"]:
                                    rule_info += f" | {info_line}"
                            j += 1
                        
                        rules.append(rule_info)
                        i = j - 1
                    
                    i += 1
            
            return rules
            
        except Exception as e:
            print(f"Error getting Windows Firewall rules: {e}")
            return []
    
    def _display_rule_details(self, rule: str):
        """
        Display detailed information about a firewall rule.
        
        Args:
            rule: Rule string to parse and display
        """
        try:
            # Format depends on firewall type
            if self.firewall_type == "iptables":
                # Parse iptables rule
                matches = {
                    "chain": re.search(r'Chain\s+(\w+)', rule),
                    "target": re.search(r'target\s+(\w+)', rule, re.IGNORECASE),
                    "protocol": re.search(r'(\w+)(?=\s+opt)', rule, re.IGNORECASE),
                    "source": re.search(r'source\s+(\S+)', rule, re.IGNORECASE),
                    "destination": re.search(r'destination\s+(\S+)', rule, re.IGNORECASE)
                }
                
                print("\nInterpreted Rule Information:")
                print(f"Action: {matches['target'].group(1) if matches['target'] else 'Unknown'}")
                print(f"Protocol: {matches['protocol'].group(1) if matches['protocol'] else 'Any'}")
                print(f"Source: {matches['source'].group(1) if matches['source'] else 'Any'}")
                print(f"Destination: {matches['destination'].group(1) if matches['destination'] else 'Any'}")
                
            elif self.firewall_type == "nftables":
                # Parse nftables rule
                if "ip saddr" in rule:
                    print(f"Source IP: {re.search(r'ip saddr (\S+)', rule).group(1)}")
                if "ip daddr" in rule:
                    print(f"Destination IP: {re.search(r'ip daddr (\S+)', rule).group(1)}")
                if "tcp dport" in rule:
                    print(f"TCP Destination Port: {re.search(r'tcp dport (\S+)', rule).group(1)}")
                if "udp dport" in rule:
                    print(f"UDP Destination Port: {re.search(r'udp dport (\S+)', rule).group(1)}")
                if "accept" in rule:
                    print("Action: ACCEPT")
                elif "drop" in rule:
                    print("Action: DROP")
                
            elif self.firewall_type == "firewalld":
                # Parse firewalld rule
                if "Zone" in rule:
                    print(f"Zone: {re.search(r"Zone '([^']+)'", rule).group(1)}")
                if "Allow service" in rule:
                    print(f"Service: {re.search(r"Allow service '([^']+)'", rule).group(1)}")
                if "Allow port" in rule:
                    print(f"Port: {re.search(r"Allow port '([^']+)'", rule).group(1)}")
                if "rich-rule" in rule.lower():
                    if "port=" in rule:
                        print(f"Port: {re.search(r'port="([^"]+)"', rule).group(1)}")
                    if "accept" in rule.lower():
                        print("Action: ACCEPT")
                    elif "reject" in rule.lower():
                        print("Action: REJECT")
                    elif "drop" in rule.lower():
                        print("Action: DROP")
                
            elif self.firewall_type == "ufw":
                # Parse ufw rule
                if "ALLOW" in rule:
                    print("Action: ALLOW")
                elif "DENY" in rule:
                    print("Action: DENY")
                elif "REJECT" in rule:
                    print("Action: REJECT")
                
                if "OUT" in rule and "IN" not in rule:
                    print("Direction: Outbound")
                elif "IN" in rule and "OUT" not in rule:
                    print("Direction: Inbound")
                
                # Try to extract source, destination, and ports
                from_match = re.search(r'from\s+(\S+)', rule)
                if from_match:
                    print(f"Source: {from_match.group(1)}")
                
                to_match = re.search(r'to\s+(\S+)', rule)
                if to_match:
                    print(f"Destination: {to_match.group(1)}")
                
                port_match = re.search(r'port\s+(\S+)', rule)
                if port_match:
                    print(f"Port: {port_match.group(1)}")
                
            elif self.firewall_type == "pf":
                # Parse pf rule
                if rule.startswith("pass"):
                    print("Action: PASS (Allow)")
                elif rule.startswith("block"):
                    print("Action: BLOCK (Deny)")
                
                if "in" in rule and "out" not in rule:
                    print("Direction: Inbound")
                elif "out" in rule and "in" not in rule:
                    print("Direction: Outbound")
                
                proto_match = re.search(r'proto (\w+)', rule)
                if proto_match:
                    print(f"Protocol: {proto_match.group(1)}")
                
                from_match = re.search(r'from (\S+)', rule)
                if from_match:
                    print(f"Source: {from_match.group(1)}")
                
                to_match = re.search(r'to (\S+)', rule)
                if to_match:
                    print(f"Destination: {to_match.group(1)}")
                
                port_match = re.search(r'port (\S+)', rule)
                if port_match:
                    print(f"Port: {port_match.group(1)}")
                
            elif self.firewall_type == "windows":
                # Parse Windows Firewall rule
                parts = rule.split(" | ")
                name = parts[0]
                
                print(f"Rule Name: {name}")
                
                for part in parts[1:]:
                    if ":" in part:
                        key, value = part.split(":", 1)
                        print(f"{key.strip()}: {value.strip()}")
            
        except Exception as e:
            print(f"Error parsing rule details: {e}")
    
    def _add_rule_menu(self):
        """Display menu for adding a new firewall rule."""
        print("\n" + "=" * 50)
        print("           ADD FIREWALL RULE")
        print("=" * 50)
        
        # Different options based on firewall type
        if self.firewall_type == "iptables":
            self._add_iptables_rule()
        elif self.firewall_type == "nftables":
            self._add_nftables_rule()
        elif self.firewall_type == "firewalld":
            self._add_firewalld_rule()
        elif self.firewall_type == "ufw":
            self._add_ufw_rule()
        elif self.firewall_type == "pf":
            self._add_pf_rule()
        elif self.firewall_type == "windows":
            self._add_windows_firewall_rule()
        else:
            print(f"Adding rules for {self.firewall_type} is not supported.")
    
    def _add_iptables_rule(self):
        """Add a new iptables rule."""
        print("\nAdd iptables Rule:")
        
        # Menu for rule type selection
        print("\nRule Type:")
        print("1. Allow traffic on a specific port")
        print("2. Block traffic from an IP address/range")
        print("3. Allow traffic for a service (by port)")
        print("4. Advanced rule (custom)")
        print("0. Cancel")
        
        choice = input("Heimdell(Select rule type) #> ").strip()
        
        if choice == '0':
            return
        
        try:
            if choice == '1':
                # Allow port rule
                protocol = input("Heimdell(Protocol [tcp/udp]) #> ").strip().lower()
                port = input("Heimdell(Port number) #> ").strip()
                
                if not port.isdigit() or int(port) < 1 or int(port) > 65535:
                    print("Invalid port number. Must be between 1-65535.")
                    return
                
                if protocol not in ['tcp', 'udp']:
                    print("Invalid protocol. Must be 'tcp' or 'udp'.")
                    return
                
                # Create the rule
                cmd = [
                    "sudo", "iptables", 
                    "-A", "INPUT", 
                    "-p", protocol, 
                    "--dport", port, 
                    "-j", "ACCEPT"
                ]
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: Allow {protocol} traffic on port {port}")
                    self._save_iptables_rules()
                else:
                    print(f"✗ Error adding rule: {result.stderr.decode()}")
                
            elif choice == '2':
                # Block IP rule
                ip_address = input("Heimdell(IP address or CIDR range to block) #> ").strip()
                
                # Validate IP
                try:
                    # Check if it's a CIDR range
                    if '/' in ip_address:
                        ipaddress.ip_network(ip_address)
                    else:
                        ipaddress.ip_address(ip_address)
                except ValueError:
                    print("Invalid IP address or CIDR range.")
                    return
                
                # Create the rule
                cmd = [
                    "sudo", "iptables", 
                    "-A", "INPUT", 
                    "-s", ip_address, 
                    "-j", "DROP"
                ]
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: Block traffic from {ip_address}")
                    self._save_iptables_rules()
                else:
                    print(f"✗ Error adding rule: {result.stderr.decode()}")
                
            elif choice == '3':
                # Allow service rule
                service = input("Heimdell(Service name or port) #> ").strip()
                
                # If service is a name, try to convert it to a port
                if not service.isdigit():
                    try:
                        import socket
                        port = socket.getservbyname(service)
                        service = str(port)
                    except:
                        print(f"Service '{service}' not recognized. Please enter a port number.")
                        return
                
                protocol = input("Heimdell(Protocol [tcp/udp]) #> ").strip().lower()
                
                if not service.isdigit() or int(service) < 1 or int(service) > 65535:
                    print("Invalid port number. Must be between 1-65535.")
                    return
                
                if protocol not in ['tcp', 'udp']:
                    print("Invalid protocol. Must be 'tcp' or 'udp'.")
                    return
                
                # Create the rule
                cmd = [
                    "sudo", "iptables", 
                    "-A", "INPUT", 
                    "-p", protocol, 
                    "--dport", service, 
                    "-j", "ACCEPT"
                ]
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: Allow {protocol} traffic for service on port {service}")
                    self._save_iptables_rules()
                else:
                    print(f"✗ Error adding rule: {result.stderr.decode()}")
                
            elif choice == '4':
                # Advanced custom rule
                print("\nEnter the iptables command arguments (after 'iptables'):")
                print("Example: -A INPUT -p tcp --dport 22 -j ACCEPT")
                
                rule_args = input("Heimdell(iptables args) #> ").strip()
                
                # Create the rule
                cmd = ["sudo", "iptables"] + rule_args.split()
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: {rule_args}")
                    self._save_iptables_rules()
                else:
                    print(f"✗ Error adding rule: {result.stderr.decode()}")
            
        except Exception as e:
            print(f"Error adding iptables rule: {e}")
    
    def _save_iptables_rules(self):
        """Save iptables rules to ensure they persist after reboot."""
        try:
            # Create backup first
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = os.path.join(self.backup_dir, f"iptables_backup_{timestamp}")
            
            # Save rules
            result = subprocess.run(
                ["sudo", "iptables-save"], 
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            if result.returncode == 0:
                # Save to backup file
                with open(backup_file, 'wb') as f:
                    f.write(result.stdout)
                
                print(f"Rules backed up to: {backup_file}")
                
                # Check if iptables-persistent is installed
                result = subprocess.run(
                    ["dpkg", "-l", "iptables-persistent"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                if result.returncode == 0:
                    # Save using iptables-persistent
                    subprocess.run(
                        ["sudo", "sh", "-c", "iptables-save > /etc/iptables/rules.v4"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    print("Rules saved to /etc/iptables/rules.v4")
                else:
                    print("Note: For rules to persist after reboot, install iptables-persistent:")
                    print("      sudo apt-get install iptables-persistent")
                    
                    # Ask to save to custom file
                    save_custom = input("Heimdell(Save rules to a file? [y/n]) #> ").strip().lower()
                    if save_custom == 'y':
                        file_path = input("Heimdell(Enter file path) #> ").strip()
                        
                        if file_path:
                            subprocess.run(
                                ["sudo", "sh", "-c", f"iptables-save > {file_path}"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE
                            )
                            print(f"Rules saved to {file_path}")
            else:
                print(f"Error saving iptables rules: {result.stderr.decode()}")
                
        except Exception as e:
            print(f"Error saving iptables rules: {e}")
    
    def _add_nftables_rule(self):
        """Add a new nftables rule."""
        print("\nAdd nftables Rule:")
        
        # Menu for rule type selection
        print("\nRule Type:")
        print("1. Allow traffic on a specific port")
        print("2. Block traffic from an IP address/range")
        print("3. Allow traffic for a service (by port)")
        print("4. Advanced rule (custom)")
        print("0. Cancel")
        
        choice = input("Heimdell(Select rule type) #> ").strip()
        
        if choice == '0':
            return
        
        try:
            if choice == '1':
                # Allow port rule
                protocol = input("Heimdell(Protocol [tcp/udp]) #> ").strip().lower()
                port = input("Heimdell(Port number) #> ").strip()
                
                if not port.isdigit() or int(port) < 1 or int(port) > 65535:
                    print("Invalid port number. Must be between 1-65535.")
                    return
                
                if protocol not in ['tcp', 'udp']:
                    print("Invalid protocol. Must be 'tcp' or 'udp'.")
                    return
                
                # Create the rule - but first we need to check if filter table and input chain exist
                self._ensure_nftables_base_setup()
                
                # Add the rule
                cmd = [
                    "sudo", "nft", "add", "rule", 
                    "inet", "filter", "input", 
                    f"{protocol}", "dport", port, 
                    "accept"
                ]
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: Allow {protocol} traffic on port {port}")
                else:
                    print(f"✗ Error adding rule: {result.stderr.decode()}")
                
            elif choice == '2':
                # Block IP rule
                ip_address = input("Heimdell(IP address or CIDR range to block) #> ").strip()
                
                # Validate IP
                try:
                    # Check if it's a CIDR range
                    if '/' in ip_address:
                        ipaddress.ip_network(ip_address)
                    else:
                        ipaddress.ip_address(ip_address)
                except ValueError:
                    print("Invalid IP address or CIDR range.")
                    return
                
                # Ensure base setup
                self._ensure_nftables_base_setup()
                
                # Add the rule
                cmd = [
                    "sudo", "nft", "add", "rule", 
                    "inet", "filter", "input", 
                    "ip", "saddr", ip_address, 
                    "drop"
                ]
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: Block traffic from {ip_address}")
                else:
                    print(f"✗ Error adding rule: {result.stderr.decode()}")
                
            elif choice == '3':
                # Allow service rule
                service = input("Heimdell(Service name or port) #> ").strip()
                
                # If service is a name, try to convert it to a port
                if not service.isdigit():
                    try:
                        import socket
                        port = socket.getservbyname(service)
                        service = str(port)
                    except:
                        print(f"Service '{service}' not recognized. Please enter a port number.")
                        return
                
                protocol = input("Heimdell(Protocol [tcp/udp]) #> ").strip().lower()
                
                if not service.isdigit() or int(service) < 1 or int(service) > 65535:
                    print("Invalid port number. Must be between 1-65535.")
                    return
                
                if protocol not in ['tcp', 'udp']:
                    print("Invalid protocol. Must be 'tcp' or 'udp'.")
                    return
                
                # Ensure base setup
                self._ensure_nftables_base_setup()
                
                # Add the rule
                cmd = [
                    "sudo", "nft", "add", "rule", 
                    "inet", "filter", "input", 
                    f"{protocol}", "dport", service, 
                    "accept"
                ]
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: Allow {protocol} traffic for service on port {service}")
                else:
                    print(f"✗ Error adding rule: {result.stderr.decode()}")
                
            elif choice == '4':
                # Advanced custom rule
                print("\nEnter the nft command arguments (after 'nft'):")
                print("Example: add rule inet filter input tcp dport 22 accept")
                
                rule_args = input("Heimdell(nft args) #> ").strip()
                
                # Create the rule
                cmd = ["sudo", "nft"] + rule_args.split()
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: {rule_args}")
                else:
                    print(f"✗ Error adding rule: {result.stderr.decode()}")
                    
        except Exception as e:
            print(f"Error adding nftables rule: {e}")
    
    def _ensure_nftables_base_setup(self):
        """Ensure nftables has the base table and chains set up."""
        try:
            # Check if inet table exists
            result = subprocess.run(
                ["sudo", "nft", "list", "tables", "inet"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            
            if "filter" not in result.stdout.decode():
                # Create the filter table
                subprocess.run(
                    ["sudo", "nft", "add", "table", "inet", "filter"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                print("Created inet filter table")
            
            # Check if input chain exists
            result = subprocess.run(
                ["sudo", "nft", "list", "chains", "inet", "filter"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            
            if "input" not in result.stdout.decode().lower():
                # Create the input chain
                subprocess.run(
                    ["sudo", "nft", "add", "chain", "inet", "filter", "input", 
                     "{ type filter hook input priority 0; policy accept; }"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                print("Created input chain")
            
            if "output" not in result.stdout.decode().lower():
                # Create the output chain
                subprocess.run(
                    ["sudo", "nft", "add", "chain", "inet", "filter", "output", 
                     "{ type filter hook output priority 0; policy accept; }"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                print("Created output chain")
            
            if "forward" not in result.stdout.decode().lower():
                # Create the forward chain
                subprocess.run(
                    ["sudo", "nft", "add", "chain", "inet", "filter", "forward", 
                     "{ type filter hook forward priority 0; policy accept; }"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                print("Created forward chain")
            
        except Exception as e:
            print(f"Error setting up nftables base configuration: {e}")
    
    def _add_firewalld_rule(self):
        """Add a new firewalld rule."""
        print("\nAdd firewalld Rule:")
        
        # Menu for rule type selection
        print("\nRule Type:")
        print("1. Allow service")
        print("2. Allow port")
        print("3. Block IP address/range")
        print("4. Add rich rule")
        print("0. Cancel")
        
        choice = input("Heimdell(Select rule type) #> ").strip()
        
        if choice == '0':
            return
        
        try:
            # Get zone to add rule to
            zones = []
            result = subprocess.run(
                ["firewall-cmd", "--get-zones"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                zones = result.stdout.strip().split()
            
            if not zones:
                print("No firewalld zones found.")
                return
            
            print("\nAvailable zones:")
            for i, zone in enumerate(zones, 1):
                print(f"{i}. {zone}")
            
            zone_choice = input("Heimdell(Select zone number or name) #> ").strip()
            
            # Get zone from choice
            selected_zone = None
            if zone_choice.isdigit() and 1 <= int(zone_choice) <= len(zones):
                selected_zone = zones[int(zone_choice) - 1]
            elif zone_choice in zones:
                selected_zone = zone_choice
            else:
                print("Invalid zone selection.")
                return
            
            # Add rule based on choice
            if choice == '1':
                # Allow service
                print("\nCommon services:")
                common_services = ["http", "https", "ssh", "ftp", "smtp", "dns", "dhcp", "ntp"]
                for i, service in enumerate(common_services, 1):
                    print(f"{i}. {service}")
                
                print(f"{len(common_services) + 1}. Other (list all available services)")
                
                service_choice = input("Heimdell(Select service number or name) #> ").strip()
                
                if service_choice.isdigit() and 1 <= int(service_choice) <= len(common_services):
                    service = common_services[int(service_choice) - 1]
                elif service_choice.isdigit() and int(service_choice) == len(common_services) + 1:
                    # List all available services
                    result = subprocess.run(
                        ["firewall-cmd", "--get-services"], 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    if result.returncode == 0:
                        all_services = result.stdout.strip().split()
                        print("\nAll available services:")
                        for i, service in enumerate(all_services, 1):
                            print(f"{i}. {service}")
                        
                        service_choice = input("Heimdell(Select service number or name) #> ").strip()
                        
                        if service_choice.isdigit() and 1 <= int(service_choice) <= len(all_services):
                            service = all_services[int(service_choice) - 1]
                        elif service_choice in all_services:
                            service = service_choice
                        else:
                            print("Invalid service selection.")
                            return
                elif service_choice in common_services:
                    service = service_choice
                else:
                    # Check if it's a valid service
                    result = subprocess.run(
                        ["firewall-cmd", "--get-services"], 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    if result.returncode == 0:
                        all_services = result.stdout.strip().split()
                        if service_choice in all_services:
                            service = service_choice
                        else:
                            print(f"Invalid service: {service_choice}")
                            return
                    else:
                        print("Error getting available services.")
                        return
                
                # Add the service to zone
                cmd = [
                    "sudo", "firewall-cmd", 
                    f"--zone={selected_zone}", 
                    f"--add-service={service}"
                ]
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: Allow {service} service in zone {selected_zone}")
                    
                    # Make permanent
                    make_perm = input("Heimdell(Make rule permanent? [y/n]) #> ").strip().lower()
                    if make_perm == 'y':
                        cmd = [
                            "sudo", "firewall-cmd", 
                            f"--zone={selected_zone}", 
                            f"--add-service={service}",
                            "--permanent"
                        ]
                        
                        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        print("Rule made permanent.")
                else:
                    print(f"✗ Error adding rule: {result.stderr}")
                
            elif choice == '2':
                # Allow port
                protocol = input("Heimdell(Protocol [tcp/udp]) #> ").strip().lower()
                port = input("Heimdell(Port number) #> ").strip()
                
                if not port.isdigit() or int(port) < 1 or int(port) > 65535:
                    print("Invalid port number. Must be between 1-65535.")
                    return
                
                if protocol not in ['tcp', 'udp']:
                    print("Invalid protocol. Must be 'tcp' or 'udp'.")
                    return
                
                # Add the port to zone
                cmd = [
                    "sudo", "firewall-cmd", 
                    f"--zone={selected_zone}", 
                    f"--add-port={port}/{protocol}"
                ]
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: Allow {protocol} port {port} in zone {selected_zone}")
                    
                    # Make permanent
                    make_perm = input("Heimdell(Make rule permanent? [y/n]) #> ").strip().lower()
                    if make_perm == 'y':
                        cmd = [
                            "sudo", "firewall-cmd", 
                            f"--zone={selected_zone}", 
                            f"--add-port={port}/{protocol}",
                            "--permanent"
                        ]
                        
                        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        print("Rule made permanent.")
                else:
                    print(f"✗ Error adding rule: {result.stderr}")
                
            elif choice == '3':
                # Block IP address/range
                ip_address = input("Heimdell(IP address or CIDR range to block) #> ").strip()
                
                # Validate IP
                try:
                    # Check if it's a CIDR range
                    if '/' in ip_address:
                        ipaddress.ip_network(ip_address)
                    else:
                        ipaddress.ip_address(ip_address)
                except ValueError:
                    print("Invalid IP address or CIDR range.")
                    return
                
                # Add rich rule to block IP
                rich_rule = f'rule family="ipv4" source address="{ip_address}" drop'
                
                cmd = [
                    "sudo", "firewall-cmd", 
                    f"--zone={selected_zone}", 
                    f"--add-rich-rule='{rich_rule}'"
                ]
                
                # Need to use shell=True for rich rules due to quotes
                result = subprocess.run(
                    " ".join(cmd), 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=True
                )
                
                if result.returncode == 0:
                    print(f"✓ Rule added: Block traffic from {ip_address} in zone {selected_zone}")
                    
                    # Make permanent
                    make_perm = input("Heimdell(Make rule permanent? [y/n]) #> ").strip().lower()
                    if make_perm == 'y':
                        cmd = [
                            "sudo", "firewall-cmd", 
                            f"--zone={selected_zone}", 
                            f"--add-rich-rule='{rich_rule}'",
                            "--permanent"
                        ]
                        
                        subprocess.run(" ".join(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                        print("Rule made permanent.")
                else:
                    print(f"✗ Error adding rule: {result.stderr}")
                
            elif choice == '4':
                # Add rich rule
                print("\nEnter a rich rule:")
                print("Example: rule family=\"ipv4\" source address=\"192.168.1.0/24\" accept")
                
                rich_rule = input("Heimdell(Rich rule) #> ").strip()
                
                # Add the rich rule
                cmd = [
                    "sudo", "firewall-cmd", 
                    f"--zone={selected_zone}", 
                    f"--add-rich-rule='{rich_rule}'"
                ]
                
                # Need to use shell=True for rich rules due to quotes
                result = subprocess.run(
                    " ".join(cmd), 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=True
                )
                
                if result.returncode == 0:
                    print(f"✓ Rich rule added to zone {selected_zone}")
                    
                    # Make permanent
                    make_perm = input("Heimdell(Make rule permanent? [y/n]) #> ").strip().lower()
                    if make_perm == 'y':
                        cmd = [
                            "sudo", "firewall-cmd", 
                            f"--zone={selected_zone}", 
                            f"--add-rich-rule='{rich_rule}'",
                            "--permanent"
                        ]
                        
                        subprocess.run(" ".join(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                        print("Rule made permanent.")
                else:
                    print(f"✗ Error adding rich rule: {result.stderr}")
            
        except Exception as e:
            print(f"Error adding firewalld rule: {e}")
    
    def _add_ufw_rule(self):
        """Add a new ufw rule."""
        print("\nAdd UFW Rule:")
        
        # Menu for rule type selection
        print("\nRule Type:")
        print("1. Allow traffic on a specific port")
        print("2. Block traffic from an IP address/range")
        print("3. Allow traffic for a service (by port name)")
        print("4. Advanced rule (custom)")
        print("0. Cancel")
        
        choice = input("Heimdell(Select rule type) #> ").strip()
        
        if choice == '0':
            return
        
        try:
            if choice == '1':
                # Allow port rule
                protocol = input("Heimdell(Protocol [tcp/udp]) #> ").strip().lower()
                port = input("Heimdell(Port number) #> ").strip()
                
                if not port.isdigit() or int(port) < 1 or int(port) > 65535:
                    print("Invalid port number. Must be between 1-65535.")
                    return
                
                if protocol not in ['tcp', 'udp']:
                    print("Invalid protocol. Must be 'tcp' or 'udp'.")
                    return
                
                # Create the rule
                cmd = [
                    "sudo", "ufw", 
                    "allow", 
                    f"{port}/{protocol}"
                ]
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: Allow {protocol} traffic on port {port}")
                else:
                    print(f"✗ Error adding rule: {result.stderr}")
                
            elif choice == '2':
                # Block IP rule
                ip_address = input("Heimdell(IP address or CIDR range to block) #> ").strip()
                
                # Validate IP
                try:
                    # Check if it's a CIDR range
                    if '/' in ip_address:
                        ipaddress.ip_network(ip_address)
                    else:
                        ipaddress.ip_address(ip_address)
                except ValueError:
                    print("Invalid IP address or CIDR range.")
                    return
                
                # Create the rule
                cmd = [
                    "sudo", "ufw", 
                    "deny", 
                    "from", ip_address
                ]
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: Block traffic from {ip_address}")
                else:
                    print(f"✗ Error adding rule: {result.stderr}")
                
            elif choice == '3':
                # Allow service rule
                service = input("Heimdell(Service name) #> ").strip()
                
                # Create the rule
                cmd = [
                    "sudo", "ufw", 
                    "allow", service
                ]
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: Allow traffic for service {service}")
                else:
                    print(f"✗ Error adding rule: {result.stderr}")
                
            elif choice == '4':
                # Advanced custom rule
                print("\nEnter the ufw command arguments (after 'ufw'):")
                print("Example: allow from 192.168.1.0/24 to any port 22")
                
                rule_args = input("Heimdell(ufw args) #> ").strip()
                
                # Create the rule
                cmd = ["sudo", "ufw"] + rule_args.split()
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: {rule_args}")
                else:
                    print(f"✗ Error adding rule: {result.stderr}")
            
        except Exception as e:
            print(f"Error adding ufw rule: {e}")
    
    def _add_pf_rule(self):
        """Add a new pf firewall rule on macOS."""
        print("\nAdd PF Rule:")
        
        # Menu for rule type selection
        print("\nRule Type:")
        print("1. Allow traffic on a specific port")
        print("2. Block traffic from an IP address/range")
        print("3. Advanced rule (custom)")
        print("0. Cancel")
        
        choice = input("Heimdell(Select rule type) #> ").strip()
        
        if choice == '0':
            return
        
        try:
            # First, check if pf is enabled
            result = subprocess.run(
                ["sudo", "pfctl", "-s", "info"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if "Status: Disabled" in result.stdout:
                print("PF firewall is currently disabled.")
                enable_pf = input("Heimdell(Enable PF firewall? [y/n]) #> ").strip().lower()
                
                if enable_pf == 'y':
                    subprocess.run(["sudo", "pfctl", "-e"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    print("PF firewall enabled.")
                else:
                    print("Cannot add rules while firewall is disabled.")
                    return
            
            if choice == '1':
                # Allow port rule
                protocol = input("Heimdell(Protocol [tcp/udp]) #> ").strip().lower()
                port = input("Heimdell(Port number) #> ").strip()
                
                if not port.isdigit() or int(port) < 1 or int(port) > 65535:
                    print("Invalid port number. Must be between 1-65535.")
                    return
                
                if protocol not in ['tcp', 'udp']:
                    print("Invalid protocol. Must be 'tcp' or 'udp'.")
                    return
                
                # Create the rule
                rule = f"pass in proto {protocol} to any port {port}"
                
                # Add rule to config file and reload
                self._modify_pf_conf(rule)
                
            elif choice == '2':
                # Block IP rule
                ip_address = input("Heimdell(IP address or CIDR range to block) #> ").strip()
                
                # Validate IP
                try:
                    # Check if it's a CIDR range
                    if '/' in ip_address:
                        ipaddress.ip_network(ip_address)
                    else:
                        ipaddress.ip_address(ip_address)
                except ValueError:
                    print("Invalid IP address or CIDR range.")
                    return
                
                # Create the rule
                rule = f"block in from {ip_address} to any"
                
                # Add rule to config file and reload
                self._modify_pf_conf(rule)
                
            elif choice == '3':
                # Advanced custom rule
                print("\nEnter the pf rule:")
                print("Example: pass in proto tcp from any to any port 22")
                
                rule = input("Heimdell(PF rule) #> ").strip()
                
                # Add rule to config file and reload
                self._modify_pf_conf(rule)
            
        except Exception as e:
            print(f"Error adding pf rule: {e}")
    
    def _modify_pf_conf(self, new_rule: str):
        """
        Modify the pf.conf file to add a new rule.
        
        Args:
            new_rule: New rule to add
        """
        try:
            # Check if pf.conf exists
            if not os.path.exists(self.config_path):
                print(f"Config file not found: {self.config_path}")
                
                # Create a basic config file
                basic_config = """
# Basic PF configuration
set skip on lo0
block in all
pass out all
"""
                with open(self.config_path, 'w') as f:
                    f.write(basic_config)
                
                print(f"Created basic PF config at {self.config_path}")
            
            # Create backup
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = os.path.join(self.backup_dir, f"pf.conf_{timestamp}")
            
            # Copy current config to backup
            shutil.copy2(self.config_path, backup_file)
            print(f"Backup created at {backup_file}")
            
            # Read current config
            with open(self.config_path, 'r') as f:
                config_lines = f.readlines()
            
            # Add new rule
            with open(self.config_path, 'w') as f:
                for line in config_lines:
                    f.write(line)
                
                # Add comment and new rule
                f.write(f"\n# Added by Heimdell at {datetime.now()}\n")
                f.write(f"{new_rule}\n")
            
            # Reload pf config
            result = subprocess.run(
                ["sudo", "pfctl", "-f", self.config_path], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                print(f"✓ Rule added and PF config reloaded: {new_rule}")
            else:
                print(f"✗ Error reloading PF config: {result.stderr}")
                
                # Restore from backup
                print("Restoring from backup...")
                shutil.copy2(backup_file, self.config_path)
                
                # Try to reload with original config
                subprocess.run(["sudo", "pfctl", "-f", self.config_path], 
                             stdout=subprocess.PIPE, 
                             stderr=subprocess.PIPE)
                
                print("Restored original configuration.")
            
        except Exception as e:
            print(f"Error modifying PF config: {e}")
    
    def _add_windows_firewall_rule(self):
        """Add a new Windows Firewall rule."""
        print("\nAdd Windows Firewall Rule:")
        
        # Menu for rule type selection
        print("\nRule Type:")
        print("1. Allow program")
        print("2. Allow port")
        print("3. Block program")
        print("4. Block port")
        print("5. Advanced rule (custom)")
        print("0. Cancel")
        
        choice = input("Heimdell(Select rule type) #> ").strip()
        
        if choice == '0':
            return
        
        try:
            if choice == '1' or choice == '3':
                # Program rule
                print("\nEnter the program path:")
                print("Example: C:\\Program Files\\App\\program.exe")
                
                program_path = input("Heimdell(Program path) #> ").strip()
                
                if not os.path.exists(program_path):
                    print(f"Warning: Program path not found: {program_path}")
                    continue_anyway = input("Heimdell(Continue anyway? [y/n]) #> ").strip().lower()
                    if continue_anyway != 'y':
                        return
                
                # Get rule name
                rule_name = input("Heimdell(Rule name) #> ").strip()
                
                if not rule_name:
                    rule_name = os.path.basename(program_path)
                
                # Create the rule
                action = "allow" if choice == '1' else "block"
                
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=\"{rule_name}\"",
                    f"dir=in",
                    f"action={action}",
                    f"program=\"{program_path}\"",
                    "enable=yes"
                ]
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: {action.capitalize()} program {program_path}")
                    
                    # Add outbound rule too?
                    add_outbound = input("Heimdell(Add matching outbound rule? [y/n]) #> ").strip().lower()
                    if add_outbound == 'y':
                        cmd = [
                            "netsh", "advfirewall", "firewall", "add", "rule",
                            f"name=\"{rule_name} (outbound)\"",
                            f"dir=out",
                            f"action={action}",
                            f"program=\"{program_path}\"",
                            "enable=yes"
                        ]
                        
                        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        print(f"✓ Outbound rule added: {action.capitalize()} program {program_path}")
                else:
                    print(f"✗ Error adding rule: {result.stderr}")
                
            elif choice == '2' or choice == '4':
                # Port rule
                protocol = input("Heimdell(Protocol [tcp/udp]) #> ").strip().lower()
                port = input("Heimdell(Port number) #> ").strip()
                
                if not port.isdigit() or int(port) < 1 or int(port) > 65535:
                    print("Invalid port number. Must be between 1-65535.")
                    return
                
                if protocol not in ['tcp', 'udp']:
                    print("Invalid protocol. Must be 'tcp' or 'udp'.")
                    return
                
                # Get rule name
                rule_name = input("Heimdell(Rule name) #> ").strip()
                
                if not rule_name:
                    rule_name = f"{protocol.upper()} Port {port}"
                
                # Create the rule
                action = "allow" if choice == '2' else "block"
                
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=\"{rule_name}\"",
                    f"dir=in",
                    f"action={action}",
                    f"protocol={protocol}",
                    f"localport={port}",
                    "enable=yes"
                ]
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: {action.capitalize()} {protocol} port {port}")
                else:
                    print(f"✗ Error adding rule: {result.stderr}")
                
            elif choice == '5':
                # Advanced custom rule
                print("\nEnter the Windows Firewall command arguments (after 'netsh advfirewall firewall add rule'):")
                print("Example: name=\"SSH\" dir=in action=allow protocol=TCP localport=22")
                
                rule_args = input("Heimdell(Firewall rule args) #> ").strip()
                
                # Create the rule
                cmd = ["netsh", "advfirewall", "firewall", "add", "rule"] + rule_args.split()
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                if result.returncode == 0:
                    print(f"✓ Rule added: {rule_args}")
                else:
                    print(f"✗ Error adding rule: {result.stderr}")
            
        except Exception as e:
            print(f"Error adding Windows Firewall rule: {e}")
    
    def _remove_rule_menu(self):
        """Display menu for removing firewall rules."""
        print("\n" + "=" * 50)
        print("           REMOVE FIREWALL RULE")
        print("=" * 50)
        
        # Different options based on firewall type
        if self.firewall_type == "iptables":
            self._remove_iptables_rule()
        elif self.firewall_type == "nftables":
            self._remove_nftables_rule()
        elif self.firewall_type == "firewalld":
            self._remove_firewalld_rule()
        elif self.firewall_type == "ufw":
            self._remove_ufw_rule()
        elif self.firewall_type == "pf":
            self._remove_pf_rule()
        elif self.firewall_type == "windows":
            self._remove_windows_firewall_rule()
        else:
            print(f"Removing rules for {self.firewall_type} is not supported.")
    def _remove_iptables_rule(self):
        """Remove an iptables rule."""
        # First, list current rules with line numbers
        rules = self._get_iptables_rules()
        
        if not rules:
            print("No rules found to remove.")
            return
        
        # Display rules with indices
        print("\nCurrent iptables Rules:")
        print("-" * 70)
        for i, rule in enumerate(rules, 1):
            print(f"{i}. {rule}")
        
        # Get rule to remove
        rule_num = input("\nHemdell(Enter rule number to remove, or 0 to cancel) #> ").strip()
        
        if rule_num == '0' or not rule_num.isdigit():
            return
        
        rule_idx = int(rule_num) - 1
        if 0 <= rule_idx < len(rules):
            # Extract chain name from the rule
            chain_match = re.search(r'Chain\s+(\w+)', rules[rule_idx])
            if not chain_match:
                print("Cannot determine chain for rule. Please try using the advanced option.")
                return
            
            chain = chain_match.group(1)
            
            # Rules are indexed from 1 in iptables
            line_number_match = re.search(r'^\s*(\d+)', rules[rule_idx])
            if not line_number_match:
                print("Cannot determine line number for rule. Please try using the advanced option.")
                return
            
            line_number = line_number_match.group(1)
            
            # Remove the rule
            cmd = [
                "sudo", "iptables", 
                "-D", chain, 
                line_number
            ]
            
            try:
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                if result.returncode == 0:
                    print(f"✓ Rule removed successfully.")
                    
                    # Save rules to ensure they persist
                    self._save_iptables_rules()
                else:
                    print(f"✗ Error removing rule: {result.stderr.decode()}")
                    
                    # Offer advanced option
                    print("\nWould you like to try removing the rule using advanced options?")
                    advanced = input("Heimdell(Use advanced removal? [y/n]) #> ").strip().lower()
                    
                    if advanced == 'y':
                        self._remove_iptables_rule_advanced()
            except Exception as e:
                print(f"Error removing rule: {e}")
        else:
            print("Invalid rule number.")
    
    def _remove_iptables_rule_advanced(self):
        """Remove an iptables rule using advanced options."""
        print("\nEnter the iptables command to remove the rule:")
        print("Example: -D INPUT -p tcp --dport 22 -j ACCEPT")
        
        rule_args = input("Heimdell(iptables args) #> ").strip()
        
        if not rule_args:
            return
        
        cmd = ["sudo", "iptables"] + rule_args.split()
        
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if result.returncode == 0:
                print(f"✓ Rule removed successfully.")
                
                # Save rules to ensure they persist
                self._save_iptables_rules()
            else:
                print(f"✗ Error removing rule: {result.stderr.decode()}")
        except Exception as e:
            print(f"Error removing rule: {e}")
    
    def _remove_nftables_rule(self):
        """Remove an nftables rule."""
        # For nftables, it's more complex to remove specific rules
        # We'll show the current ruleset and then ask for a handle to delete
        
        print("\nCurrent nftables Rules:")
        print("-" * 70)
        
        try:
            # Show rules with handles
            result = subprocess.run(
                ["sudo", "nft", "--handle", "--numeric", "list", "ruleset"],
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                print(result.stdout)
                
                print("\nTo remove a rule, you need the table, chain, and handle.")
                table = input("Heimdell(Table name) #> ").strip()
                chain = input("Heimdell(Chain name) #> ").strip()
                handle = input("Heimdell(Rule handle number) #> ").strip()
                
                if not table or not chain or not handle.isdigit():
                    print("Invalid input. Table, chain, and handle are required.")
                    return
                
                # Remove the rule
                cmd = [
                    "sudo", "nft", 
                    "delete", "rule", 
                    table, chain, 
                    "handle", handle
                ]
                
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                if result.returncode == 0:
                    print(f"✓ Rule removed successfully.")
                else:
                    print(f"✗ Error removing rule: {result.stderr}")
            else:
                print(f"Error listing rules: {result.stderr}")
        except Exception as e:
            print(f"Error removing nftables rule: {e}")
    
    def _remove_firewalld_rule(self):
        """Remove a firewalld rule."""
        print("\nRemove firewalld Rule:")
        
        # Menu for rule type selection
        print("\nRule Type to Remove:")
        print("1. Service")
        print("2. Port")
        print("3. Rich rule")
        print("4. Source")
        print("0. Cancel")
        
        choice = input("Heimdell(Select rule type) #> ").strip()
        
        if choice == '0':
            return
        
        try:
            # Get zone to remove rule from
            zones = []
            result = subprocess.run(
                ["firewall-cmd", "--get-active-zones"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                zones = []
                current_zone = None
                
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    
                    if not line.startswith(' '):  # Zone name
                        current_zone = line
                        zones.append(current_zone)
            
            if not zones:
                print("No active zones found.")
                return
            
            print("\nAvailable zones:")
            for i, zone in enumerate(zones, 1):
                print(f"{i}. {zone}")
            
            zone_choice = input("Heimdell(Select zone number or name) #> ").strip()
            
            # Get zone from choice
            selected_zone = None
            if zone_choice.isdigit() and 1 <= int(zone_choice) <= len(zones):
                selected_zone = zones[int(zone_choice) - 1]
            elif zone_choice in zones:
                selected_zone = zone_choice
            else:
                print("Invalid zone selection.")
                return
            
            # Remove rule based on choice
            if choice == '1':
                # Remove service
                # List services in zone
                result = subprocess.run(
                    ["firewall-cmd", f"--zone={selected_zone}", "--list-services"], 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if result.returncode == 0:
                    services = result.stdout.strip().split()
                    
                    if not services:
                        print(f"No services found in zone {selected_zone}.")
                        return
                    
                    print("\nServices in zone:")
                    for i, service in enumerate(services, 1):
                        print(f"{i}. {service}")
                    
                    service_choice = input("Heimdell(Select service number or name) #> ").strip()
                    
                    # Get service from choice
                    selected_service = None
                    if service_choice.isdigit() and 1 <= int(service_choice) <= len(services):
                        selected_service = services[int(service_choice) - 1]
                    elif service_choice in services:
                        selected_service = service_choice
                    else:
                        print("Invalid service selection.")
                        return
                    
                    # Remove the service
                    cmd = [
                        "sudo", "firewall-cmd", 
                        f"--zone={selected_zone}", 
                        f"--remove-service={selected_service}"
                    ]
                    
                    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    
                    if result.returncode == 0:
                        print(f"✓ Service {selected_service} removed from zone {selected_zone}")
                        
                        # Make permanent
                        make_perm = input("Heimdell(Make change permanent? [y/n]) #> ").strip().lower()
                        if make_perm == 'y':
                            cmd = [
                                "sudo", "firewall-cmd", 
                                f"--zone={selected_zone}", 
                                f"--remove-service={selected_service}",
                                "--permanent"
                            ]
                            
                            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            print("Change made permanent.")
                    else:
                        print(f"✗ Error removing service: {result.stderr}")
                else:
                    print(f"Error listing services: {result.stderr}")
                
            elif choice == '2':
                # Remove port
                # List ports in zone
                result = subprocess.run(
                    ["firewall-cmd", f"--zone={selected_zone}", "--list-ports"], 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if result.returncode == 0:
                    ports = result.stdout.strip().split()
                    
                    if not ports:
                        print(f"No ports found in zone {selected_zone}.")
                        return
                    
                    print("\nPorts in zone:")
                    for i, port in enumerate(ports, 1):
                        print(f"{i}. {port}")
                    
                    port_choice = input("Heimdell(Select port number or full port spec) #> ").strip()
                    
                    # Get port from choice
                    selected_port = None
                    if port_choice.isdigit() and 1 <= int(port_choice) <= len(ports):
                        selected_port = ports[int(port_choice) - 1]
                    elif port_choice in ports:
                        selected_port = port_choice
                    else:
                        print("Invalid port selection.")
                        return
                    
                    # Remove the port
                    cmd = [
                        "sudo", "firewall-cmd", 
                        f"--zone={selected_zone}", 
                        f"--remove-port={selected_port}"
                    ]
                    
                    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    
                    if result.returncode == 0:
                        print(f"✓ Port {selected_port} removed from zone {selected_zone}")
                        
                        # Make permanent
                        make_perm = input("Heimdell(Make change permanent? [y/n]) #> ").strip().lower()
                        if make_perm == 'y':
                            cmd = [
                                "sudo", "firewall-cmd", 
                                f"--zone={selected_zone}", 
                                f"--remove-port={selected_port}",
                                "--permanent"
                            ]
                            
                            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            print("Change made permanent.")
                    else:
                        print(f"✗ Error removing port: {result.stderr}")
                else:
                    print(f"Error listing ports: {result.stderr}")
                
            elif choice == '3':
                # Remove rich rule
                # List rich rules in zone
                result = subprocess.run(
                    ["firewall-cmd", f"--zone={selected_zone}", "--list-rich-rules"], 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if result.returncode == 0:
                    rich_rules = [r for r in result.stdout.split('\n') if r.strip()]
                    
                    if not rich_rules:
                        print(f"No rich rules found in zone {selected_zone}.")
                        return
                    
                    print("\nRich rules in zone:")
                    for i, rule in enumerate(rich_rules, 1):
                        print(f"{i}. {rule}")
                    
                    rule_choice = input("Heimdell(Select rule number) #> ").strip()
                    
                    # Get rule from choice
                    if rule_choice.isdigit() and 1 <= int(rule_choice) <= len(rich_rules):
                        selected_rule = rich_rules[int(rule_choice) - 1]
                        
                        # Remove the rich rule
                        cmd = [
                            "sudo", "firewall-cmd", 
                            f"--zone={selected_zone}", 
                            f"--remove-rich-rule='{selected_rule}'"
                        ]
                        
                        # Need to use shell=True for rich rules due to quotes
                        result = subprocess.run(
                            " ".join(cmd), 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE,
                            text=True,
                            shell=True
                        )
                        
                        if result.returncode == 0:
                            print(f"✓ Rich rule removed from zone {selected_zone}")
                            
                            # Make permanent
                            make_perm = input("Heimdell(Make change permanent? [y/n]) #> ").strip().lower()
                            if make_perm == 'y':
                                cmd = [
                                    "sudo", "firewall-cmd", 
                                    f"--zone={selected_zone}", 
                                    f"--remove-rich-rule='{selected_rule}'",
                                    "--permanent"
                                ]
                                
                                subprocess.run(" ".join(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                                print("Change made permanent.")
                        else:
                            print(f"✗ Error removing rich rule: {result.stderr}")
                    else:
                        print("Invalid rule selection.")
                else:
                    print(f"Error listing rich rules: {result.stderr}")
                
            elif choice == '4':
                # Remove source
                # List sources in zone
                result = subprocess.run(
                    ["firewall-cmd", f"--zone={selected_zone}", "--list-sources"], 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if result.returncode == 0:
                    sources = result.stdout.strip().split()
                    
                    if not sources:
                        print(f"No sources found in zone {selected_zone}.")
                        return
                    
                    print("\nSources in zone:")
                    for i, source in enumerate(sources, 1):
                        print(f"{i}. {source}")
                    
                    source_choice = input("Heimdell(Select source number or address) #> ").strip()
                    
                    # Get source from choice
                    selected_source = None
                    if source_choice.isdigit() and 1 <= int(source_choice) <= len(sources):
                        selected_source = sources[int(source_choice) - 1]
                    elif source_choice in sources:
                        selected_source = source_choice
                    else:
                        print("Invalid source selection.")
                        return
                    
                    # Remove the source
                    cmd = [
                        "sudo", "firewall-cmd", 
                        f"--zone={selected_zone}", 
                        f"--remove-source={selected_source}"
                    ]
                    
                    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    
                    if result.returncode == 0:
                        print(f"✓ Source {selected_source} removed from zone {selected_zone}")
                        
                        # Make permanent
                        make_perm = input("Heimdell(Make change permanent? [y/n]) #> ").strip().lower()
                        if make_perm == 'y':
                            cmd = [
                                "sudo", "firewall-cmd", 
                                f"--zone={selected_zone}", 
                                f"--remove-source={selected_source}",
                                "--permanent"
                            ]
                            
                            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            print("Change made permanent.")
                    else:
                        print(f"✗ Error removing source: {result.stderr}")
                else:
                    print(f"Error listing sources: {result.stderr}")
            
        except Exception as e:
            print(f"Error removing firewalld rule: {e}")
    
    def _remove_ufw_rule(self):
        """Remove a ufw rule."""
        # Get numbered rules
        try:
            result = subprocess.run(
                ["sudo", "ufw", "status", "numbered"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                rules = []
                for line in result.stdout.split('\n'):
                    if re.match(r'^\s*\[\s*\d+\s*\]', line):
                        rules.append(line.strip())
                
                if not rules:
                    print("No rules found.")
                    return
                
                print("\nCurrent UFW Rules:")
                print("-" * 70)
                for rule in rules:
                    print(rule)
                
                # Get rule number to remove
                rule_num = input("\nHemdell(Enter rule number to remove, or 0 to cancel) #> ").strip()
                
                if rule_num == '0' or not rule_num.isdigit():
                    return
                
                # Extract just the number from "[1]"
                rule_number_match = re.search(r'\[\s*(\d+)\s*\]', rules[int(rule_num) - 1])
                if not rule_number_match:
                    print("Cannot determine rule number. Please check the rule list.")
                    return
                
                rule_number = rule_number_match.group(1)
                
                # Confirm removal
                print(f"\nConfirm removal of rule {rule_number}:")
                confirm = input("Heimdell(Remove rule? [y/n]) #> ").strip().lower()
                
                if confirm != 'y':
                    return
                
                # Remove the rule - need to answer 'y' to the confirmation prompt
                process = subprocess.Popen(
                    ["sudo", "ufw", "delete", rule_number],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Send 'y' to confirm
                stdout, stderr = process.communicate(input="y\n")
                
                if process.returncode == 0:
                    print(f"✓ Rule removed successfully.")
                else:
                    print(f"✗ Error removing rule: {stderr}")
            else:
                print("Error getting UFW rules. Is UFW installed and enabled?")
        except Exception as e:
            print(f"Error removing UFW rule: {e}")
    
    def _remove_pf_rule(self):
        """Remove a pf firewall rule."""
        print("\nTo remove a PF rule, you need to edit the configuration file directly.")
        print(f"PF config file: {self.config_path}")
        
        edit_now = input("Heimdell(Edit PF config now? [y/n]) #> ").strip().lower()
        
        if edit_now != 'y':
            return
        
        try:
            # Create backup
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = os.path.join(self.backup_dir, f"pf.conf_{timestamp}")
            
            # Copy current config to backup
            shutil.copy2(self.config_path, backup_file)
            print(f"Backup created at {backup_file}")
            
            # Determine editor to use
            if self.system == "Darwin":  # macOS
                editor = os.environ.get('EDITOR', 'nano')
            else:
                editor = os.environ.get('EDITOR', 'vi')
            
            # Open the file in the editor
            subprocess.run([editor, self.config_path])
            
            # After editing, check syntax
            result = subprocess.run(
                ["sudo", "pfctl", "-n", "-f", self.config_path], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                print("PF configuration syntax is valid.")
                
                # Ask to reload
                reload_pf = input("Heimdell(Reload PF with new configuration? [y/n]) #> ").strip().lower()
                
                if reload_pf == 'y':
                    result = subprocess.run(
                        ["sudo", "pfctl", "-f", self.config_path], 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    if result.returncode == 0:
                        print("✓ PF configuration reloaded successfully.")
                    else:
                        print(f"✗ Error reloading PF configuration: {result.stderr}")
                        
                        # Offer to restore from backup
                        restore = input("Heimdell(Restore from backup? [y/n]) #> ").strip().lower()
                        
                        if restore == 'y':
                            shutil.copy2(backup_file, self.config_path)
                            
                            # Reload original config
                            subprocess.run(
                                ["sudo", "pfctl", "-f", self.config_path], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE
                            )
                            
                            print("Restored from backup.")
            else:
                print(f"✗ PF configuration syntax error: {result.stderr}")
                
                # Offer to restore from backup
                restore = input("Heimdell(Restore from backup? [y/n]) #> ").strip().lower()
                
                if restore == 'y':
                    shutil.copy2(backup_file, self.config_path)
                    print("Restored from backup.")
        except Exception as e:
            print(f"Error editing PF configuration: {e}")
    
    def _remove_windows_firewall_rule(self):
        """Remove a Windows Firewall rule."""
        print("\nList of enabled Windows Firewall rules:")
        
        try:
            # Get all enabled rules
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "status=enabled", "name=all"],
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                # Parse rules and display them
                rules = []
                rule_name = None
                
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    
                    if line.startswith("Rule Name:"):
                        if rule_name:
                            rules.append(rule_name)
                        rule_name = line[10:].strip()
                    elif not line and rule_name:
                        rules.append(rule_name)
                        rule_name = None
                
                if rule_name:  # Add the last rule
                    rules.append(rule_name)
                
                if not rules:
                    print("No enabled rules found.")
                    return
                
                # Display rules with pagination
                page_size = 10
                total_pages = (len(rules) + page_size - 1) // page_size
                current_page = 1
                
                while True:
                    start_idx = (current_page - 1) * page_size
                    end_idx = min(start_idx + page_size, len(rules))
                    
                    print(f"\nRules (Page {current_page}/{total_pages}):")
                    print("-" * 70)
                    
                    for i, rule in enumerate(rules[start_idx:end_idx], start_idx + 1):
                        print(f"{i}. {rule}")
                    
                    print("\nOptions:")
                    print("n: Next page, p: Previous page, r: Remove rule, 0: Cancel")
                    
                    cmd = input("Heimdell(Action) #> ").strip().lower()
                    
                    if cmd == '0':
                        return
                    elif cmd == 'n' and current_page < total_pages:
                        current_page += 1
                    elif cmd == 'p' and current_page > 1:
                        current_page -= 1
                    elif cmd == 'r':
                        # Remove a rule
                        rule_num = input("Heimdell(Enter rule number to remove) #> ").strip()
                        
                        if rule_num.isdigit() and 1 <= int(rule_num) <= len(rules):
                            rule_to_remove = rules[int(rule_num) - 1]
                            
                            # Confirm removal
                            confirm = input(f"Heimdell(Remove rule '{rule_to_remove}'? [y/n]) #> ").strip().lower()
                            
                            if confirm == 'y':
                                # Remove the rule
                                cmd = [
                                    "netsh", "advfirewall", "firewall", 
                                    "delete", "rule", 
                                    f'name="{rule_to_remove}"'
                                ]
                                
                                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                                
                                if result.returncode == 0:
                                    print(f"✓ Rule '{rule_to_remove}' removed successfully.")
                                    # Reload the rules list
                                    return self._remove_windows_firewall_rule()
                                else:
                                    print(f"✗ Error removing rule: {result.stderr}")
                        else:
                            print("Invalid rule number.")
                    else:
                        print("Invalid command.")
            else:
                print(f"Error listing firewall rules: {result.stderr}")
        except Exception as e:
            print(f"Error removing Windows Firewall rule: {e}")
    
    def _enable_disable_firewall(self):
        """Enable or disable the firewall."""
        print("\n" + "=" * 50)
        print("           ENABLE/DISABLE FIREWALL")
        print("=" * 50)
        
        # Check current status
        status = self.check_firewall_status()
        
        if status["enabled"]:
            print("\nFirewall is currently ENABLED.")
            action = input("Heimdell(Disable firewall? [y/n]) #> ").strip().lower()
            
            if action == 'y':
                self._disable_firewall()
        else:
            print("\nFirewall is currently DISABLED.")
            action = input("Heimdell(Enable firewall? [y/n]) #> ").strip().lower()
            
            if action == 'y':
                self._enable_firewall()
    
    def _enable_firewall(self):
        """Enable the firewall."""
        try:
            if self.system == "Linux":
                if self.firewall_type == "iptables":
                    # Flush chains and set default policy
                    subprocess.run(["sudo", "iptables", "-F"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(["sudo", "iptables", "-P", "INPUT", "DROP"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(["sudo", "iptables", "-P", "FORWARD", "DROP"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    # Allow loopback
                    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    # Allow established connections
                    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    # Save the rules
                    self._save_iptables_rules()
                    
                    print("✓ iptables firewall enabled with default DROP policy.")
                    
                elif self.firewall_type == "nftables":
                    # Create base configuration if it doesn't exist
                    self._ensure_nftables_base_setup()
                    
                    # Set default policy to drop
                    subprocess.run(["sudo", "nft", "chain", "inet", "filter", "input", "{ policy drop; }"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    print("✓ nftables firewall enabled with default DROP policy.")
                    
                elif self.firewall_type == "firewalld":
                    subprocess.run(["sudo", "systemctl", "start", "firewalld"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(["sudo", "systemctl", "enable", "firewalld"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    print("✓ firewalld service started and enabled.")
                    
                elif self.firewall_type == "ufw":
                    # This will prompt for confirmation, so we need to handle the input
                    process = subprocess.Popen(
                        ["sudo", "ufw", "enable"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    # Send 'y' to confirm
                    stdout, stderr = process.communicate(input="y\n")
                    
                    if process.returncode == 0:
                        print(f"✓ Rule removed successfully.")
                    else:
                        print(f"✗ Error removing rule: {stderr}")
                else:
                    print("Error getting UFW rules. Is UFW installed and enabled?")
        except Exception as e:
            print(f"Error removing UFW rule: {e}")
    def _remove_pf_rule(self):
        """Remove a pf firewall rule."""
        print("\nTo remove a PF rule, you need to edit the configuration file directly.")
        print(f"PF config file: {self.config_path}")
        
        edit_now = input("Heimdell(Edit PF config now? [y/n]) #> ").strip().lower()
        
        if edit_now != 'y':
            return
        
        try:
            # Create backup
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = os.path.join(self.backup_dir, f"pf.conf_{timestamp}")
            
            # Copy current config to backup
            shutil.copy2(self.config_path, backup_file)
            print(f"Backup created at {backup_file}")
            
            # Determine editor to use
            if self.system == "Darwin":  # macOS
                editor = os.environ.get('EDITOR', 'nano')
            else:
                editor = os.environ.get('EDITOR', 'vi')
            
            # Open the file in the editor
            subprocess.run([editor, self.config_path])
            
            # After editing, check syntax
            result = subprocess.run(
                ["sudo", "pfctl", "-n", "-f", self.config_path], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                print("PF configuration syntax is valid.")
                
                # Ask to reload
                reload_pf = input("Heimdell(Reload PF with new configuration? [y/n]) #> ").strip().lower()
                
                if reload_pf == 'y':
                    result = subprocess.run(
                        ["sudo", "pfctl", "-f", self.config_path], 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    if result.returncode == 0:
                        print("✓ PF configuration reloaded successfully.")
                    else:
                        print(f"✗ Error reloading PF configuration: {result.stderr}")
                        
                        # Offer to restore from backup
                        restore = input("Heimdell(Restore from backup? [y/n]) #> ").strip().lower()
                        
                        if restore == 'y':
                            shutil.copy2(backup_file, self.config_path)
                            
                            # Reload original config
                            subprocess.run(
                                ["sudo", "pfctl", "-f", self.config_path], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE
                            )
                            
                            print("Restored from backup.")
            else:
                print(f"✗ PF configuration syntax error: {result.stderr}")
                
                # Offer to restore from backup
                restore = input("Heimdell(Restore from backup? [y/n]) #> ").strip().lower()
                
                if restore == 'y':
                    shutil.copy2(backup_file, self.config_path)
                    print("Restored from backup.")
        except Exception as e:
            print(f"Error editing PF configuration: {e}")
    
    def _remove_windows_firewall_rule(self):
        """Remove a Windows Firewall rule."""
        print("\nList of enabled Windows Firewall rules:")
        
        try:
            # Get all enabled rules
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "status=enabled", "name=all"],
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                # Parse rules and display them
                rules = []
                rule_name = None
                
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    
                    if line.startswith("Rule Name:"):
                        if rule_name:
                            rules.append(rule_name)
                        rule_name = line[10:].strip()
                    elif not line and rule_name:
                        rules.append(rule_name)
                        rule_name = None
                
                if rule_name:  # Add the last rule
                    rules.append(rule_name)
                
                if not rules:
                    print("No enabled rules found.")
                    return
                
                # Display rules with pagination
                page_size = 10
                total_pages = (len(rules) + page_size - 1) // page_size
                current_page = 1
                
                while True:
                    start_idx = (current_page - 1) * page_size
                    end_idx = min(start_idx + page_size, len(rules))
                    
                    print(f"\nRules (Page {current_page}/{total_pages}):")
                    print("-" * 70)
                    
                    for i, rule in enumerate(rules[start_idx:end_idx], start_idx + 1):
                        print(f"{i}. {rule}")
                    
                    print("\nOptions:")
                    print("n: Next page, p: Previous page, r: Remove rule, 0: Cancel")
                    
                    cmd = input("Heimdell(Action) #> ").strip().lower()
                    
                    if cmd == '0':
                        return
                    elif cmd == 'n' and current_page < total_pages:
                        current_page += 1
                    elif cmd == 'p' and current_page > 1:
                        current_page -= 1
                    elif cmd == 'r':
                        # Remove a rule
                        rule_num = input("Heimdell(Enter rule number to remove) #> ").strip()
                        
                        if rule_num.isdigit() and 1 <= int(rule_num) <= len(rules):
                            rule_to_remove = rules[int(rule_num) - 1]
                            
                            # Confirm removal
                            confirm = input(f"Heimdell(Remove rule '{rule_to_remove}'? [y/n]) #> ").strip().lower()
                            
                            if confirm == 'y':
                                # Remove the rule
                                cmd = [
                                    "netsh", "advfirewall", "firewall", 
                                    "delete", "rule", 
                                    f'name="{rule_to_remove}"'
                                ]
                                
                                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                                
                                if result.returncode == 0:
                                    print(f"✓ Rule '{rule_to_remove}' removed successfully.")
                                    # Reload the rules list
                                    return self._remove_windows_firewall_rule()
                                else:
                                    print(f"✗ Error removing rule: {result.stderr}")
                        else:
                            print("Invalid rule number.")
                    else:
                        print("Invalid command.")
            else:
                print(f"Error listing firewall rules: {result.stderr}")
        except Exception as e:
            print(f"Error removing Windows Firewall rule: {e}")
    
    def _enable_disable_firewall(self):
        """Enable or disable the firewall."""
        print("\n" + "=" * 50)
        print("           ENABLE/DISABLE FIREWALL")
        print("=" * 50)
        
        # Check current status
        status = self.check_firewall_status()
        
        if status["enabled"]:
            print("\nFirewall is currently ENABLED.")
            action = input("Heimdell(Disable firewall? [y/n]) #> ").strip().lower()
            
            if action == 'y':
                self._disable_firewall()
        else:
            print("\nFirewall is currently DISABLED.")
            action = input("Heimdell(Enable firewall? [y/n]) #> ").strip().lower()
            
            if action == 'y':
                self._enable_firewall()
    
    def _enable_firewall(self):
        """Enable the firewall."""
        try:
            if self.system == "Linux":
                if self.firewall_type == "iptables":
                    # Flush chains and set default policy
                    subprocess.run(["sudo", "iptables", "-F"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(["sudo", "iptables", "-P", "INPUT", "DROP"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(["sudo", "iptables", "-P", "FORWARD", "DROP"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    # Allow loopback
                    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    # Allow established connections
                    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    # Save the rules
                    self._save_iptables_rules()
                    
                    print("✓ iptables firewall enabled with default DROP policy.")
                    
                elif self.firewall_type == "nftables":
                    # Create base configuration if it doesn't exist
                    self._ensure_nftables_base_setup()
                    
                    # Set default policy to drop
                    subprocess.run(["sudo", "nft", "chain", "inet", "filter", "input", "{ policy drop; }"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    print("✓ nftables firewall enabled with default DROP policy.")
                    
                elif self.firewall_type == "firewalld":
                    subprocess.run(["sudo", "systemctl", "start", "firewalld"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(["sudo", "systemctl", "enable", "firewalld"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    print("✓ firewalld service started and enabled.")
                    
                elif self.firewall_type == "ufw":
                    # This will prompt for confirmation, so we need to handle the input
                    process = subprocess.Popen(
                        ["sudo", "ufw", "enable"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    # Send 'y' to confirm
                    stdout, stderr = process.communicate(input="y\n")
                    
                    if process.returncode == 0:
                        print("✓ ufw firewall enabled.")
                    else:
                        print(f"✗ Error enabling ufw: {stderr}")
            
            elif self.system == "Darwin":
                # For macOS pf
                subprocess.run(["sudo", "pfctl", "-e"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print("✓ pf firewall enabled.")
                
            elif self.system == "Windows":
                # Enable all profiles
                subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print("✓ Windows Firewall enabled for all profiles.")
            
        except Exception as e:
            print(f"Error enabling firewall: {e}")
    
    def _disable_firewall(self):
        """Disable the firewall."""
        try:
            if self.system == "Linux":
                if self.firewall_type == "iptables":
                    # Flush chains and set default policy to ACCEPT
                    subprocess.run(["sudo", "iptables", "-F"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(["sudo", "iptables", "-P", "INPUT", "ACCEPT"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    # Save the rules
                    self._save_iptables_rules()
                    
                    print("✓ iptables firewall disabled (all traffic allowed).")
                    
                elif self.firewall_type == "nftables":
                    # Set default policy to accept
                    subprocess.run(["sudo", "nft", "chain", "inet", "filter", "input", "{ policy accept; }"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    print("✓ nftables firewall disabled (all traffic allowed).")
                    
                elif self.firewall_type == "firewalld":
                    subprocess.run(["sudo", "systemctl", "stop", "firewalld"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(["sudo", "systemctl", "disable", "firewalld"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    print("✓ firewalld service stopped and disabled.")
                    
                elif self.firewall_type == "ufw":
                    # This will prompt for confirmation, so we need to handle the input
                    process = subprocess.Popen(
                        ["sudo", "ufw", "disable"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    stdout, stderr = process.communicate()
                    
                    if process.returncode == 0:
                        print("✓ ufw firewall disabled.")
                    else:
                        print(f"✗ Error disabling ufw: {stderr}")
            
            elif self.system == "Darwin":
                # For macOS pf
                subprocess.run(["sudo", "pfctl", "-d"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print("✓ pf firewall disabled.")
                
            elif self.system == "Windows":
                # Disable all profiles
                subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "off"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print("✓ Windows Firewall disabled for all profiles.")
            
        except Exception as e:
            print(f"Error disabling firewall: {e}")
    
    def _set_default_policy(self):
        """Set the default policy for the firewall."""
        print("\n" + "=" * 50)
        print("           SET DEFAULT POLICY")
        print("=" * 50)
        
        print("\nAvailable policies:")
        print("1. DROP (deny and log all connections by default)")
        print("2. REJECT (deny and return error for all connections by default)")
        print("3. ACCEPT (allow all connections by default)")
        print("0. Cancel")
        
        choice = input("Heimdell(Select default policy) #> ").strip()
        
        if choice == '0':
            return
        
        try:
            if choice == '1':
                policy = "DROP"
            elif choice == '2':
                policy = "REJECT"
            elif choice == '3':
                policy = "ACCEPT"
            else:
                print("Invalid choice.")
                return
            
            if self.system == "Linux":
                if self.firewall_type == "iptables":
                    # Set default policy for INPUT chain
                    subprocess.run(["sudo", "iptables", "-P", "INPUT", policy], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    # Set default policy for FORWARD chain
                    subprocess.run(["sudo", "iptables", "-P", "FORWARD", policy], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    # Save the rules
                    self._save_iptables_rules()
                    
                    print(f"✓ Default policy set to {policy} for INPUT and FORWARD chains.")
                    
                elif self.firewall_type == "nftables":
                    # Set default policy for input chain
                    policy_lower = policy.lower()
                    subprocess.run(["sudo", "nft", "chain", "inet", "filter", "input", f"{{ policy {policy_lower}; }}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    print(f"✓ Default policy set to {policy} for input chain.")
                    
                elif self.firewall_type == "firewalld":
                    # firewalld uses zones, so we need to set the default zone's target
                    # Get the default zone
                    result = subprocess.run(["firewall-cmd", "--get-default-zone"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    
                    if result.returncode == 0:
                        default_zone = result.stdout.strip()
                        
                        # Convert policy to firewalld target
                        if policy == "DROP":
                            target = "DROP"
                        elif policy == "REJECT":
                            target = "REJECT"
                        else:
                            target = "ACCEPT"
                        
                        # Set the target for the zone
                        cmd = ["sudo", "firewall-cmd", "--permanent", f"--zone={default_zone}", f"--set-target={target}"]
                        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        
                        # Reload to apply changes
                        subprocess.run(["sudo", "firewall-cmd", "--reload"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        
                        print(f"✓ Default policy set to {policy} for zone {default_zone}.")
                    else:
                        print("Error getting default zone.")
                    
                elif self.firewall_type == "ufw":
                    # UFW default policy
                    if policy == "DROP" or policy == "REJECT":
                        cmd_incoming = ["sudo", "ufw", "default", "deny", "incoming"]
                    else:
                        cmd_incoming = ["sudo", "ufw", "default", "allow", "incoming"]
                    
                    # Always allow outgoing by default
                    cmd_outgoing = ["sudo", "ufw", "default", "allow", "outgoing"]
                    
                    subprocess.run(cmd_incoming, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(cmd_outgoing, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    print(f"✓ Default policy set for incoming connections.")
            
            elif self.system == "Darwin":
                # For macOS pf, we need to edit the config file
                print("For macOS pf firewall, you need to edit the config file to change default policy.")
                edit_now = input("Heimdell(Edit pf.conf now? [y/n]) #> ").strip().lower()
                
                if edit_now == 'y':
                    # Create backup
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    backup_file = os.path.join(self.backup_dir, f"pf.conf_{timestamp}")
                    
                    # Copy current config to backup
                    shutil.copy2(self.config_path, backup_file)
                    print(f"Backup created at {backup_file}")
                    
                    # Default policy lines
                    if policy == "DROP":
                        default_policy_line = "block in all\npass out all\n"
                    elif policy == "REJECT":
                        default_policy_line = "block return in all\npass out all\n"
                    else:
                        default_policy_line = "pass in all\npass out all\n"
                    
                    # Read current config
                    with open(self.config_path, 'r') as f:
                        config_lines = f.readlines()
                    
                    # Look for existing policy lines to replace
                    new_config = []
                    found_policy = False
                    
                    for line in config_lines:
                        if re.match(r'^(block|pass)', line.strip()):
                            if not found_policy:
                                # Add our new policy (only once)
                                new_config.append(default_policy_line)
                                found_policy = True
                        else:
                            new_config.append(line)
                    
                    # If we didn't find any policy lines, add ours
                    if not found_policy:
                        new_config.append(default_policy_line)
                    
                    # Write new config
                    with open(self.config_path, 'w') as f:
                        f.writelines(new_config)
                    
                    # Reload pf config
                    result = subprocess.run(["sudo", "pfctl", "-f", self.config_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    
                    if result.returncode == 0:
                        print(f"✓ Default policy set to {policy} and PF config reloaded.")
                    else:
                        print(f"✗ Error reloading PF config: {result.stderr}")
                        
                        # Restore from backup
                        shutil.copy2(backup_file, self.config_path)
                        subprocess.run(["sudo", "pfctl", "-f", self.config_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        print("Restored original configuration.")
                
            elif self.system == "Windows":
                # Windows Firewall policy
                if policy == "DROP" or policy == "REJECT":
                    action = "block"
                else:
                    action = "allow"
                
                # Set default policy for all profiles
                cmd = ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", f"{action}inbound,allowoutbound"]
                subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                print(f"✓ Default policy set to {policy} (inbound) for all profiles.")
            
        except Exception as e:
            print(f"Error setting default policy: {e}")
    
    # ==== Rule Template Functions ====
    
    def _apply_rule_templates(self):
        """Display and handle the rule templates menu."""
        print("\n" + "=" * 50)
        print("           APPLY RULE TEMPLATES")
        print("=" * 50)
        
        print("\nRule Templates:")
        templates = list(self.rule_templates.keys())
        
        for i, template_key in enumerate(templates, 1):
            template = self.rule_templates[template_key]
            status = "✓ Enabled" if template['enabled'] else "✗ Disabled"
            print(f"{i}. {template['name']} [{status}]")
            print(f"   {template['description']}")
        
        print("\n0. Back")
        
        choice = input("Heimdell(Select template to apply, or 0 to return) #> ").strip()
        
        if choice == '0':
            return
        
        try:
            template_idx = int(choice) - 1
            if 0 <= template_idx < len(templates):
                template_key = templates[template_idx]
                template = self.rule_templates[template_key]
                
                print(f"\nTemplate: {template['name']}")
                print(f"Description: {template['description']}")
                print(f"Status: {'Enabled' if template['enabled'] else 'Disabled'}")
                
                # Show template rules
                print("\nRules in template:")
                for i, rule in enumerate(template['rules'], 1):
                    # Format depends on firewall type
                    if isinstance(rule, dict):
                        rule_str = f"{rule.get('action', 'UNKNOWN')} {rule.get('protocol', 'any')} on port {rule.get('port', 'any')}"
                        if 'source' in rule:
                            rule_str += f" from {rule['source']}"
                        if 'destination' in rule:
                            rule_str += f" to {rule['destination']}"
                    else:
                        rule_str = str(rule)
                    
                    print(f"{i}. {rule_str}")
                
                # Options
                print("\nOptions:")
                print("1. Apply template rules")
                print("2. Toggle template status (enable/disable)")
                print("3. Edit template rules")
                print("0. Back")
                
                action = input("Heimdell(Select action) #> ").strip()
                
                if action == '0':
                    return
                elif action == '1':
                    if template['enabled']:
                        self._apply_template_rules(template_key, template)
                    else:
                        print("Template is disabled. Please enable it first.")
                elif action == '2':
                    # Toggle status
                    self.rule_templates[template_key]['enabled'] = not template['enabled']
                    status = "enabled" if self.rule_templates[template_key]['enabled'] else "disabled"
                    print(f"Template {template['name']} is now {status}.")
                elif action == '3':
                    self._edit_template_rules(template_key, template)
            else:
                print("Invalid template selection.")
        except ValueError:
            print("Please enter a number.")
        except Exception as e:
            print(f"Error processing template: {e}")
    
    def _apply_template_rules(self, template_key, template):
        """
        Apply rules from a template to the firewall.
        
        Args:
            template_key: Key of the template in the rule_templates dict
            template: The template dictionary
        """
        print(f"\nApplying rules from template: {template['name']}")
        
        if not template['rules']:
            print("Template has no rules to apply.")
            return
        
        # Confirm application
        confirm = input("Heimdell(Apply these rules to your firewall? [y/n]) #> ").strip().lower()
        
        if confirm != 'y':
            return
        
        # Apply rules based on firewall type
        success_count = 0
        error_count = 0
        
        try:
            for rule in template['rules']:
                # Convert template rule to actual firewall rule and apply
                if self.system == "Linux":
                    if self.firewall_type == "iptables":
                        success = self._apply_iptables_template_rule(rule)
                    elif self.firewall_type == "nftables":
                        success = self._apply_nftables_template_rule(rule)
                    elif self.firewall_type == "firewalld":
                        success = self._apply_firewalld_template_rule(rule)
                    elif self.firewall_type == "ufw":
                        success = self._apply_ufw_template_rule(rule)
                    else:
                        print(f"Applying templates for {self.firewall_type} is not supported.")
                        return
                elif self.system == "Darwin":
                    success = self._apply_pf_template_rule(rule)
                elif self.system == "Windows":
                    success = self._apply_windows_template_rule(rule)
                else:
                    print(f"Applying templates for {self.system} is not supported.")
                    return
                
                if success:
                    success_count += 1
                else:
                    error_count += 1
            
            print(f"\nTemplate application complete: {success_count} rules applied, {error_count} errors.")
            
            # If iptables, save rules
            if self.system == "Linux" and self.firewall_type == "iptables":
                self._save_iptables_rules()
                
        except Exception as e:
            print(f"Error applying template rules: {e}")
    
    def _apply_iptables_template_rule(self, rule):
        """
        Apply a template rule to iptables.
        
        Args:
            rule: Rule dict or string
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if isinstance(rule, dict):
                # Convert dict to iptables command
                cmd = ["sudo", "iptables"]
                
                # Add action (-A INPUT)
                cmd.extend(["-A", "INPUT"])
                
                # Add protocol if specified
                if 'protocol' in rule and rule['protocol'] not in ['any', '*']:
                    cmd.extend(["-p", rule['protocol']])
                
                # Add source if specified
                if 'source' in rule and rule['source'] not in ['any', '*']:
                    cmd.extend(["-s", rule['source']])
                
                # Add destination if specified
                if 'destination' in rule and rule['destination'] not in ['any', '*']:
                    cmd.extend(["-d", rule['destination']])
                
                # Add port if specified
                if 'port' in rule and rule['port'] not in ['any', '*']:
                    dport_opt = "--dport" if 'protocol' in rule and rule['protocol'] in ['tcp', 'udp'] else "--dport"
                    cmd.extend([dport_opt, str(rule['port'])])
                
                # Add jump target (action)
                if 'action' in rule:
                    action = rule['action'].upper()
                    cmd.extend(["-j", action])
                else:
                    cmd.extend(["-j", "ACCEPT"])  # Default to ACCEPT
            else:
                # Rule is a string, parse it
                if rule.startswith("iptables "):
                    rule = rule[9:]  # Remove "iptables " prefix
                
                cmd = ["sudo", "iptables"] + rule.split()
            
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if result.returncode == 0:
                print(f"✓ Applied rule: {' '.join(cmd[2:])}")
                return True
            else:
                print(f"✗ Error applying rule: {result.stderr.decode()}")
                return False
                
        except Exception as e:
            print(f"Error applying iptables rule: {e}")
            return False
    
    def _apply_nftables_template_rule(self, rule):
        """
        Apply a template rule to nftables.
        
        Args:
            rule: Rule dict or string
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Ensure base setup exists
            self._ensure_nftables_base_setup()
            
            if isinstance(rule, dict):
                # Convert dict to nftables command
                base_cmd = ["sudo", "nft", "add", "rule", "inet", "filter", "input"]
                cmd = base_cmd.copy()
                
                # Add protocol if specified
                if 'protocol' in rule and rule['protocol'] not in ['any', '*']:
                    cmd.append(rule['protocol'])
                
                # Add source if specified
                if 'source' in rule and rule['source'] not in ['any', '*']:
                    cmd.extend(["ip", "saddr", rule['source']])
                
                # Add destination if specified
                if 'destination' in rule and rule['destination'] not in ['any', '*']:
                    cmd.extend(["ip", "daddr", rule['destination']])
                
                # Add port if specified
                if 'port' in rule and rule['port'] not in ['any', '*']:
                    if 'protocol' in rule and rule['protocol'] in ['tcp', 'udp']:
                        cmd.extend([rule['protocol'], "dport", str(rule['port'])])
                
                # Add action
                if 'action' in rule:
                    action = rule['action'].lower()
                    cmd.append(action)
                else:
                    cmd.append("accept")  # Default to accept
            else:
                # Rule is a string, parse it
                if rule.startswith("nft "):
                    rule = rule[4:]  # Remove "nft " prefix
                
                cmd = ["sudo", "nft"] + rule.split()
            
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if result.returncode == 0:
                print(f"✓ Applied rule: {' '.join(cmd[2:])}")
                return True
            else:
                print(f"✗ Error applying rule: {result.stderr.decode()}")
                return False
                
        except Exception as e:
            print(f"Error applying nftables rule: {e}")
            return False
    
    def _apply_firewalld_template_rule(self, rule):
        """
        Apply a template rule to firewalld.
        
        Args:
            rule: Rule dict or string
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get default zone
            result = subprocess.run(["firewall-cmd", "--get-default-zone"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if result.returncode != 0:
                print("Error getting default zone.")
                return False
                
            default_zone = result.stdout.strip()
            
            if isinstance(rule, dict):
                # Convert dict to firewalld command
                if 'service' in rule:
                    # Add service
                    service = rule['service']
                    cmd = ["sudo", "firewall-cmd", f"--zone={default_zone}", f"--add-service={service}"]
                elif 'port' in rule and 'protocol' in rule:
                    # Add port
                    port = rule['port']
                    protocol = rule['protocol']
                    cmd = ["sudo", "firewall-cmd", f"--zone={default_zone}", f"--add-port={port}/{protocol}"]
                elif 'source' in rule and rule.get('action', '').upper() == 'DROP':
                    # Block source
                    source = rule['source']
                    rich_rule = f'rule family="ipv4" source address="{source}" drop'
                    cmd = ["sudo", "firewall-cmd", f"--zone={default_zone}", f"--add-rich-rule='{rich_rule}'"]
                else:
                    # Not supported, try as a rich rule
                    rich_rule = "rule "
                    
                    if 'protocol' in rule:
                        rich_rule += f'protocol="{rule["protocol"]}" '
                    
                    if 'source' in rule:
                        rich_rule += f'source address="{rule["source"]}" '
                    
                    if 'destination' in rule:
                        rich_rule += f'destination address="{rule["destination"]}" '
                    
                    if 'port' in rule:
                        rich_rule += f'port port="{rule["port"]}" '
                    
                    # Add action
                    action = rule.get('action', 'ACCEPT').lower()
                    if action == 'drop':
                        rich_rule += 'drop'
                    elif action == 'reject':
                        rich_rule += 'reject'
                    else:
                        rich_rule += 'accept'
                    
                    cmd = ["sudo", "firewall-cmd", f"--zone={default_zone}", f"--add-rich-rule='{rich_rule}'"]
            else:
                # Rule is a string
                if "firewall-cmd" in rule:
                    # Extract just the arguments
                    rule = rule.split("firewall-cmd", 1)[1].strip()
                
                cmd = ["sudo", "firewall-cmd"] + rule.split()
            
            # Need to use shell=True for rich rules due to quotes
            if "--add-rich-rule" in " ".join(cmd):
                result = subprocess.run(" ".join(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
            else:
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                print(f"✓ Applied rule: {' '.join(cmd[2:])}")
                
                # Make permanent
                if "--permanent" not in " ".join(cmd):
                    if "--add-rich-rule" in " ".join(cmd):
                        perm_cmd = " ".join(cmd) + " --permanent"
                        subprocess.run(perm_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                    else:
                        cmd.append("--permanent")
                        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                return True
            else:
                print(f"✗ Error applying rule: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"Error applying firewalld rule: {e}")
            return False
    
    def _apply_ufw_template_rule(self, rule):
        """
        Apply a template rule to ufw.
        
        Args:
            rule: Rule dict or string
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if isinstance(rule, dict):
                # Convert dict to ufw command
                base_cmd = ["sudo", "ufw"]
                
                # Determine action
                if 'action' in rule:
                    action = rule['action'].lower()
                    if action in ['drop', 'reject']:
                        action = "deny"
                    else:
                        action = "allow"
                else:
                    action = "allow"  # Default to allow
                
                cmd = base_cmd + [action]
                
                # Add protocol/port
                if 'port' in rule and 'protocol' in rule:
                    cmd.append(f"{rule['port']}/{rule['protocol']}")
                elif 'port' in rule:
                    cmd.append(str(rule['port']))
                elif 'service' in rule:
                    cmd.append(rule['service'])
                
                # Add source/destination
                if 'source' in rule and rule['source'] not in ['any', '*']:
                    cmd.extend(["from", rule['source']])
                
                if 'destination' in rule and rule['destination'] not in ['any', '*']:
                    cmd.extend(["to", rule['destination']])
            else:
                # Rule is a string
                if "ufw" in rule:
                    # Extract just the arguments
                    rule = rule.split("ufw", 1)[1].strip()
                
                cmd = ["sudo", "ufw"] + rule.split()
            
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                print(f"✓ Applied rule: {' '.join(cmd[2:])}")
                return True
            else:
                print(f"✗ Error applying rule: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"Error applying ufw rule: {e}")
            return False#!/usr/bin/env python3