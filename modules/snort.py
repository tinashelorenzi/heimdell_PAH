#!/usr/bin/env python3
"""
Heimdell Snort IDS Module

This module provides functionality to:
1. Install Snort IDS
2. Check Snort health status
3. Configure Snort rules through an interactive prompt
4. Collect and process Snort alerts
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
from typing import Dict, Any, List, Tuple, Optional, Union

class SnortModule:
    """
    Heimdell module for managing Snort IDS integration.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the Snort module.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Set default paths
        self.system = platform.system()
        if self.system == "Linux":
            self.snort_bin = self.config.get('snort_bin', '/usr/sbin/snort')
            self.snort_conf = self.config.get('snort_conf', '/etc/snort/snort.conf')
            self.snort_rules_dir = self.config.get('snort_rules_dir', '/etc/snort/rules')
            self.snort_log_dir = self.config.get('snort_log_dir', '/var/log/snort')
            self.alert_file = self.config.get('alert_file', '/var/log/snort/alert')
        elif self.system == "Darwin":  # macOS
            self.snort_bin = self.config.get('snort_bin', '/usr/local/bin/snort')
            self.snort_conf = self.config.get('snort_conf', '/usr/local/etc/snort/snort.conf')
            self.snort_rules_dir = self.config.get('snort_rules_dir', '/usr/local/etc/snort/rules')
            self.snort_log_dir = self.config.get('snort_log_dir', '/usr/local/var/log/snort')
            self.alert_file = self.config.get('alert_file', '/usr/local/var/log/snort/alert')
        else:  # Windows or other
            self.snort_bin = self.config.get('snort_bin', 'C:\\Snort\\bin\\snort.exe')
            self.snort_conf = self.config.get('snort_conf', 'C:\\Snort\\etc\\snort.conf')
            self.snort_rules_dir = self.config.get('snort_rules_dir', 'C:\\Snort\\rules')
            self.snort_log_dir = self.config.get('snort_log_dir', 'C:\\Snort\\log')
            self.alert_file = self.config.get('alert_file', 'C:\\Snort\\log\\alert')
        
        # Tracking for alert file reading
        self.position_file = self.config.get('position_file', '.snort_position')
        self.last_position = 0
        self.last_check = 0
        
        # Rule templates/categories
        self.rule_templates = {
            'dos': {
                'name': 'Denial of Service',
                'description': 'Rules to detect denial of service attacks',
                'filename': 'dos.rules',
                'enabled': True
            },
            'exploit': {
                'name': 'Exploit Detection',
                'description': 'Rules to detect known exploits and vulnerabilities',
                'filename': 'exploit.rules',
                'enabled': True
            },
            'scan': {
                'name': 'Port Scanning',
                'description': 'Rules to detect port scanning activity',
                'filename': 'scan.rules',
                'enabled': True
            },
            'web-attacks': {
                'name': 'Web Attacks',
                'description': 'Rules to detect common web application attacks',
                'filename': 'web-attacks.rules',
                'enabled': True
            },
            'malware': {
                'name': 'Malware',
                'description': 'Rules to detect malware communication',
                'filename': 'malware.rules',
                'enabled': True
            },
            'backdoor': {
                'name': 'Backdoors',
                'description': 'Rules to detect backdoor activity',
                'filename': 'backdoor.rules',
                'enabled': True
            },
            'policy': {
                'name': 'Policy Violations',
                'description': 'Rules to detect policy violations',
                'filename': 'policy.rules',
                'enabled': False
            },
            'custom': {
                'name': 'Custom Rules',
                'description': 'User-defined custom rules',
                'filename': 'custom.rules',
                'enabled': False
            }
        }
        
        # Load last position for alert reading
        self._load_position()

    def run(self):
        """
        Main entry point for running the Snort module.
        This function is called when the module is executed through the 'runmodule' command.
        """
        print("\n" + "=" * 60)
        print("             HEIMDELL - SNORT IDS MODULE")
        print("=" * 60)
        print("       \"Watching the network, detecting intrusions\"")
        print("-" * 60)
        
        # Check if Snort is installed
        if not self._is_snort_installed():
            print("Snort IDS is not installed.")
            install_now = input("Heimdell(Would you like to install Snort now? [y/n]) #> ").strip().lower()
            if install_now == 'y':
                if not self.install():
                    print("Snort installation failed. Please install manually and try again.")
                    return
            else:
                print("Skipping Snort installation. Some features may not work.")
        
        # Main module menu
        while True:
            self._print_module_menu()
            choice = input("Heimdell(Select an option) #> ").strip()
            
            if choice == '0':
                print("Exiting Snort module.")
                break
                
            elif choice == '1':
                # Check Snort health
                health = self.check_health()
                self._display_health_results(health)
                
            elif choice == '2':
                # Manage Rules - Simplified interface
                self._manage_rules()
                
            elif choice == '3':
                # Monitor alerts
                self.monitor_alerts()
                
            elif choice == '4':
                # Start/Stop Snort service
                self._manage_snort_service()
                
            else:
                print("Invalid option. Please try again.")

    def _print_module_menu(self):
        """Display the main Snort module menu."""
        print("\nSnort Module Options:")
        print("1. Check Snort Health")
        print("2. Manage Rules")
        print("3. Monitor Alerts")
        print("4. Start/Stop Snort Service")
        print("0. Exit Module")
        print("")
    
    def _display_health_results(self, health):
        """
        Display the results of a health check in a formatted way.
        
        Args:
            health: Health check results dictionary
        """
        print("\n--- Snort Health Check Results ---")
        
        # Status indicator
        status = "✓ HEALTHY" if health["status"] == "healthy" else "✗ UNHEALTHY"
        print(f"Overall Status: {status}")
        
        # Basic information
        print(f"Snort Installed: {'Yes' if health['installed'] else 'No'}")
        print(f"Snort Version: {health['version']}")
        
        # Files and directories
        print(f"Config File: {'Found' if health['config_file_exists'] else 'Missing'}")
        print(f"Rules Directory: {'Found' if health['rules_directory_exists'] else 'Missing'}")
        print(f"Log Directory: {'Found' if health['log_directory_exists'] else 'Missing'}")
        
        # Configuration status
        if health.get('config_valid') is not None:
            print(f"Config Syntax: {'Valid' if health['config_valid'] else 'Invalid'}")
        
        # Rule count
        print(f"Active Rules: {health['rules_count']}")
        
        # Running status
        print(f"Service Status: {'Running' if health['is_running'] else 'Stopped'}")
        
        # Errors, if any
        if health["errors"]:
            print("\nIssues Detected:")
            for i, error in enumerate(health["errors"], 1):
                print(f"  {i}. {error}")
        
        print("")
    
    # ==== Installation Functions ====
    
    def install(self) -> bool:
        """
        Install Snort IDS.
        
        Returns:
            bool: True if installation was successful, False otherwise
        """
        print("\nPreparing to install Snort IDS...")
        
        if self._is_snort_installed():
            print("Snort is already installed!")
            return True
            
        # Choose installation method based on platform
        if self.system == "Linux":
            return self._install_linux()
        elif self.system == "Darwin":  # macOS
            return self._install_macos()
        elif self.system == "Windows":
            return self._install_windows()
        else:
            print(f"Unsupported platform: {self.system}")
            return False
    
    def _is_snort_installed(self) -> bool:
        """
        Check if Snort is already installed.
        
        Returns:
            bool: True if Snort is installed, False otherwise
        """
        # Check if snort binary exists
        if os.path.exists(self.snort_bin):
            print(f"Snort found installed at: {self.snort_bin}")
            try:
                # Try to run snort -V to check version
                result = subprocess.run([self.snort_bin, '-V'], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE,
                                       text=True,
                                       timeout=5)
                print("Snort version:", result.stdout.strip())
                if result.returncode == 0 and "Snort" in result.stdout:
                    return True
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
        return False
    
    def _install_linux(self) -> bool:
        """
        Install Snort on Linux.
        
        Returns:
            bool: True if installation was successful, False otherwise
        """
        # Detect the Linux distribution
        distro = self._get_linux_distro()
        
        print(f"Detected Linux distribution: {distro}")
        
        # Install based on distribution
        if distro == "ubuntu" or distro == "debian":
            cmd = [
                "sudo", "apt-get", "update", "&&",
                "sudo", "apt-get", "install", "-y",
                "snort", "snort-rules-default"
            ]
        elif distro == "fedora" or distro == "rhel" or distro == "centos":
            cmd = [
                "sudo", "dnf", "install", "-y", "snort"
            ]
        elif distro == "arch":
            cmd = [
                "sudo", "pacman", "-S", "--noconfirm", "snort"
            ]
        else:
            print(f"Unsupported Linux distribution: {distro}")
            print("Please install Snort manually and configure paths in Heimdell")
            return False
        
        try:
            print("Installing Snort. This may take a few minutes...")
            # Run as a string to allow && syntax
            result = subprocess.run(" ".join(cmd), shell=True, check=True)
            
            # Verify installation
            if self._is_snort_installed():
                print("Snort installed successfully!")
                self._create_directories()
                return True
            else:
                print("Snort installation appears to have failed. Please check system logs.")
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"Error installing Snort: {e}")
            return False
    
    def _install_macos(self) -> bool:
        """
        Install Snort on macOS using Homebrew.
        
        Returns:
            bool: True if installation was successful, False otherwise
        """
        # Check if Homebrew is installed
        try:
            subprocess.run(["brew", "--version"], check=True, stdout=subprocess.PIPE)
        except (subprocess.SubprocessError, FileNotFoundError):
            print("Homebrew is not installed. Please install Homebrew first:")
            print("  /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"")
            return False
        
        # Install Snort with Homebrew
        try:
            print("Installing Snort with Homebrew. This may take a few minutes...")
            subprocess.run(["brew", "install", "snort"], check=True)
            
            # Verify installation
            if self._is_snort_installed():
                print("Snort installed successfully!")
                self._create_directories()
                return True
            else:
                print("Snort installation appears to have failed.")
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"Error installing Snort: {e}")
            return False
    
    def _install_windows(self) -> bool:
        """
        Provide instructions for manual Snort installation on Windows.
        
        Returns:
            bool: Always returns False as manual installation is required
        """
        print("Automatic Snort installation on Windows is not supported.")
        print("\nPlease install Snort manually with these steps:")
        print("1. Download Snort from https://www.snort.org/downloads")
        print("2. Run the installer and follow the prompts")
        print("3. Configure the following paths in Heimdell:")
        print("   - Snort binary: C:\\Snort\\bin\\snort.exe")
        print("   - Snort config: C:\\Snort\\etc\\snort.conf")
        print("   - Rules directory: C:\\Snort\\rules")
        print("   - Log directory: C:\\Snort\\log")
        
        return False
    
    def _get_linux_distro(self) -> str:
        """
        Determine the Linux distribution.
        
        Returns:
            str: Name of the Linux distribution
        """
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("ID="):
                        return line.split("=")[1].strip().strip('"').lower()
        
        # Fallback method
        if os.path.exists("/etc/debian_version"):
            return "debian"
        elif os.path.exists("/etc/fedora-release"):
            return "fedora"
        elif os.path.exists("/etc/redhat-release"):
            return "rhel"
        elif os.path.exists("/etc/arch-release"):
            return "arch"
            
        return "unknown"
    
    def _create_directories(self) -> bool:
        """
        Create necessary directories for Snort if they don't exist.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            directories = [
                self.snort_rules_dir,
                self.snort_log_dir
            ]
            
            for directory in directories:
                if not os.path.exists(directory):
                    os.makedirs(directory, mode=0o755, exist_ok=True)
                    print(f"Created directory: {directory}")
                    
                    # Set permissions on Unix-like systems
                    if self.system != "Windows":
                        try:
                            import pwd, grp
                            snort_user = pwd.getpwnam("snort").pw_uid
                            snort_group = grp.getgrnam("snort").gr_gid
                            os.chown(directory, snort_user, snort_group)
                        except (KeyError, PermissionError, ImportError):
                            print("Could not set directory ownership to snort user.")
            
            return True
            
        except Exception as e:
            print(f"Error creating directories: {e}")
            return False
    
    # ==== Health Check Functions ====
    
    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the Snort installation.
        
        Returns:
            dict: Dictionary containing health status information
        """
        health = {
            "installed": self._is_snort_installed(),
            "version": self._get_snort_version(),
            "config_file_exists": os.path.exists(self.snort_conf),
            "rules_directory_exists": os.path.exists(self.snort_rules_dir),
            "log_directory_exists": os.path.exists(self.snort_log_dir),
            "rules_count": self._count_rules(),
            "is_running": self._is_snort_running(),
            "errors": []
        }
        
        # Check config file
        if not health["config_file_exists"]:
            health["errors"].append(f"Config file not found: {self.snort_conf}")
        
        # Check rules directory
        if not health["rules_directory_exists"]:
            health["errors"].append(f"Rules directory not found: {self.snort_rules_dir}")
        
        # Check log directory
        if not health["log_directory_exists"]:
            health["errors"].append(f"Log directory not found: {self.snort_log_dir}")
        
        # Verify config file syntax
        if health["config_file_exists"]:
            config_valid, config_error = self._verify_config()
            health["config_valid"] = config_valid
            if not config_valid:
                health["errors"].append(f"Config syntax error: {config_error}")
        
        # Overall health status
        health["status"] = "healthy" if not health["errors"] else "unhealthy"
        
        return health
    
    def _get_snort_version(self) -> str:
        """
        Get the installed Snort version.
        
        Returns:
            str: Snort version string or "Unknown"
        """
        try:
            result = subprocess.run([self.snort_bin, '-V'], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True,
                                   timeout=5)
            if result.returncode == 0:
                # Extract version from output
                match = re.search(r'Snort (\d+\.\d+\.\d+(\.\d+)?)', result.stdout)
                if match:
                    return match.group(1)
                return result.stdout.strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return "Unknown"
    
    def _count_rules(self) -> int:
        """
        Count the number of Snort rules.
        
        Returns:
            int: Number of rules found
        """
        rule_count = 0
        
        if not os.path.exists(self.snort_rules_dir):
            return 0
            
        for filename in os.listdir(self.snort_rules_dir):
            if filename.endswith('.rules'):
                file_path = os.path.join(self.snort_rules_dir, filename)
                try:
                    with open(file_path, 'r') as f:
                        for line in f:
                            # Count non-commented rule lines
                            if ('alert' in line or 'drop' in line) and not line.strip().startswith('#'):
                                rule_count += 1
                except Exception:
                    pass
                    
        return rule_count
    
    def _is_snort_running(self) -> bool:
        """
        Check if Snort is currently running.
        
        Returns:
            bool: True if Snort is running, False otherwise
        """
        if self.system == "Windows":
            # Use tasklist on Windows
            try:
                result = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq snort.exe'], 
                                       stdout=subprocess.PIPE, 
                                       text=True)
                return "snort.exe" in result.stdout
            except (subprocess.SubprocessError, FileNotFoundError):
                return False
        else:
            # Use pgrep on Unix-like systems
            try:
                result = subprocess.run(['pgrep', 'snort'], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE)
                return result.returncode == 0
            except (subprocess.SubprocessError, FileNotFoundError):
                return False
    
    def _verify_config(self) -> Tuple[bool, str]:
        """
        Verify Snort configuration syntax.
        
        Returns:
            tuple: (is_valid, error_message)
        """
        try:
            result = subprocess.run([self.snort_bin, '-T', '-c', self.snort_conf], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True,
                                   timeout=10)
            if result.returncode == 0:
                return True, ""
            else:
                return False, result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "Config verification timed out"
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            return False, str(e)
    
    # ==== Simplified Rule Management Functions ====
    
    def _manage_rules(self):
        """
        Simplified interface for managing Snort rules.
        """
        while True:
            print("\n" + "=" * 50)
            print("           SNORT RULE MANAGEMENT")
            print("=" * 50)
            
            print("\nRule Management Options:")
            print("1. Enable/Disable Rule Categories")
            print("2. Add Custom Rule")
            print("3. View & Remove Rules")
            print("4. Download Community Rules")
            print("5. Apply Rule Changes")
            print("0. Back to Main Menu")
            
            choice = input("Heimdell(Select an option) #> ").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                self._toggle_rule_categories()
            elif choice == '2':
                self._add_custom_rule()
            elif choice == '3':
                self._view_and_remove_rules()
            elif choice == '4':
                self._download_rule_templates()
            elif choice == '5':
                if self._verify_and_apply_rules():
                    print("Rules verified and applied successfully!")
                else:
                    print("Failed to apply rules. See errors above.")
            else:
                print("Invalid option. Please try again.")
    
    def _toggle_rule_categories(self):
        """
        Simplified interface to enable or disable rule categories.
        """
        categories = list(self.rule_templates.keys())
        
        while True:
            print("\nRule Categories:")
            print("-" * 50)
            
            # Display categories with status
            for i, category in enumerate(categories, 1):
                template = self.rule_templates[category]
                status = "✓ Enabled" if template['enabled'] else "✗ Disabled"
                print(f"{i}. {template['name']} [{status}]")
            
            print("\n0. Back")
            choice = input("Heimdell(Select category to toggle, or 0 to return) #> ").strip()
            
            if choice == '0':
                break
                
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(categories):
                    category = categories[idx]
                    # Toggle the enabled status
                    self.rule_templates[category]['enabled'] = not self.rule_templates[category]['enabled']
                    status = "enabled" if self.rule_templates[category]['enabled'] else "disabled"
                    print(f"\n✓ {self.rule_templates[category]['name']} is now {status}")
                else:
                    print("\nInvalid selection. Please try again.")
            except ValueError:
                print("\nPlease enter a number.")
    
    def _add_custom_rule(self):
        """
        Simplified interface to add a custom rule.
        """
        print("\n" + "=" * 50)
        print("           ADD CUSTOM SNORT RULE")
        print("=" * 50)
        
        print("\nEnter your custom rule below. Format example:")
        print("alert tcp any any -> any any (msg:\"Test Rule\"; sid:1000001; rev:1;)")
        print("\nType 'cancel' to abort, or 'help' for more information.")
        
        while True:
            rule = input("\nHemdell(Custom rule) #> ").strip()
            
            if rule.lower() == 'cancel':
                print("Cancelled adding rule.")
                return
                
            if rule.lower() == 'help':
                self._show_rule_help()
                continue
                
            if not rule.startswith(('alert', 'log', 'pass', 'drop', 'reject', 'sdrop')):
                print("Invalid rule format. Rule must start with an action (alert, log, etc.)")
                print("Try again or type 'help' for more information.")
                continue
                
            # Ensure custom rules file exists
            custom_rules_file = os.path.join(self.snort_rules_dir, 'custom.rules')
            os.makedirs(os.path.dirname(custom_rules_file), exist_ok=True)
            
            # Write the rule
            try:
                with open(custom_rules_file, 'a+') as f:
                    # Add newline if file isn't empty and doesn't end with one
                    f.seek(0, os.SEEK_END)
                    if f.tell() > 0:
                        f.seek(f.tell() - 1, os.SEEK_SET)
                        if f.read(1) != '\n':
                            f.write('\n')
                    
                    f.write(rule + '\n')
                    
                # Enable custom rules category
                self.rule_templates['custom']['enabled'] = True
                
                print("\n✓ Custom rule added successfully!")
                print("The custom rules category has been enabled.")
                
                another = input("\nHemdell(Add another rule? [y/n]) #> ").strip().lower()
                if another != 'y':
                    break
                    
            except Exception as e:
                print(f"\nError adding custom rule: {e}")
                return
    
    def _show_rule_help(self):
        """Display help information for creating Snort rules."""
        print("\n" + "=" * 60)
        print("                SNORT RULE SYNTAX HELP")
        print("=" * 60)
        print("\nBasic Format:")
        print("action protocol source_ip source_port direction dest_ip dest_port (options)")
        
        print("\nActions:")
        print("- alert: Generate an alert and log the packet")
        print("- log: Log the packet")
        print("- pass: Ignore the packet")
        print("- drop: Block and log the packet")
        print("- reject: Block the packet, log it, and send a TCP reset")
        
        print("\nProtocols:")
        print("- tcp, udp, icmp, ip")
        
        print("\nDirection:")
        print("- ->: Source to destination")
        print("- <>: Bidirectional")
        
        print("\nCommon Options:")
        print("- msg: Message to include in the alert")
        print("- sid: Signature ID (must be unique)")
        print("- rev: Revision number")
        print("- content: Pattern to match in the packet payload")
        print("- reference: Reference URL for the alert")
        
        print("\nExample Rules:")
        print('alert tcp any any -> any 80 (msg:"Web Traffic"; sid:1000001; rev:1;)')
        print('alert icmp any any -> $HOME_NET any (msg:"ICMP Ping"; itype:8; sid:1000002; rev:1;)')
        
        print("\nPress Enter to continue...")
        input()
    
    def _view_and_remove_rules(self):
        """
        Simplified interface to view and remove rules.
        """
        print("\n" + "=" * 50)
        print("           VIEW AND REMOVE RULES")
        print("=" * 50)
        
        # Get all rule files
        rule_files = []
        if os.path.exists(self.snort_rules_dir):
            rule_files = [f for f in os.listdir(self.snort_rules_dir) if f.endswith('.rules')]
        
        if not rule_files:
            print("\nNo rule files found in rules directory.")
            return
        
        # Show rule files
        print("\nAvailable Rule Files:")
        for i, file in enumerate(rule_files, 1):
            print(f"{i}. {file}")
        
        print("\n0. Back")
        file_choice = input("Heimdell(Select rule file to view, or 0 to return) #> ").strip()
        
        if file_choice == '0':
            return
            
        try:
            file_idx = int(file_choice) - 1
            if 0 <= file_idx < len(rule_files):
                selected_file = rule_files[file_idx]
                self._view_and_remove_rules_from_file(selected_file)
            else:
                print("\nInvalid selection. Please try again.")
        except ValueError:
            print("\nPlease enter a number.")
    
    def _view_and_remove_rules_from_file(self, rule_file):
        """
        View and remove rules from a specific file.
        
        Args:
            rule_file: Name of the rule file
        """
        file_path = os.path.join(self.snort_rules_dir, rule_file)
        
        if not os.path.exists(file_path):
            print(f"\nRule file not found: {file_path}")
            return
            
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            # Extract actual rules (non-comment, non-empty lines)
            rules = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#') and any(action in line for action in ['alert', 'log', 'pass', 'drop', 'reject', 'sdrop']):
                    rules.append(line)
            
            if not rules:
                print(f"\nNo active rules found in {rule_file}")
                return
                
            # Show rules with pagination
            page_size = 5
            total_pages = (len(rules) + page_size - 1) // page_size
            current_page = 1
            
            while True:
                start_idx = (current_page - 1) * page_size
                end_idx = min(start_idx + page_size, len(rules))
                
                print(f"\nRules in {rule_file} (Page {current_page}/{total_pages}):")
                print("-" * 70)
                
                for i, rule in enumerate(rules[start_idx:end_idx], start_idx + 1):
                    # Extract message if available
                    msg_match = re.search(r'msg:"([^"]+)"', rule)
                    msg = msg_match.group(1) if msg_match else "No description"
                    
                    # Show truncated rule with message
                    truncated_rule = rule[:50] + "..." if len(rule) > 50 else rule
                    print(f"{i}. [{msg}] {truncated_rule}")
                
                print("\nOptions:")
                print("n: Next page, p: Previous page, v: View full rule, r: Remove rule, 0: Back")
                
                cmd = input("Heimdell(Action) #> ").strip().lower()
                
                if cmd == '0':
                    return
                elif cmd == 'n' and current_page < total_pages:
                    current_page += 1
                elif cmd == 'p' and current_page > 1:
                    current_page -= 1
                elif cmd == 'v':
                    # View full rule
                    rule_num = input("Heimdell(Enter rule number to view) #> ").strip()
                    try:
                        rule_idx = int(rule_num) - 1
                        if 0 <= rule_idx < len(rules):
                            print("\nFull Rule:")
                            print("-" * 70)
                            print(rules[rule_idx])
                            print("-" * 70)
                            input("Press Enter to continue...")
                        else:
                            print("Invalid rule number.")
                    except ValueError:
                        print("Please enter a valid number.")
                elif cmd == 'r':
                    # Remove rule
                    rule_num = input("Heimdell(Enter rule number to remove) #> ").strip()
                    try:
                        rule_idx = int(rule_num) - 1
                        if 0 <= rule_idx < len(rules):
                            # Find and remove the rule from the original file
                            rule_to_remove = rules[rule_idx]
                            with open(file_path, 'w') as f:
                                for line in lines:
                                    if line.strip() != rule_to_remove:
                                        f.write(line)
                            
                            print(f"\n✓ Rule removed successfully.")
                            
                            # Reload the file
                            return self._view_and_remove_rules_from_file(rule_file)
                        else:
                            print("Invalid rule number.")
                    except ValueError:
                        print("Please enter a valid number.")
                else:
                    print("Invalid command.")
        except Exception as e:
            print(f"Error processing rules file: {e}")
    
    def _download_rule_templates(self):
        """
        Simplified interface to download and install rule templates.
        """
        print("\n" + "=" * 50)
        print("           DOWNLOAD RULE TEMPLATES")
        print("=" * 50)
        
        print("\nAvailable Rule Templates:")
        print("1. Emerging Threats Open (Free)")
        print("2. Snort VRT Rules (Requires subscription)")
        print("3. Simple Template Rules (Basic protection)")
        print("0. Back")
        
        choice = input("Heimdell(Select option) #> ").strip()
        
        if choice == '0':
            return
        elif choice == '1':
            self._download_et_rules()
        elif choice == '2':
            self._download_vrt_rules()
        elif choice == '3':
            self._create_basic_templates()
        else:
            print("Invalid option. Please try again.")
    
    def _download_et_rules(self):
        """Download and install Emerging Threats rules."""
        print("\nDownloading Emerging Threats Open rules...")
        
        try:
            import tempfile
            import tarfile
            import urllib.request
            
            url = "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz"
            
            # Create a temporary file for the download
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_path = temp_file.name
            
            # Download the file with progress
            print("Downloading rules...")
            urllib.request.urlretrieve(url, temp_path)
            
            print("Download complete. Extracting rules...")
            
            # Create rules directory if it doesn't exist
            os.makedirs(self.snort_rules_dir, exist_ok=True)
            
            # Extract the tarball
            with tarfile.open(temp_path, 'r:gz') as tar:
                # Create a list of rule files
                rule_files = [f for f in tar.getnames() if f.endswith('.rules')]
                
                # Extract only the rule files
                for rule_file in rule_files:
                    file_obj = tar.extractfile(rule_file)
                    if file_obj:
                        content = file_obj.read()
                        
                        # Write to the rules directory
                        output_path = os.path.join(self.snort_rules_dir, os.path.basename(rule_file))
                        with open(output_path, 'wb') as out_file:
                            out_file.write(content)
                            
                        print(f"Extracted: {os.path.basename(rule_file)}")
            
            # Clean up
            os.unlink(temp_path)
            
            # Update rule template configuration
            for rule_file in rule_files:
                base_name = os.path.basename(rule_file)
                category = os.path.splitext(base_name)[0]
                
                # Add to rule templates if not exists
                if category not in self.rule_templates:
                    self.rule_templates[category] = {
                        'name': category.replace('_', ' ').title(),
                        'description': f'Emerging Threats {category} rules',
                        'filename': base_name,
                        'enabled': True
                    }
            
            print("\n✓ Emerging Threats rules installed successfully!")
            return True
            
        except Exception as e:
            print(f"Error downloading rules: {e}")
            return False
    
    def _download_vrt_rules(self):
        """Download and install Snort VRT rules."""
        print("\nSnort VRT Rules require a subscription and Oinkcode.")
        print("You can get an Oinkcode by registering at https://www.snort.org/users/sign_up")
        
        oinkcode = input("Heimdell(Enter your Oinkcode or 'cancel') #> ").strip()
        
        if oinkcode.lower() == 'cancel':
            return False
            
        try:
            import tempfile
            import tarfile
            import urllib.request
            
            url = f"https://www.snort.org/rules/snortrules-snapshot-29200.tar.gz?oinkcode={oinkcode}"
            
            # Create a temporary file for the download
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_path = temp_file.name
            
            # Download the file
            print("Downloading VRT rules...")
            urllib.request.urlretrieve(url, temp_path)
            
            print("Download complete. Extracting rules...")
            
            # Create rules directory if it doesn't exist
            os.makedirs(self.snort_rules_dir, exist_ok=True)
            
            # Extract the tarball
            with tarfile.open(temp_path, 'r:gz') as tar:
                # Create a list of rule files
                rule_files = [f for f in tar.getnames() if f.endswith('.rules')]
                
                if not rule_files:
                    print("No rule files found in the download. Your Oinkcode may be invalid.")
                    os.unlink(temp_path)
                    return False
                
                # Extract only the rule files
                for rule_file in rule_files:
                    file_obj = tar.extractfile(rule_file)
                    if file_obj:
                        content = file_obj.read()
                        
                        # Write to the rules directory
                        output_path = os.path.join(self.snort_rules_dir, os.path.basename(rule_file))
                        with open(output_path, 'wb') as out_file:
                            out_file.write(content)
                            
                        print(f"Extracted: {os.path.basename(rule_file)}")
            
            # Clean up
            os.unlink(temp_path)
            
            print("\n✓ VRT rules installed successfully!")
            return True
            
        except Exception as e:
            print(f"Error downloading VRT rules: {e}")
            return False
    
    def _create_basic_templates(self):
        """Create basic rule templates for common threats."""
        print("\nCreating basic rule templates...")
        
        # Make sure rules directory exists
        os.makedirs(self.snort_rules_dir, exist_ok=True)
        
        # Define basic templates
        templates = {
            'dos.rules': [
                '# Basic DoS detection rules',
                'alert tcp any any -> $HOME_NET any (msg:"Possible SYN flood"; flow:stateless; flags:S; threshold:type threshold, track by_dst, count 100, seconds 5; sid:1000001; rev:1;)',
                'alert icmp any any -> $HOME_NET any (msg:"ICMP flood"; threshold:type threshold, track by_dst, count 100, seconds 5; sid:1000002; rev:1;)'
            ],
            'scan.rules': [
                '# Basic port scan detection rules',
                'alert tcp any any -> $HOME_NET any (msg:"Port scanning"; detection_filter:track by_src, count 30, seconds 60; sid:1000101; rev:1;)'
            ],
            'web-attacks.rules': [
                '# Basic web attack detection rules',
                'alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt"; content:"SELECT"; nocase; content:"FROM"; nocase; pcre:"/SELECT.+FROM/i"; sid:1000201; rev:1;)',
                'alert tcp any any -> $HOME_NET 80 (msg:"XSS Attempt"; content:"<script>"; nocase; sid:1000202; rev:1;)',
                'alert tcp any any -> $HOME_NET 80 (msg:"Directory Traversal Attempt"; content:"../"; sid:1000203; rev:1;)'
            ],
            'malware.rules': [
                '# Basic malware detection rules',
                'alert tcp any any -> $HOME_NET any (msg:"Potential malware communication"; content:"bot"; nocase; content:"command"; nocase; sid:1000301; rev:1;)'
            ],
            'custom.rules': [
                '# Custom rules',
                '# Add your custom rules below'
            ]
        }
        
        # Write template files
        for filename, rules in templates.items():
            file_path = os.path.join(self.snort_rules_dir, filename)
            
            # Don't overwrite existing files
            if os.path.exists(file_path):
                print(f"Skipping existing file: {filename}")
                continue
                
            try:
                with open(file_path, 'w') as f:
                    for rule in rules:
                        f.write(rule + '\n')
                        
                print(f"Created: {filename}")
            except Exception as e:
                print(f"Error creating {filename}: {e}")
        
        print("\n✓ Basic rule templates created successfully!")
        
        # Enable rule templates
        for category in templates.keys():
            category_name = os.path.splitext(category)[0]
            if category_name in self.rule_templates:
                self.rule_templates[category_name]['enabled'] = True
        
        return True
    
    def _verify_and_apply_rules(self):
        """
        Verify and apply rule changes.
        
        Returns:
            bool: True if successful, False otherwise
        """
        print("\nVerifying and applying rule changes...")
        
        # Update snort.conf with enabled rule files
        if not self._update_config_with_rules():
            return False
            
        # Verify configuration
        valid, error = self._verify_config()
        if not valid:
            print(f"Configuration error: {error}")
            return False
            
        print("\n✓ Rules verified successfully.")
        
        # Check if Snort is running
        if self._is_snort_running():
            print("\nSnort is currently running and needs to be restarted to apply changes.")
            restart = input("Heimdell(Restart Snort now? [y/n]) #> ").strip().lower()
            
            if restart == 'y':
                print("Restarting Snort...")
                self._stop_snort()
                time.sleep(2)  # Give it time to stop
                
                interface = input("Heimdell(Enter network interface to monitor (leave blank for 'any')) #> ").strip() or "any"
                if self._start_snort(interface):
                    print("\n✓ Snort restarted successfully with new rules.")
                    return True
                else:
                    print("\n✗ Failed to restart Snort. Please check logs.")
                    return False
            else:
                print("Please restart Snort manually to apply the changes.")
                return True
        else:
            print("\n✓ Rule changes applied. Start Snort to begin monitoring.")
            return True
    
    def _update_config_with_rules(self):
        """
        Update the Snort configuration file with enabled rule files.
        
        Returns:
            bool: True if successful, False otherwise
        """
        if not os.path.exists(self.snort_conf):
            print(f"Snort configuration file not found: {self.snort_conf}")
            return False
            
        try:
            # Read the current config
            with open(self.snort_conf, 'r') as f:
                config_lines = f.readlines()
            
            # Find the rules section in the config
            rules_section_start = None
            rules_section_end = None
            
            for i, line in enumerate(config_lines):
                if "Step #6: Configure output plugins" in line:
                    rules_section_end = i
                    break
                    
                if "Step #5: Configure rule files" in line:
                    rules_section_start = i
            
            if rules_section_start is None or rules_section_end is None:
                print("Could not locate rules section in Snort configuration file.")
                return False
            
            # Keep the config parts before and after the rules section
            config_before = config_lines[:rules_section_start + 1]
            config_after = config_lines[rules_section_end:]
            
            # Generate new rules section
            new_rules_section = []
            for category, template in self.rule_templates.items():
                if template['enabled']:
                    rule_file = os.path.join(self.snort_rules_dir, template['filename'])
                    if os.path.exists(rule_file):
                        rule_path = rule_file.replace('\\', '/')  # Normalize path for Snort
                        new_rules_section.append(f'include {rule_path}\n')
            
            # Combine the config parts
            new_config = config_before + new_rules_section + config_after
            
            # Write the new config
            with open(self.snort_conf, 'w') as f:
                f.writelines(new_config)
                
            print("Snort configuration updated with enabled rule files.")
            return True
            
        except Exception as e:
            print(f"Error updating Snort configuration: {e}")
            return False
    
    def _manage_snort_service(self):
        """Manage the Snort service (start/stop)."""
        is_running = self._is_snort_running()
        status = "running" if is_running else "stopped"
        
        print(f"\nSnort service is currently {status}.")
        
        if is_running:
            choice = input("Heimdell(Stop Snort service? [y/n]) #> ").strip().lower()
            if choice == 'y':
                print("Stopping Snort service...")
                self._stop_snort()
                if not self._is_snort_running():
                    print("Snort service stopped successfully.")
                else:
                    print("Failed to stop Snort service.")
        else:
            choice = input("Heimdell(Start Snort service? [y/n]) #> ").strip().lower()
            if choice == 'y':
                print("Starting Snort service...")
                interface = input("Heimdell(Enter network interface to monitor (leave blank for 'any')) #> ").strip() or "any"
                
                if self._start_snort(interface):
                    print("Snort service started successfully.")
                else:
                    print("Failed to start Snort service.")

    def _start_snort(self, interface="any"):
        """
        Start the Snort IDS service.
        
        Args:
            interface: Network interface to monitor
            
        Returns:
            bool: True if started successfully, False otherwise
        """
        try:
            # Build the command based on system
            if self.system == "Windows":
                # Windows often needs to run as admin
                cmd = [
                    self.snort_bin,
                    "-c", self.snort_conf,
                    "-i", interface,
                    "-A", "console",  # Alert mode
                    "-l", self.snort_log_dir
                ]
                
                # Use subprocess.DETACHED_PROCESS on Windows to run in background
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.DETACHED_PROCESS
                )
            else:
                # Unix-like systems can use nohup to run in background
                cmd = [
                    "sudo", "nohup",
                    self.snort_bin,
                    "-c", self.snort_conf,
                    "-i", interface,
                    "-D",  # Daemon mode
                    "-A", "fast",  # Fast alert output
                    "-l", self.snort_log_dir,
                    "&"
                ]
                
                # For Unix, we need shell=True to use & at the end
                subprocess.Popen(" ".join(cmd), shell=True)
            
            # Wait a moment for process to start
            time.sleep(2)
            return self._is_snort_running()
            
        except Exception as e:
            print(f"Error starting Snort: {e}")
            return False
    
    def _stop_snort(self):
        """Stop the Snort process."""
        if self.system == "Windows":
            try:
                subprocess.run(["taskkill", "/F", "/IM", "snort.exe"], 
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
                return True
            except subprocess.CalledProcessError as e:
                print(f"Error stopping Snort: {e}")
                return False
        else:
            try:
                subprocess.run(["sudo", "killall", "snort"], 
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
                return True
            except subprocess.CalledProcessError as e:
                print(f"Error stopping Snort: {e}")
                return False
    
    def _load_position(self):
        """Load the last position in the alert file that was read."""
        try:
            if os.path.exists(self.position_file):
                with open(self.position_file, 'r') as f:
                    self.last_position = int(f.read().strip())
        except Exception:
            self.last_position = 0
    
    def _save_position(self, position):
        """
        Save the current position in the alert file.
        
        Args:
            position: Position in the alert file to save
        """
        try:
            with open(self.position_file, 'w') as f:
                f.write(str(position))
        except Exception as e:
            print(f"Error saving position: {e}")
    
    def monitor_alerts(self, live=True):
        """
        Monitor Snort alerts.
        
        Args:
            live: Whether to monitor live (continuous) or just show recent alerts
        """
        if not os.path.exists(self.alert_file):
            print(f"Alert file not found: {self.alert_file}")
            print("Make sure Snort is configured and has been run at least once.")
            return
        
        print("\nSnort Alert Monitor")
        print("-" * 40)
        
        if live:
            print("Monitoring alerts in real-time. Press Ctrl+C to stop.")
            print("-" * 40)
            try:
                while True:
                    self._check_alerts()
                    time.sleep(1)  # Check every second
            except KeyboardInterrupt:
                print("\nStopped monitoring alerts.")
        else:
            # Just show recent alerts once
            self._check_alerts()
    
    def _check_alerts(self):
        """Check for new alerts in the alert file."""
        try:
            # Get file size
            file_size = os.path.getsize(self.alert_file)
            
            # If file size is smaller than last position, file was probably rotated
            if file_size < self.last_position:
                self.last_position = 0
            
            # If no new data, return
            if file_size <= self.last_position:
                return
            
            # Open and read new data
            with open(self.alert_file, 'r') as f:
                f.seek(self.last_position)
                new_alerts = f.read()
            
            # Process and display alerts
            if new_alerts:
                self._process_alerts(new_alerts)
            
            # Update position
            self.last_position = file_size
            self._save_position(file_size)
            
        except Exception as e:
            print(f"Error checking alerts: {e}")
    
    def _process_alerts(self, alerts_text):
        """
        Process and display alert text.
        
        Args:
            alerts_text: Text containing alerts to process
        """
        # Split into individual alerts (assuming they're separated by blank lines)
        alerts = alerts_text.split('\n\n')
        
        for alert in alerts:
            if not alert.strip():
                continue
                
            # Simple parsing - extract basic info
            lines = alert.strip().split('\n')
            if not lines:
                continue
                
            # Display the alert with timestamp
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"\n[{timestamp}] NEW ALERT:")
            print("-" * 60)
            print(alert)
            print("-" * 60)
            
            # Here you would normally send this alert to Heimdell's central system
            # self._send_alert_to_heimdell(alert)