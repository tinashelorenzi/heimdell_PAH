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
import asyncio
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
            try:
                # Try to run snort -V to check version
                result = subprocess.run([self.snort_bin, '-V'], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE,
                                       text=True,
                                       timeout=5)
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
                            if 'alert' in line and not line.strip().startswith('#'):
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
    
    # ==== Rule Configuration Functions ====
    
    def configure_rules(self) -> bool:
        """
        Interactive configuration for Snort rules.
        
        Returns:
            bool: True if configuration was successful, False otherwise
        """
        if not self._is_snort_installed():
            print("Snort is not installed. Please install Snort first.")
            return False
            
        print("\n" + "=" * 60)
        print("             HEIMDELL - SNORT RULE CONFIGURATION")
        print("=" * 60)
        print("        \"Guardian of the network, detector of intruders\"")
        print("-" * 60)
        
        # Load current rule configurations
        self._load_rule_config()
        
        while True:
            self._print_rule_menu()
            choice = input("Heimdell(Select an option) #> ").strip()
            
            if choice == '0':
                print("Saving rule configuration...")
                self._save_rule_config()
                return True
                
            elif choice == '1':
                self._toggle_rule_sets()
                
            elif choice == '2':
                self._manage_custom_rules()
                
            elif choice == '3':
                self._download_community_rules()
                
            elif choice == '4':
                if self._verify_and_apply_rules():
                    print("Rules verified and applied successfully!")
                else:
                    print("Failed to apply rules. See errors above.")
                    
            elif choice == '5':
                self._show_rule_statistics()
                
            else:
                print("Invalid option. Please try again.")
    
    def _print_rule_menu(self):
        """Print the rule configuration menu."""
        print("\nSnort Rule Configuration Options:")
        print("1. Enable/Disable Rule Categories")
        print("2. Manage Custom Rules")
        print("3. Download Community Rules")
        print("4. Verify and Apply Rules")
        print("5. Show Rule Statistics")
        print("0. Save and Exit")
        print("")
    
    def _load_rule_config(self):
        """Load rule configuration from config file."""
        # Check if rule configuration exists in the config
        if 'rule_templates' in self.config:
            for key, value in self.config['rule_templates'].items():
                if key in self.rule_templates:
                    self.rule_templates[key].update(value)
    
    def _save_rule_config(self):
        """Save rule configuration to config file."""
        # Update the config with current rule template settings
        if 'rule_templates' not in self.config:
            self.config['rule_templates'] = {}
            
        # Only save essential attributes
        for key, template in self.rule_templates.items():
            self.config['rule_templates'][key] = {
                'enabled': template['enabled'],
                'filename': template['filename']
            }
    
    def _toggle_rule_sets(self):
        """Enable or disable rule categories."""
        while True:
            print("\nRule Categories:")
            
            # Print numbered list of rule categories
            categories = list(self.rule_templates.keys())
            for i, category in enumerate(categories, 1):
                template = self.rule_templates[category]
                status = "Enabled" if template['enabled'] else "Disabled"
                print(f"{i}. {template['name']} [{status}]")
                print(f"   Description: {template['description']}")
                
            print("\n0. Back to main menu")
            
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
                    print(f"{self.rule_templates[category]['name']} is now {status}")
                else:
                    print("Invalid selection. Please try again.")
            except ValueError:
                print("Please enter a number.")
    
    def _manage_custom_rules(self):
        """Manage custom Snort rules."""
        print("\nCustom Rules Management:")
        print("1. View custom rules")
        print("2. Add a new custom rule")
        print("3. Remove a custom rule")
        print("0. Back to main menu")
        
        choice = input("Heimdell(Select an option) #> ").strip()
        
        if choice == '0':
            return
            
        elif choice == '1':
            self._view_custom_rules()
            
        elif choice == '2':
            self._add_custom_rule()
            
        elif choice == '3':
            self._remove_custom_rule()
            
        else:
            print("Invalid option. Please try again.")
    
    def _view_custom_rules(self):
        """View existing custom rules."""
        custom_rules_file = os.path.join(self.snort_rules_dir, self.rule_templates['custom']['filename'])
        
        if not os.path.exists(custom_rules_file):
            print("No custom rules file found.")
            return
            
        try:
            with open(custom_rules_file, 'r') as f:
                rules = f.readlines()
                
            if not rules:
                print("No custom rules defined.")
                return
                
            print("\nCustom Rules:")
            for i, rule in enumerate(rules, 1):
                rule = rule.strip()
                if rule and not rule.startswith('#'):
                    print(f"{i}. {rule}")
            
            print("")
        except Exception as e:
            print(f"Error reading custom rules: {e}")
    
    def _add_custom_rule(self):
        """Add a new custom rule."""
        print("\nAdd a new custom Snort rule.")
        print("Example format: alert tcp any any -> any any (msg:\"Test Rule\"; sid:1000001; rev:1;)")
        print("Enter the rule below or type 'cancel' to abort:")
        
        rule = input("Heimdell(New rule) #> ").strip()
        
        if rule.lower() == 'cancel':
            print("Cancelled adding rule.")
            return
            
        if not rule.startswith(('alert', 'log', 'pass', 'drop', 'reject', 'sdrop')):
            print("Invalid rule format. Rule must start with an action (alert, log, etc.)")
            return
            
        # Ensure custom rules directory exists
        custom_rules_file = os.path.join(self.snort_rules_dir, self.rule_templates['custom']['filename'])
        os.makedirs(os.path.dirname(custom_rules_file), exist_ok=True)
        
        # Append the rule to the custom rules file
        try:
            with open(custom_rules_file, 'a+') as f:
                # Add newline if file isn't empty and doesn't end with one
                f.seek(0, os.SEEK_END)
                if f.tell() > 0:
                    f.seek(f.tell() - 1, os.SEEK_SET)
                    if f.read(1) != '\n':
                        f.write('\n')
                
                f.write(rule + '\n')
                
            print("Custom rule added successfully.")
            # Enable custom rules if they're disabled
            if not self.rule_templates['custom']['enabled']:
                self.rule_templates['custom']['enabled'] = True
                print("Custom rules category has been enabled.")
                
        except Exception as e:
            print(f"Error adding custom rule: {e}")
    
    def _remove_custom_rule(self):
        """Remove a custom rule."""
        custom_rules_file = os.path.join(self.snort_rules_dir, self.rule_templates['custom']['filename'])
        
        if not os.path.exists(custom_rules_file):
            print("No custom rules file found.")
            return
            
        try:
            with open(custom_rules_file, 'r') as f:
                rules = f.readlines()
                
            # Filter out comments and empty lines
            active_rules = [rule.strip() for rule in rules if rule.strip() and not rule.strip().startswith('#')]
            
            if not active_rules:
                print("No custom rules to remove.")
                return
                
            print("\nSelect a rule to remove:")
            for i, rule in enumerate(active_rules, 1):
                print(f"{i}. {rule}")
                
            print("0. Cancel")
            
            choice = input("Heimdell(Select rule to remove) #> ").strip()
            
            if choice == '0':
                print("Cancelled removing rule.")
                return
                
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(active_rules):
                    rule_to_remove = active_rules[idx]
                    
                    # Create new rule file without the selected rule
                    with open(custom_rules_file, 'w') as f:
                        for rule in rules:
                            if rule.strip() != rule_to_remove:
                                f.write(rule)
                                
                    print("Rule removed successfully.")
                else:
                    print("Invalid selection. Please try again.")
            except ValueError:
                print("Please enter a number.")
                
        except Exception as e:
            print(f"Error removing custom rule: {e}")
    
    def _download_community_rules(self):
        """Download and install community rules."""
        print("\nDownload Community Rules:")
        print("1. Snort VRT rules (requires subscription)")
        print("2. Emerging Threats Open rules (free)")
        print("0. Back to main menu")
        
        choice = input("Heimdell(Select rule source) #> ").strip()
        
        if choice == '0':
            return
            
        elif choice == '1':
            print("\nTo download Snort VRT rules, you need a Snort.org account and Oinkcode.")
            print("Get an Oinkcode at: https://www.snort.org/users/sign_up")
            
            oinkcode = input("Heimdell(Enter your Oinkcode or 'cancel') #> ").strip()
            
            if oinkcode.lower() == 'cancel':
                return
                
            url = f"https://www.snort.org/rules/snortrules-snapshot-29200.tar.gz?oinkcode={oinkcode}"
            self._download_and_extract_rules(url)
            
        elif choice == '2':
            url = "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz"
            self._download_and_extract_rules(url)
            
        else:
            print("Invalid option. Please try again.")
    
    def _download_and_extract_rules(self, url):
        """
        Download and extract rules from a URL.
        
        Args:
            url: URL to download rules from
        """
        try:
            import tempfile
            import tarfile
            import urllib.request
            
            print(f"Downloading rules from {url}...")
            
            # Create a temporary file for the download
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_path = temp_file.name
                
            # Download the file
            urllib.request.urlretrieve(url, temp_path)
            
            print("Download complete. Extracting rules...")
            
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
            
            print("Rules downloaded and extracted successfully!")
            return True
            
        except Exception as e:
            print(f"Error downloading or extracting rules: {e}")
            return False
    
    def _verify_and_apply_rules(self):
        """
        Verify and apply the Snort rules configuration.
        
        Returns:
            bool: True if successful, False otherwise
        """
        # First, update the snort.conf to include the correct rule files
        if not self._update_config_with_rules():
            return False
            
        # Verify the configuration
        valid, error = self._verify_config()
        if not valid:
            print(f"Configuration error: {error}")
            return False
            
        print("Rules verified successfully.")
        
        # If Snort is running, suggest restarting it
        if self._is_snort_running():
            print("\nSnort is currently running. You need to restart it to apply changes.")
            restart = input("Heimdell(Restart Snort now? [y/n]) #> ").strip().lower()
            
            if restart == 'y':
                return self._restart_snort()
            else:
                print("Please restart Snort manually to apply the changes.")
    
    def _restart_snort(self) -> bool:
        """
        Restart the Snort process.
    
        Returns:
            bool: True if restart was successful, False otherwise
        """
        try:
            # Stop Snort if it's running
            if self._is_snort_running():
                self._stop_snort()
    
            # Start Snort
            print("Starting Snort...")
            result = subprocess.run([self.snort_bin, "-c", self.snort_conf, "-i", "any"], 
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
    
            if result.returncode == 0:
                print("Snort started successfully.")
                return True
            else:
                print(f"Error starting Snort: {result.stderr.decode()}")
                return False
    
        except Exception as e:
            print(f"Error restarting Snort: {e}")
            return False
    
    def _stop_snort(self):
        """Stop the Snort process."""
        if self.system == "Windows":
            try:
                subprocess.run(["taskkill", "/F", "/IM", "snort.exe"], capture_output=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error stopping Snort: {e.stderr.decode()}")
        else:
            try:
                subprocess.run(["killall", "snort"], capture_output=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error stopping Snort: {e.stderr.decode()}")