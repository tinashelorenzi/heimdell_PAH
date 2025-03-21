#!/usr/bin/env python3
"""
Heimdell System Monitoring Module

This module provides functionality to:
1. Monitor system resources (CPU, memory, disk usage)
2. Track running processes and detect suspicious activity
3. Scan for malware using ClamAV
4. Check for rootkits using chkrootkit
5. Monitor file integrity of critical system files
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
import psutil
from datetime import datetime
import hashlib
import logging
from typing import Dict, Any, List, Tuple, Optional, Union
import csv
import tempfile

class SystemModule:
    """
    Heimdell module for system monitoring, malware scanning, and rootkit detection.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the System Monitoring module.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Set default paths and configurations
        self.system = platform.system()
        self.monitored_processes = self.config.get('monitored_processes', [
            'sshd', 'apache2', 'nginx', 'mysql', 'postgresql'
        ])
        
        # Set tool paths based on system
        if self.system == "Linux":
            self.clamav_bin = self.config.get('clamav_bin', '/usr/bin/clamscan')
            self.chkrootkit_bin = self.config.get('chkrootkit_bin', '/usr/sbin/chkrootkit')
            self.logs_dir = self.config.get('logs_dir', '/var/log/heimdell/system')
        elif self.system == "Darwin":  # macOS
            self.clamav_bin = self.config.get('clamav_bin', '/usr/local/bin/clamscan')
            self.chkrootkit_bin = self.config.get('chkrootkit_bin', '/usr/local/sbin/chkrootkit')
            self.logs_dir = self.config.get('logs_dir', '/usr/local/var/log/heimdell/system')
        else:  # Windows
            self.clamav_bin = self.config.get('clamav_bin', 'C:\\Program Files\\ClamAV\\clamscan.exe')
            self.chkrootkit_bin = None  # chkrootkit not available for Windows
            self.logs_dir = self.config.get('logs_dir', 'C:\\ProgramData\\Heimdell\\logs\\system')
        
        # File integrity monitoring settings
        self.fim_enabled = self.config.get('fim_enabled', True)
        self.fim_baseline_file = self.config.get('fim_baseline_file', os.path.join(self.logs_dir, 'fim_baseline.json'))
        self.fim_critical_files = self.config.get('fim_critical_files', [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/sudoers',
            '/etc/hosts',
            '/etc/ssh/sshd_config',
            '/etc/fstab'
        ])
        
        # Resource monitoring settings
        self.cpu_threshold = self.config.get('cpu_threshold', 90)  # Alert if CPU usage > 90%
        self.memory_threshold = self.config.get('memory_threshold', 90)  # Alert if memory usage > 90%
        self.disk_threshold = self.config.get('disk_threshold', 90)  # Alert if disk usage > 90%
        
        # Initialize logging
        self._setup_logging()
    
    def _setup_logging(self):
        """Initialize logging for the system module."""
        try:
            # Create logs directory if it doesn't exist
            os.makedirs(self.logs_dir, exist_ok=True)
            
            # Set up logging
            log_file = os.path.join(self.logs_dir, 'system_monitor.log')
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
            
        except Exception as e:
            print(f"Error setting up logging: {e}")
    
    def run(self):
        """
        Main entry point for running the System Monitoring module.
        This function is called when the module is executed through the 'runmodule' command.
        """
        print("\n" + "=" * 60)
        print("         HEIMDELL - SYSTEM MONITORING MODULE")
        print("=" * 60)
        print("     \"Guarding your system, detecting threats\"")
        print("-" * 60)
        
        # Ensure required directories exist
        self._ensure_directories()
        
        # Main module menu
        while True:
            self._print_module_menu()
            choice = input("Heimdell(Select an option) #> ").strip()
            
            if choice == '0':
                print("Exiting System Monitoring module.")
                break
                
            elif choice == '1':
                # Check system health
                self.check_system_health()
                
            elif choice == '2':
                # Scan for malware
                self.scan_for_malware()
                
            elif choice == '3':
                # Check for rootkits
                self.check_for_rootkits()
                
            elif choice == '4':
                # Monitor file integrity
                self.monitor_file_integrity()
                
            elif choice == '5':
                # Process monitoring
                self.monitor_processes()
                
            elif choice == '6':
                # Configure monitoring settings
                self._configure_settings()
                
            else:
                print("Invalid option. Please try again.")
    
    def _ensure_directories(self):
        """Ensure required directories exist."""
        try:
            os.makedirs(self.logs_dir, exist_ok=True)
            print(f"Log directory: {self.logs_dir}")
        except Exception as e:
            print(f"Error ensuring directories: {e}")
            
            # Try with sudo on Unix-like systems if permission denied
            if isinstance(e, PermissionError) and self.system != "Windows":
                try:
                    subprocess.run(["sudo", "mkdir", "-p", self.logs_dir], check=True)
                    subprocess.run(["sudo", "chmod", "755", self.logs_dir], check=True)
                    print(f"Created directory with sudo: {self.logs_dir}")
                except Exception as sudo_e:
                    print(f"Error creating directory with sudo: {sudo_e}")

    def _print_module_menu(self):
        """Display the main System Monitoring module menu."""
        print("\nSystem Monitoring Options:")
        print("1. Check System Health (CPU, Memory, Disk)")
        print("2. Scan for Malware")
        print("3. Check for Rootkits")
        print("4. Monitor File Integrity")
        print("5. Process Monitoring")
        print("6. Configure Monitoring Settings")
        print("0. Exit Module")
        print("")
    
    # ==== System Health Monitoring ====
    
    def check_system_health(self):
        """Check system health including CPU, memory, and disk usage."""
        print("\n" + "=" * 50)
        print("           SYSTEM HEALTH CHECK")
        print("=" * 50)
        
        # Get CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        print(f"\nCPU Usage: {cpu_percent}%")
        if cpu_percent > self.cpu_threshold:
            print(f"⚠️  WARNING: CPU usage exceeds threshold ({self.cpu_threshold}%)")
        
        # Get memory usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        print(f"Memory Usage: {memory_percent}% (Used: {self._format_bytes(memory.used)} / Total: {self._format_bytes(memory.total)})")
        if memory_percent > self.memory_threshold:
            print(f"⚠️  WARNING: Memory usage exceeds threshold ({self.memory_threshold}%)")
        
        # Get disk usage for each partition
        print("\nDisk Usage:")
        partitions = psutil.disk_partitions()
        for partition in partitions:
            if self.system == "Windows" and "cdrom" in partition.opts or partition.fstype == "":
                # Skip CD-ROM drives on Windows
                continue
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                print(f"  {partition.mountpoint}: {usage.percent}% (Used: {self._format_bytes(usage.used)} / Total: {self._format_bytes(usage.total)})")
                if usage.percent > self.disk_threshold:
                    print(f"  ⚠️  WARNING: Disk usage on {partition.mountpoint} exceeds threshold ({self.disk_threshold}%)")
            except PermissionError:
                print(f"  {partition.mountpoint}: Permission denied")
        
        # Get network information
        print("\nNetwork Interfaces:")
        net_io = psutil.net_io_counters(pernic=True)
        for interface, io_counters in net_io.items():
            print(f"  {interface}: Sent: {self._format_bytes(io_counters.bytes_sent)} / Received: {self._format_bytes(io_counters.bytes_recv)}")
        
        # Get system uptime
        uptime = time.time() - psutil.boot_time()
        days, remainder = divmod(uptime, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        print(f"\nSystem Uptime: {int(days)} days, {int(hours)} hours, {int(minutes)} minutes")
        
        # Save health data to log
        health_data = {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'memory_used': memory.used,
            'memory_total': memory.total,
            'disk_usage': {p.mountpoint: psutil.disk_usage(p.mountpoint)._asdict() 
                          for p in partitions if self.system != "Windows" or ("cdrom" not in p.opts and p.fstype != "")}
        }
        
        self._log_health_data(health_data)
        
        # Ask if user wants to see top processes
        see_processes = input("\nHemdell(View top processes? [y/n]) #> ").strip().lower()
        if see_processes == 'y':
            self.monitor_processes(top_only=True)
    
    def _format_bytes(self, bytes_value):
        """
        Format bytes value to human-readable format.
        
        Args:
            bytes_value: Bytes value to format
            
        Returns:
            str: Formatted bytes value (e.g., "1.23 GB")
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024 or unit == 'TB':
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024
    
    def _log_health_data(self, health_data):
        """
        Log system health data to CSV file.
        
        Args:
            health_data: Dictionary containing system health data
        """
        try:
            # Flatten disk usage for CSV
            disks = []
            for mountpoint, usage in health_data['disk_usage'].items():
                disks.append({
                    'mountpoint': mountpoint,
                    'total': usage['total'],
                    'used': usage['used'],
                    'free': usage['free'],
                    'percent': usage['percent']
                })
            
            # Create logs directory if it doesn't exist
            os.makedirs(self.logs_dir, exist_ok=True)
            
            # Write health data to CSV
            health_log = os.path.join(self.logs_dir, 'system_health.csv')
            file_exists = os.path.isfile(health_log)
            
            with open(health_log, 'a', newline='') as f:
                fieldnames = ['timestamp', 'cpu_percent', 'memory_percent', 'memory_used', 'memory_total']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                
                if not file_exists:
                    writer.writeheader()
                
                # Write the main metrics
                writer.writerow({
                    'timestamp': health_data['timestamp'],
                    'cpu_percent': health_data['cpu_percent'],
                    'memory_percent': health_data['memory_percent'],
                    'memory_used': health_data['memory_used'],
                    'memory_total': health_data['memory_total']
                })
            
            # Write disk data to separate CSV
            disk_log = os.path.join(self.logs_dir, 'disk_usage.csv')
            disk_file_exists = os.path.isfile(disk_log)
            
            with open(disk_log, 'a', newline='') as f:
                fieldnames = ['timestamp', 'mountpoint', 'total', 'used', 'free', 'percent']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                
                if not disk_file_exists:
                    writer.writeheader()
                
                # Write disk metrics
                for disk in disks:
                    writer.writerow({
                        'timestamp': health_data['timestamp'],
                        'mountpoint': disk['mountpoint'],
                        'total': disk['total'],
                        'used': disk['used'],
                        'free': disk['free'],
                        'percent': disk['percent']
                    })
            
            print(f"\nHealth data logged to {health_log}")
            
        except Exception as e:
            print(f"Error logging health data: {e}")
    
    # ==== Malware Scanning ====
    
    def scan_for_malware(self):
        """Scan for malware using ClamAV."""
        print("\n" + "=" * 50)
        print("           MALWARE SCANNING")
        print("=" * 50)
        
        # Check if ClamAV is installed
        if not self._is_clamav_installed():
            print("ClamAV is not installed.")
            install_now = input("Heimdell(Would you like to install ClamAV now? [y/n]) #> ").strip().lower()
            if install_now == 'y':
                if not self._install_clamav():
                    print("ClamAV installation failed. Please install manually and try again.")
                    return
            else:
                print("Skipping malware scan.")
                return
        
        # Get scan path
        print("\nEnter the path to scan (leave blank for current directory):")
        scan_path = input("Heimdell(Path to scan) #> ").strip() or os.getcwd()
        
        if not os.path.exists(scan_path):
            print(f"Error: Path '{scan_path}' does not exist.")
            return
        
        # Configure scan options
        print("\nScan Options:")
        print("1. Quick Scan (Scan common malware locations only)")
        print("2. Full Scan (Scan entire directory)")
        print("3. Custom Scan (Configure scan options)")
        
        scan_type = input("Heimdell(Select scan type) #> ").strip()
        
        # Build scan command based on options
        cmd = [self.clamav_bin]
        
        if scan_type == '1':
            # Quick scan - check only executable files and common malware locations
            cmd.extend(['--scan-exe=yes', '--max-filesize=100M', '--max-scansize=500M'])
        elif scan_type == '2':
            # Full scan - thorough scan of all files
            cmd.extend(['--scan-archive=yes', '--scan-pdf=yes', '--scan-ole2=yes', '--scan-html=yes'])
        elif scan_type == '3':
            # Custom scan - configure options
            print("\nCustom Scan Options:")
            
            scan_archives = input("Heimdell(Scan archives? [y/n]) #> ").strip().lower()
            if scan_archives == 'y':
                cmd.append('--scan-archive=yes')
            
            scan_pdf = input("Heimdell(Scan PDF files? [y/n]) #> ").strip().lower()
            if scan_pdf == 'y':
                cmd.append('--scan-pdf=yes')
            
            scan_ole = input("Heimdell(Scan Office documents? [y/n]) #> ").strip().lower()
            if scan_ole == 'y':
                cmd.append('--scan-ole2=yes')
            
            scan_html = input("Heimdell(Scan HTML files? [y/n]) #> ").strip().lower()
            if scan_html == 'y':
                cmd.append('--scan-html=yes')
            
            recursive = input("Heimdell(Scan recursively? [y/n]) #> ").strip().lower()
            if recursive == 'y':
                cmd.append('-r')
        else:
            print("Invalid option. Using default scan settings.")
        
        # Always add recursive flag for thorough scanning if not already added
        if '-r' not in cmd:
            cmd.append('-r')
        
        # Add output file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(self.logs_dir, f'clamscan_{timestamp}.log')
        
        cmd.extend(['--log=' + output_file, scan_path])
        
        print(f"\nStarting malware scan of {scan_path}...\n")
        print(f"Scan results will be logged to {output_file}")
        print("This may take some time depending on the size of the directory.\n")
        
        try:
            # Run ClamAV
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse and display results
            if process.returncode == 0:
                print("✅ No malware found.")
            elif process.returncode == 1:
                print("⚠️  Malware found! See details below:")
                
                # Parse output to extract infected files
                infected_files = []
                for line in process.stdout.splitlines():
                    if ': ' in line and ('FOUND' in line or 'Infected' in line):
                        infected_files.append(line)
                
                for file in infected_files:
                    print(f"  {file}")
                
                print(f"\nTotal infected files: {len(infected_files)}")
            else:
                print(f"❌ Error during scan: {process.stderr}")
            
            # Show summary
            print("\nScan Summary:")
            for line in process.stdout.splitlines():
                if "Infected files:" in line or "Scanned files:" in line or "Time:" in line:
                    print(f"  {line}")
            
        except Exception as e:
            print(f"Error during malware scan: {e}")
    
    def _is_clamav_installed(self):
        """
        Check if ClamAV is installed.
        
        Returns:
            bool: True if ClamAV is installed, False otherwise
        """
        if not os.path.exists(self.clamav_bin):
            return False
            
        try:
            result = subprocess.run([self.clamav_bin, '--version'], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def _install_clamav(self):
        """
        Install ClamAV.
        
        Returns:
            bool: True if installation was successful, False otherwise
        """
        try:
            if self.system == "Linux":
                # Detect distribution
                if os.path.exists('/etc/debian_version'):
                    # Debian/Ubuntu
                    cmd = "sudo apt-get update && sudo apt-get install -y clamav clamav-freshclam"
                elif os.path.exists('/etc/redhat-release'):
                    # RHEL/CentOS/Fedora
                    cmd = "sudo yum install -y clamav clamav-update"
                elif os.path.exists('/etc/arch-release'):
                    # Arch Linux
                    cmd = "sudo pacman -S clamav"
                else:
                    print("Unsupported Linux distribution. Please install ClamAV manually.")
                    return False
            elif self.system == "Darwin":
                # macOS (using Homebrew)
                cmd = "brew install clamav"
            elif self.system == "Windows":
                print("Automatic installation on Windows is not supported.")
                print("Please download and install ClamAV from: https://www.clamav.net/downloads")
                return False
            else:
                print(f"Unsupported platform: {self.system}")
                return False
            
            print(f"Installing ClamAV with command: {cmd}")
            result = subprocess.run(cmd, shell=True, check=True)
            
            if result.returncode == 0:
                print("ClamAV installed successfully.")
                
                # Update virus database
                print("Updating virus database...")
                if self.system == "Windows":
                    update_cmd = os.path.join(os.path.dirname(self.clamav_bin), 'freshclam.exe')
                else:
                    update_cmd = "sudo freshclam"
                
                subprocess.run(update_cmd, shell=True)
                return True
            else:
                return False
                
        except Exception as e:
            print(f"Error installing ClamAV: {e}")
            return False
    
    # ==== Rootkit Detection ====
    
    def check_for_rootkits(self):
        """Check for rootkits using chkrootkit."""
        print("\n" + "=" * 50)
        print("           ROOTKIT DETECTION")
        print("=" * 50)
        
        if self.system == "Windows":
            print("Rootkit detection with chkrootkit is not available on Windows.")
            print("Consider using Windows Defender or a third-party security solution.")
            return
        
        # Check if chkrootkit is installed
        if not self._is_chkrootkit_installed():
            print("chkrootkit is not installed.")
            install_now = input("Heimdell(Would you like to install chkrootkit now? [y/n]) #> ").strip().lower()
            if install_now == 'y':
                if not self._install_chkrootkit():
                    print("chkrootkit installation failed. Please install manually and try again.")
                    return
            else:
                print("Skipping rootkit check.")
                return
        
        print("\nStarting rootkit scan...")
        print("This may take some time.\n")
        
        try:
            # Create log file with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(self.logs_dir, f'chkrootkit_{timestamp}.log')
            
            # Run chkrootkit with sudo
            cmd = f"sudo {self.chkrootkit_bin} -q"
            process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Save output to log file
            with open(output_file, 'w') as f:
                f.write(process.stdout)
                if process.stderr:
                    f.write("\n--- ERRORS ---\n")
                    f.write(process.stderr)
            
            # Parse and display results
            warnings = []
            for line in process.stdout.splitlines():
                if "INFECTED" in line or "suspicious" in line.lower() or "warning" in line.lower():
                    warnings.append(line)
            
            if warnings:
                print("⚠️  Potential rootkits or suspicious files found:")
                for warning in warnings:
                    print(f"  {warning}")
            else:
                print("✅ No rootkits found.")
            
            print(f"\nRootkit scan results saved to: {output_file}")
            
        except Exception as e:
            print(f"Error during rootkit scan: {e}")
    
    def _is_chkrootkit_installed(self):
        """
        Check if chkrootkit is installed.
        
        Returns:
            bool: True if chkrootkit is installed, False otherwise
        """
        if not self.chkrootkit_bin or not os.path.exists(self.chkrootkit_bin):
            return False
            
        try:
            result = subprocess.run(['sudo', self.chkrootkit_bin, '-V'], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE)
            return result.returncode == 0
        except Exception:
            return False
    
    def _install_chkrootkit(self):
        """
        Install chkrootkit.
        
        Returns:
            bool: True if installation was successful, False otherwise
        """
        try:
            if self.system == "Linux":
                # Detect distribution
                if os.path.exists('/etc/debian_version'):
                    # Debian/Ubuntu
                    cmd = "sudo apt-get update && sudo apt-get install -y chkrootkit"
                elif os.path.exists('/etc/redhat-release'):
                    # RHEL/CentOS/Fedora
                    cmd = "sudo yum install -y chkrootkit"
                elif os.path.exists('/etc/arch-release'):
                    # Arch Linux
                    cmd = "sudo pacman -S chkrootkit"
                else:
                    print("Unsupported Linux distribution. Please install chkrootkit manually.")
                    return False
            elif self.system == "Darwin":
                # macOS (using Homebrew)
                cmd = "brew install chkrootkit"
            else:
                print(f"Unsupported platform: {self.system}")
                return False
            
            print(f"Installing chkrootkit with command: {cmd}")
            result = subprocess.run(cmd, shell=True, check=True)
            
            if result.returncode == 0:
                print("chkrootkit installed successfully.")
                return True
            else:
                return False
                
        except Exception as e:
            print(f"Error installing chkrootkit: {e}")
            return False
    
    # ==== File Integrity Monitoring ====
    
    def monitor_file_integrity(self):
        """Monitor file integrity of critical system files."""
        print("\n" + "=" * 50)
        print("           FILE INTEGRITY MONITORING")
        print("=" * 50)
        
        if not self.fim_enabled:
            print("File integrity monitoring is disabled.")
            enable_now = input("Heimdell(Would you like to enable it? [y/n]) #> ").strip().lower()
            if enable_now == 'y':
                self.fim_enabled = True
                print("File integrity monitoring enabled.")
            else:
                return
        
        print("\nFile Integrity Monitoring Options:")
        print("1. Create/Update Baseline")
        print("2. Check Files Against Baseline")
        print("3. Configure Monitored Files")
        print("0. Back to Main Menu")
        
        choice = input("Heimdell(Select an option) #> ").strip()
        
        if choice == '0':
            return
        elif choice == '1':
            self._create_fim_baseline()
        elif choice == '2':
            self._check_fim_baseline()
        elif choice == '3':
            self._configure_fim_files()
        else:
            print("Invalid option. Please try again.")
    
    def _create_fim_baseline(self):
        """Create or update file integrity monitoring baseline."""
        print("\nCreating file integrity baseline...")
        
        baseline = {}
        
        for file_path in self.fim_critical_files:
            if not os.path.exists(file_path):
                print(f"Skipping non-existent file: {file_path}")
                continue
                
            try:
                # Get file hash
                file_hash = self._calculate_file_hash(file_path)
                
                # Get file metadata
                stat_info = os.stat(file_path)
                
                baseline[file_path] = {
                    'hash': file_hash,
                    'size': stat_info.st_size,
                    'mode': stat_info.st_mode,
                    'uid': stat_info.st_uid,
                    'gid': stat_info.st_gid,
                    'mtime': stat_info.st_mtime,
                    'timestamp': datetime.now().isoformat()
                }
                
                print(f"Added baseline for: {file_path}")
                
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")
        
        # Save baseline to file
        try:
            os.makedirs(os.path.dirname(self.fim_baseline_file), exist_ok=True)
            
            with open(self.fim_baseline_file, 'w') as f:
                json.dump(baseline, f, indent=2)
                
            print(f"\nBaseline saved to: {self.fim_baseline_file}")
            print(f"Total files in baseline: {len(baseline)}")
            
        except Exception as e:
            print(f"Error saving baseline: {e}")
    
    def _check_fim_baseline(self):
        """Check files against the integrity baseline."""
        print("\nChecking files against integrity baseline...")
        
        if not os.path.exists(self.fim_baseline_file):
            print("Baseline file does not exist. Please create a baseline first.")
            return
            
        try:
            # Load baseline
            with open(self.fim_baseline_file, 'r') as f:
                baseline = json.load(f)
                
            print(f"Loaded baseline with {len(baseline)} files.")
            
            # Check each file
            changes = []
            
            for file_path, baseline_data in baseline.items():
                if not os.path.exists(file_path):
                    changes.append({
                        'file': file_path,
                        'status': 'MISSING',
                        'baseline_time': baseline_data['timestamp']
                    })
                    continue
                    
                try:
                    # Check file hash
                    current_hash = self._calculate_file_hash(file_path)
                    
                    if current_hash != baseline_data['hash']:
                        # Get file metadata
                        stat_info = os.stat(file_path)
                        
                        changes.append({
                            'file': file_path,
							'status': 'MODIFIED',
                            'baseline_time': baseline_data['timestamp'],
                            'baseline_hash': baseline_data['hash'],
                            'current_hash': current_hash,
                            'mtime': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                            'size_changed': stat_info.st_size != baseline_data['size'],
                            'permissions_changed': stat_info.st_mode != baseline_data['mode'],
                            'owner_changed': (stat_info.st_uid != baseline_data['uid'] or 
                                              stat_info.st_gid != baseline_data['gid'])
                        })
                        
                except Exception as e:
                    changes.append({
                        'file': file_path,
                        'status': 'ERROR',
                        'error': str(e),
                        'baseline_time': baseline_data['timestamp']
                    })
            
            # Display results
            if changes:
                print("\n⚠️  File integrity changes detected:")
                
                for change in changes:
                    if change['status'] == 'MISSING':
                        print(f"  ❌ MISSING: {change['file']}")
                        print(f"     Baseline created: {change['baseline_time']}")
                    elif change['status'] == 'MODIFIED':
                        print(f"  ⚠️  MODIFIED: {change['file']}")
                        print(f"     Baseline: {change['baseline_time']}")
                        print(f"     Last modified: {change['mtime']}")
                        
                        if change['size_changed']:
                            print("     Size has changed")
                        if change['permissions_changed']:
                            print("     Permissions have changed")
                        if change['owner_changed']:
                            print("     Owner has changed")
                    elif change['status'] == 'ERROR':
                        print(f"  ❗ ERROR: {change['file']}")
                        print(f"     Error: {change['error']}")
                
                # Save changes to log file
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                changes_file = os.path.join(self.logs_dir, f'fim_changes_{timestamp}.json')
                
                with open(changes_file, 'w') as f:
                    json.dump(changes, f, indent=2)
                    
                print(f"\nChanges saved to: {changes_file}")
                
                # Ask if user wants to update baseline
                update_baseline = input("\nHemdell(Update baseline with current file states? [y/n]) #> ").strip().lower()
                if update_baseline == 'y':
                    self._create_fim_baseline()
            else:
                print("✅ No integrity changes detected.")
                
        except Exception as e:
            print(f"Error checking files against baseline: {e}")
    
    def _configure_fim_files(self):
        """Configure which files to monitor for integrity."""
        print("\nConfigure Files to Monitor:")
        
        while True:
            print("\nCurrently monitored files:")
            for i, file_path in enumerate(self.fim_critical_files, 1):
                exists = os.path.exists(file_path)
                status = "✅ Exists" if exists else "❌ Missing"
                print(f"{i}. {file_path} ({status})")
            
            print("\nOptions:")
            print("1. Add a file to monitor")
            print("2. Remove a file from monitoring")
            print("0. Back")
            
            choice = input("Heimdell(Select an option) #> ").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                new_file = input("Heimdell(Enter path of file to monitor) #> ").strip()
                
                if not new_file:
                    print("No file path entered.")
                    continue
                
                if new_file in self.fim_critical_files:
                    print("This file is already being monitored.")
                else:
                    if os.path.exists(new_file):
                        self.fim_critical_files.append(new_file)
                        print(f"Added {new_file} to monitored files.")
                    else:
                        print(f"Warning: File {new_file} does not exist.")
                        add_anyway = input("Heimdell(Add anyway? [y/n]) #> ").strip().lower()
                        if add_anyway == 'y':
                            self.fim_critical_files.append(new_file)
                            print(f"Added {new_file} to monitored files.")
            elif choice == '2':
                if not self.fim_critical_files:
                    print("No files to remove.")
                    continue
                
                remove_index = input("Heimdell(Enter number of file to remove) #> ").strip()
                
                try:
                    idx = int(remove_index) - 1
                    if 0 <= idx < len(self.fim_critical_files):
                        removed = self.fim_critical_files.pop(idx)
                        print(f"Removed {removed} from monitored files.")
                    else:
                        print("Invalid index.")
                except ValueError:
                    print("Please enter a valid number.")
            else:
                print("Invalid option. Please try again.")
    
    def _calculate_file_hash(self, file_path):
        """
        Calculate SHA-256 hash of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            str: Hexadecimal hash string
        """
        sha256 = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except PermissionError:
            # Try with sudo on Unix-like systems
            if self.system != "Windows":
                try:
                    # Create temporary file
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        tmp_path = tmp.name
                    
                    # Copy file with sudo
                    subprocess.run(['sudo', 'cat', file_path], stdout=open(tmp_path, 'wb'), check=True)
                    
                    # Calculate hash
                    with open(tmp_path, 'rb') as f:
                        for chunk in iter(lambda: f.read(4096), b''):
                            sha256.update(chunk)
                    
                    # Clean up
                    os.unlink(tmp_path)
                    
                    return sha256.hexdigest()
                except Exception as e:
                    raise Exception(f"Error calculating hash with sudo: {e}")
            else:
                raise
    
    # ==== Process Monitoring ====
    
    def monitor_processes(self, top_only=False):
        """
        Monitor running processes and detect suspicious activity.
        
        Args:
            top_only: If True, only show top processes by CPU and memory usage
        """
        if top_only:
            self._show_top_processes()
            return
        
        print("\n" + "=" * 50)
        print("           PROCESS MONITORING")
        print("=" * 50)
        
        print("\nProcess Monitoring Options:")
        print("1. View Top Processes (CPU & Memory)")
        print("2. Search for a Process")
        print("3. Monitor Specific Processes")
        print("4. Find Suspicious Processes")
        print("0. Back to Main Menu")
        
        choice = input("Heimdell(Select an option) #> ").strip()
        
        if choice == '0':
            return
        elif choice == '1':
            self._show_top_processes()
        elif choice == '2':
            self._search_process()
        elif choice == '3':
            self._monitor_specific_processes()
        elif choice == '4':
            self._find_suspicious_processes()
        else:
            print("Invalid option. Please try again.")
    
    def _show_top_processes(self):
        """Show top processes by CPU and memory usage."""
        print("\nTop Processes by CPU usage:")
        print("-" * 80)
        print("{:<5} {:<20} {:<10} {:<10} {:<10} {:<20}".format(
            "PID", "NAME", "CPU%", "MEM%", "STATUS", "USER"))
        print("-" * 80)
        
        # Get top processes by CPU
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status']):
            try:
                # Get process info
                proc_info = proc.info
                proc_info['cpu_percent'] = proc.cpu_percent(interval=0.1)
                proc_info['memory_percent'] = proc.memory_percent()
                processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Sort by CPU usage
        top_cpu = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:10]
        
        for proc in top_cpu:
            print("{:<5} {:<20} {:<10.2f} {:<10.2f} {:<10} {:<20}".format(
                proc['pid'],
                proc['name'][:20],
                proc['cpu_percent'],
                proc['memory_percent'],
                proc['status'],
                proc['username'][:20] if proc['username'] else 'N/A'
            ))
        
        print("\nTop Processes by Memory usage:")
        print("-" * 80)
        print("{:<5} {:<20} {:<10} {:<10} {:<10} {:<20}".format(
            "PID", "NAME", "CPU%", "MEM%", "STATUS", "USER"))
        print("-" * 80)
        
        # Sort by memory usage
        top_memory = sorted(processes, key=lambda x: x['memory_percent'], reverse=True)[:10]
        
        for proc in top_memory:
            print("{:<5} {:<20} {:<10.2f} {:<10.2f} {:<10} {:<20}".format(
                proc['pid'],
                proc['name'][:20],
                proc['cpu_percent'],
                proc['memory_percent'],
                proc['status'],
                proc['username'][:20] if proc['username'] else 'N/A'
            ))
    
    def _search_process(self):
        """Search for a specific process by name or PID."""
        print("\nSearch for a Process:")
        search_term = input("Heimdell(Enter process name or PID) #> ").strip()
        
        if not search_term:
            print("No search term provided.")
            return
        
        # Check if search term is a PID
        is_pid = search_term.isdigit()
        
        # Search for processes
        found_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'cmdline']):
            try:
                # Check if process matches search criteria
                if is_pid and proc.info['pid'] == int(search_term):
                    found_processes.append(proc)
                elif not is_pid and search_term.lower() in proc.info['name'].lower():
                    found_processes.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        if found_processes:
            print(f"\nFound {len(found_processes)} matching processes:")
            print("-" * 90)
            print("{:<5} {:<15} {:<10} {:<10} {:<10} {:<20}".format(
                "PID", "NAME", "CPU%", "MEM%", "STATUS", "USER"))
            print("-" * 90)
            
            for proc in found_processes:
                try:
                    cpu_percent = proc.cpu_percent(interval=0.1)
                    memory_percent = proc.memory_percent()
                    
                    print("{:<5} {:<15} {:<10.2f} {:<10.2f} {:<10} {:<20}".format(
                        proc.info['pid'],
                        proc.info['name'][:15],
                        cpu_percent,
                        memory_percent,
                        proc.info['status'],
                        proc.info['username'][:20] if proc.info['username'] else 'N/A'
                    ))
                    
                    # Show command line
                    cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else 'N/A'
                    if len(cmdline) > 80:
                        cmdline = cmdline[:77] + '...'
                    print(f"  Command: {cmdline}")
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    print(f"  Process {proc.info['pid']} no longer exists or cannot be accessed.")
                
                # Ask if user wants to see more details
                if len(found_processes) <= 5:  # Only for a few processes
                    show_details = input("\nHemdell(Show more details for this process? [y/n]) #> ").strip().lower()
                    if show_details == 'y':
                        self._show_process_details(proc.info['pid'])
        else:
            print(f"No processes found matching '{search_term}'.")
    
    def _show_process_details(self, pid):
        """
        Show detailed information about a specific process.
        
        Args:
            pid: Process ID
        """
        try:
            proc = psutil.Process(pid)
            
            print("\nProcess Details:")
            print(f"  PID: {proc.pid}")
            print(f"  Name: {proc.name()}")
            print(f"  Status: {proc.status()}")
            print(f"  Created: {datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  User: {proc.username()}")
            
            # CPU and memory info
            cpu_percent = proc.cpu_percent(interval=0.5)
            memory_info = proc.memory_info()
            memory_percent = proc.memory_percent()
            
            print(f"  CPU Usage: {cpu_percent:.2f}%")
            print(f"  Memory Usage: {self._format_bytes(memory_info.rss)} ({memory_percent:.2f}%)")
            
            # Command line
            cmdline = ' '.join(proc.cmdline()) if proc.cmdline() else 'N/A'
            print(f"  Command Line: {cmdline}")
            
            # Open files
            try:
                open_files = proc.open_files()
                if open_files:
                    print("\n  Open Files:")
                    for file in open_files[:10]:  # Limit to 10 files
                        print(f"    {file.path}")
                    
                    if len(open_files) > 10:
                        print(f"    ... and {len(open_files) - 10} more")
            except (psutil.AccessDenied, psutil.ZombieProcess):
                print("  Open Files: Access denied")
            
            # Network connections
            try:
                connections = proc.connections()
                if connections:
                    print("\n  Network Connections:")
                    for conn in connections[:10]:  # Limit to 10 connections
                        local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if hasattr(conn, 'laddr') and conn.laddr else 'N/A'
                        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if hasattr(conn, 'raddr') and conn.raddr else 'N/A'
                        print(f"    {conn.type}: {local_addr} -> {remote_addr} ({conn.status})")
                    
                    if len(connections) > 10:
                        print(f"    ... and {len(connections) - 10} more")
            except (psutil.AccessDenied, psutil.ZombieProcess):
                print("  Network Connections: Access denied")
            
        except psutil.NoSuchProcess:
            print(f"Process with PID {pid} no longer exists.")
        except psutil.AccessDenied:
            print(f"Access denied to process with PID {pid}.")
        except Exception as e:
            print(f"Error getting process details: {e}")
    
    def _monitor_specific_processes(self):
        """Monitor specific processes of interest."""
        print("\nMonitoring Specific Processes:")
        
        # Offer options to add/remove monitored processes
        while True:
            print("\nCurrently monitored processes:")
            for i, proc_name in enumerate(self.monitored_processes, 1):
                print(f"{i}. {proc_name}")
            
            print("\nOptions:")
            print("1. Add a process to monitor")
            print("2. Remove a process from monitoring")
            print("3. Monitor all processes now")
            print("0. Back")
            
            choice = input("Heimdell(Select an option) #> ").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                new_proc = input("Heimdell(Enter process name to monitor) #> ").strip()
                
                if not new_proc:
                    print("No process name entered.")
                    continue
                
                if new_proc in self.monitored_processes:
                    print("This process is already being monitored.")
                else:
                    self.monitored_processes.append(new_proc)
                    print(f"Added {new_proc} to monitored processes.")
            elif choice == '2':
                if not self.monitored_processes:
                    print("No processes to remove.")
                    continue
                
                remove_index = input("Heimdell(Enter number of process to remove) #> ").strip()
                
                try:
                    idx = int(remove_index) - 1
                    if 0 <= idx < len(self.monitored_processes):
                        removed = self.monitored_processes.pop(idx)
                        print(f"Removed {removed} from monitored processes.")
                    else:
                        print("Invalid index.")
                except ValueError:
                    print("Please enter a valid number.")
            elif choice == '3':
                self._check_monitored_processes()
            else:
                print("Invalid option. Please try again.")
    
    def _check_monitored_processes(self):
        """Check the status of monitored processes."""
        print("\nChecking monitored processes...")
        
        # Dictionary to hold found processes
        found_processes = {proc: [] for proc in self.monitored_processes}
        
        # Search for monitored processes
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                proc_name = proc.info['name'].lower()
                
                # Check if process name matches any monitored process
                for monitored in self.monitored_processes:
                    if monitored.lower() in proc_name or monitored.lower() in ' '.join(proc.info['cmdline']).lower():
                        # Add process info
                        proc_info = {
                            'pid': proc.pid,
                            'name': proc.info['name'],
                            'username': proc.info['username'],
                            'cpu_percent': proc.cpu_percent(interval=0.1),
                            'memory_percent': proc.memory_percent(),
                            'cmdline': ' '.join(proc.info['cmdline'])
                        }
                        found_processes[monitored].append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Display results
        print("\nMonitored Processes Status:")
        print("-" * 80)
        
        for proc_name, processes in found_processes.items():
            if processes:
                print(f"\n✅ {proc_name}: {len(processes)} instances found")
                
                for p in processes:
                    print(f"  PID: {p['pid']}, CPU: {p['cpu_percent']:.2f}%, Memory: {p['memory_percent']:.2f}%")
                    print(f"  User: {p['username'] if p['username'] else 'N/A'}")
                    
                    # Show abbreviated command line
                    cmdline = p['cmdline']
                    if len(cmdline) > 70:
                        cmdline = cmdline[:67] + '...'
                    print(f"  Command: {cmdline}")
            else:
                print(f"\n❌ {proc_name}: Not running")
    
    def _find_suspicious_processes(self):
        """Find potentially suspicious processes."""
        print("\nScanning for suspicious processes...")
        
        suspicious = []
        
        # Get all processes
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'exe', 'connections']):
            try:
                # Skip system processes we can't access
                if not proc.info['username']:
                    continue
                
                # Check for suspicious indicators
                proc_info = {
                    'pid': proc.pid,
                    'name': proc.info['name'],
                    'username': proc.info['username'],
                    'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                    'exe': proc.info['exe'],
                    'suspicious_reasons': []
                }
                
                # Check for unusual names (random characters)
                if re.match(r'^[a-zA-Z0-9]{8,}$', proc_info['name']) and not proc_info['name'].lower() in [
					'explorer', 'svchost', 'conhost', 'runtimebroker', 'searchindexer', 'smss', 'csrss', 'wininit', 'services', 'lsass'
                ]:
                    proc_info['suspicious_reasons'].append("Unusual process name (random characters)")
                
                # Check for processes running from temp directories
                if proc_info['exe'] and any(temp_dir in proc_info['exe'].lower() for temp_dir in ['/tmp/', 'temp', 'appdata']):
                    proc_info['suspicious_reasons'].append("Running from temporary directory")
                
                # Check for hidden process names (starting with dot on Unix or hidden attribute on Windows)
                if self.system != "Windows" and proc_info['name'].startswith('.'):
                    proc_info['suspicious_reasons'].append("Hidden process name (starts with dot)")
                
                # Check for unusual network connections
                try:
                    connections = proc.connections()
                    for conn in connections:
                        if hasattr(conn, 'raddr') and conn.raddr:
                            if conn.raddr.port in [4444, 1337, 31337, 6666, 6667, 6668, 6669]:  # Common backdoor ports
                                proc_info['suspicious_reasons'].append(f"Connection to suspicious port {conn.raddr.port}")
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                
                # Check for processes with unusual command line options
                suspicious_cmds = ['nc -e', 'netcat -e', 'wget http', 'curl http', 'bash -i', 'sh -i', 'cmd.exe /c',
                                   'powershell -e', 'python -c "import socket', 'perl -e', 'chmod 777',
                                   'mv /bin', 'rm -rf /', 'mkfifo', 'mknod', 'exec']
                
                for cmd in suspicious_cmds:
                    if cmd in proc_info['cmdline'].lower():
                        proc_info['suspicious_reasons'].append(f"Suspicious command line: '{cmd}'")
                
                # Add to suspicious list if any reasons found
                if proc_info['suspicious_reasons']:
                    suspicious.append(proc_info)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Display results
        if suspicious:
            print(f"\nFound {len(suspicious)} potentially suspicious processes:")
            
            for proc in suspicious:
                print("\n" + "-" * 80)
                print(f"PID: {proc['pid']}, Name: {proc['name']}, User: {proc['username']}")
                
                for reason in proc['suspicious_reasons']:
                    print(f"  ⚠️  {reason}")
                
                # Show command line
                cmdline = proc['cmdline']
                if len(cmdline) > 70:
                    cmdline = cmdline[:67] + '...'
                print(f"Command: {cmdline}")
                
                # Show executable path
                exe = proc['exe'] if proc['exe'] else 'Unknown'
                print(f"Executable: {exe}")
                
                # Option to kill process
                kill_proc = input(f"\nHemdell(Kill process {proc['pid']}? [y/n]) #> ").strip().lower()
                if kill_proc == 'y':
                    try:
                        if self.system == "Windows":
                            # On Windows, use taskkill
                            subprocess.run(['taskkill', '/F', '/PID', str(proc['pid'])], check=True)
                        else:
                            # On Unix, use sudo kill
                            subprocess.run(['sudo', 'kill', '-9', str(proc['pid'])], check=True)
                        print(f"✅ Process {proc['pid']} terminated.")
                    except Exception as e:
                        print(f"Error terminating process: {e}")
        else:
            print("\n✅ No suspicious processes found.")
    
    # ==== Configuration ====
    
    def _configure_settings(self):
        """Configure monitoring settings."""
        print("\n" + "=" * 50)
        print("           CONFIGURE SETTINGS")
        print("=" * 50)
        
        print("\nCurrent Settings:")
        print(f"1. CPU Usage Threshold: {self.cpu_threshold}%")
        print(f"2. Memory Usage Threshold: {self.memory_threshold}%")
        print(f"3. Disk Usage Threshold: {self.disk_threshold}%")
        print(f"4. File Integrity Monitoring: {'Enabled' if self.fim_enabled else 'Disabled'}")
        print("5. Tool Paths")
        print("0. Back to Main Menu")
        
        choice = input("Heimdell(Select setting to change, or 0 to return) #> ").strip()
        
        if choice == '0':
            return
        elif choice == '1':
            new_threshold = input("Heimdell(Enter new CPU usage threshold %) #> ").strip()
            try:
                value = int(new_threshold)
                if 0 <= value <= 100:
                    self.cpu_threshold = value
                    print(f"CPU usage threshold updated to {value}%")
                else:
                    print("Value must be between 0 and 100.")
            except ValueError:
                print("Please enter a valid number.")
        elif choice == '2':
            new_threshold = input("Heimdell(Enter new memory usage threshold %) #> ").strip()
            try:
                value = int(new_threshold)
                if 0 <= value <= 100:
                    self.memory_threshold = value
                    print(f"Memory usage threshold updated to {value}%")
                else:
                    print("Value must be between 0 and 100.")
            except ValueError:
                print("Please enter a valid number.")
        elif choice == '3':
            new_threshold = input("Heimdell(Enter new disk usage threshold %) #> ").strip()
            try:
                value = int(new_threshold)
                if 0 <= value <= 100:
                    self.disk_threshold = value
                    print(f"Disk usage threshold updated to {value}%")
                else:
                    print("Value must be between 0 and 100.")
            except ValueError:
                print("Please enter a valid number.")
        elif choice == '4':
            if self.fim_enabled:
                disable = input("Heimdell(File integrity monitoring is enabled. Disable? [y/n]) #> ").strip().lower()
                if disable == 'y':
                    self.fim_enabled = False
                    print("File integrity monitoring disabled.")
            else:
                enable = input("Heimdell(File integrity monitoring is disabled. Enable? [y/n]) #> ").strip().lower()
                if enable == 'y':
                    self.fim_enabled = True
                    print("File integrity monitoring enabled.")
        elif choice == '5':
            self._configure_tool_paths()
        else:
            print("Invalid option. Please try again.")
    
    def _configure_tool_paths(self):
        """Configure paths to external tools."""
        print("\nTool Paths Configuration:")
        print(f"1. ClamAV Path: {self.clamav_bin}")
        if self.system != "Windows":
            print(f"2. chkrootkit Path: {self.chkrootkit_bin}")
        print(f"3. Logs Directory: {self.logs_dir}")
        print("0. Back")
        
        choice = input("Heimdell(Select option, or 0 to return) #> ").strip()
        
        if choice == '0':
            return
        elif choice == '1':
            new_path = input(f"Heimdell(Enter new ClamAV path [current: {self.clamav_bin}]) #> ").strip()
            if new_path:
                # Verify path exists
                if os.path.exists(new_path):
                    self.clamav_bin = new_path
                    print(f"ClamAV path updated to {new_path}")
                else:
                    print(f"Warning: Path {new_path} does not exist.")
                    update_anyway = input("Heimdell(Update anyway? [y/n]) #> ").strip().lower()
                    if update_anyway == 'y':
                        self.clamav_bin = new_path
                        print(f"ClamAV path updated to {new_path}")
        elif choice == '2' and self.system != "Windows":
            new_path = input(f"Heimdell(Enter new chkrootkit path [current: {self.chkrootkit_bin}]) #> ").strip()
            if new_path:
                # Verify path exists
                if os.path.exists(new_path):
                    self.chkrootkit_bin = new_path
                    print(f"chkrootkit path updated to {new_path}")
                else:
                    print(f"Warning: Path {new_path} does not exist.")
                    update_anyway = input("Heimdell(Update anyway? [y/n]) #> ").strip().lower()
                    if update_anyway == 'y':
                        self.chkrootkit_bin = new_path
                        print(f"chkrootkit path updated to {new_path}")
        elif choice == '3':
            new_path = input(f"Heimdell(Enter new logs directory [current: {self.logs_dir}]) #> ").strip()
            if new_path:
                try:
                    # Try to create directory if it doesn't exist
                    os.makedirs(new_path, exist_ok=True)
                    self.logs_dir = new_path
                    print(f"Logs directory updated to {new_path}")
                except Exception as e:
                    print(f"Error creating directory: {e}")
                    
                    # Try with sudo on Unix-like systems
                    if isinstance(e, PermissionError) and self.system != "Windows":
                        try_sudo = input("Heimdell(Try creating directory with sudo? [y/n]) #> ").strip().lower()
                        if try_sudo == 'y':
                            try:
                                subprocess.run(['sudo', 'mkdir', '-p', new_path], check=True)
                                subprocess.run(['sudo', 'chmod', '755', new_path], check=True)
                                self.logs_dir = new_path
                                print(f"Logs directory updated to {new_path}")
                            except Exception as sudo_e:
                                print(f"Error creating directory with sudo: {sudo_e}")
        else:
            print("Invalid option. Please try again.")
    
    def save_config(self):
        """Save current configuration."""
        config = {
            'cpu_threshold': self.cpu_threshold,
            'memory_threshold': self.memory_threshold,
            'disk_threshold': self.disk_threshold,
            'fim_enabled': self.fim_enabled,
            'fim_critical_files': self.fim_critical_files,
            'monitored_processes': self.monitored_processes,
            'clamav_bin': self.clamav_bin,
            'chkrootkit_bin': self.chkrootkit_bin,
            'logs_dir': self.logs_dir
        }
        
        return config