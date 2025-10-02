# ASRepCatcher-Win - Make everyone in your VLAN ASREProastable

##  "Works on My Machine" Disclaimer 

This Windows version of ASRepCatcher has been tested on a limited number of virtual machines running on an ARM M4 MacBook with only one target node. There is **not** perfect functionality parity between the Linux and Windows versions. Your mileage may vary depending on your specific Windows environment, network configuration, and security settings.

If you encounter issues, consider using the original Linux version on a Kali or Ubuntu VM.

## Overview

During an Active Directory black box pentest, if multicast DNS protocols are disabled and/or all protocols (SMB, LDAP, etc.) are signed and no exposed service is vulnerable, you quickly run out of options to get a domain user.

ASRepCatcher uses ARP spoofing to catch AS-REP messages returned by the Domain Controller to the clients and prints out the hash to crack.

**This technique does not rely on Kerberos pre-authentication being disabled. It works for all users on the VLAN.**

## Two modes

### Listen Mode

In listen mode, the ARP cache of the gateway is poisoned in order to receive the AS-REP responses destined to the clients.
This is a passive mode - there is no alteration of the packets in transit.

```bash
python ASRepCatcher-WIN.py listen -t 192.168.1.50 -dc 192.168.1.100
```

### Relay Mode

In relay mode, ASRepCatcher uses packet sniffing to capture Kerberos authentication traffic. If ARP spoofing is enabled, the ARP caches of the workstations are poisoned to redirect traffic through your machine.

**Note**: Unlike the Linux version, the Windows version does not modify Kerberos packets or force RC4 encryption. It only captures the traffic.

```bash
python ASRepCatcher-WIN.py relay -t 192.168.1.50 -dc 192.168.1.100
```

## Features of ARP Spoofing

In both modes, ARP spoofing can be targeted to specific systems to reduce network load:

- In relay mode: Workstation ARP caches are poisoned to redirect their traffic
- In listen mode: The gateway's ARP cache is poisoned to intercept responses

If executed with `--stop-spoofing` option, a client's IP is removed from the target list after capturing its hash:
- The ARP cache is restored to normal to minimize network disruption
- It's generally better not to use this option as multiple users may be on the same IP (shared computers, DHCP, NAT, etc.)

If you prefer to use your own spoofing method, you can disable ARP spoofing with `--disable-spoofing`.

## Installation

```bash
# Clone the repository
git clone https://github.com/mojibake-dev/ASRepCatcher-Win
cd ASRepCatcher-Win

# Install dependencies
pip install -r requirements.txt
```

Requires Python 3.7 or newer and Scapy.

## Usage

```
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

usage: python ASRepCatcher-WIN.py [-h] [-outfile OUTFILE] [-format {hashcat,john}] [-debug]
                                  [-t Client workstations] [-tf targets file] [-gw Gateway IP]
                                  [-dc DC IP] [-iface interface] [--port PORT] [--skip-redirection]
                                  [--stop-spoofing] [--disable-spoofing]
                                  {relay,listen}

Catches Kerberos AS-REP packets and outputs it to a crackable format

positional arguments:
  {relay,listen}        Relay mode  : AS-REQ requests are relayed to capture AS-REP.
                        Listen mode : AS-REP packets going to clients are sniffed. No alteration of
                        packets is performed.

options:
  -h, --help            show this help message and exit
  -outfile OUTFILE      Output file name to write hashes to crack.
  -format {hashcat,john}
                        Format to save the AS_REP hashes. Default is hashcat.
  -debug                Increase verbosity.
  -dc DC IP             Domain controller's IP.
  -iface interface      Interface to use. Uses default interface if not specified.
  --port PORT           Port to use for packet capture (default: 88).
  --skip-redirection    Skip setting up traffic redirection (useful for testing or when using external
                        redirection)

ARP poisoning:
  -t Client workstations
                        Comma separated list of client computers IP addresses or subnet (IP/mask).
  -tf targets file      File containing client workstations IP addresses.
  -gw Gateway IP        Gateway IP. More generally, the IP from which the AS-REP will be coming from.
                        Default is default interface's gateway.
  --stop-spoofing       Stops poisoning the target once an AS-REP packet is received from it. False by
                        default.
  --disable-spoofing    Disables arp spoofing, the MitM position is attained by the attacker using
                        their own method. False by default : the tool uses its own arp spoofing method.
```

## Windows-Specific Notes

- Must be run as Administrator to set up network capturing and ARP spoofing
- If you get errors about port 88 being in use, try stopping the Kerberos services or using `--skip-redirection` option
- The Windows version relies more heavily on passive sniffing rather than active packet manipulation
- Uses Windows-specific network configuration to enable IP forwarding and properly capture redirected traffic

## Hash Cracking

The captured hashes can be cracked using Hashcat:

- For RC4-based hashes: `hashcat -m 18200 hashes.txt wordlist.txt`
- For AES-based hashes: `hashcat -m 19700 hashes.txt wordlist.txt`

## Credits

- Original ASRepCatcher by [Yassine OUKESSOU](https://github.com/Yaxxine7/ASRepCatcher)
- Windows port and modifications by Samara Eli