# LightPacket - A Comprehensive Packet Manipulation Library

[![License: MPL-2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS%20%7C%20BSD-lightgrey.svg)](https://github.com/Light-Projects/LightPacket)

![](images/LightPacket-Logo.png)

## Overview

**LightPacket** is a cross-platform packet manipulation library designed for building, parsing, and sending network packets at Layer 2. It provides a clean Python interface for constructing custom packets, parsing captured data, and interacting with network interfaces using libpcap/Npcap.

### Key Features

- **Cross-Platform Support**: Works on Linux, macOS, BSD, Unix (libpcap) and Windows (Npcap)
- **Layer 2 Packet Construction**: Build Ethernet, ARP, LLC, SNAP, Dot3, VLAN (802.1Q/802.1ad QinQ), STP, PPP, PPPoE, EAPOL, and ISL packets
- **Automatic Layer Detection**: Parse raw bytes into structured packet objects
- **Packet Stacking**: Chain multiple protocol layers together using `/` operator
- **Interface Detection**: Automatically detect and use default network interfaces
- **Rich Packet Representation**: Human-readable packet displays with color support
- **Send/Receive Capabilities**: Send and receive packets at Layer 2 (both `L2Socket` and the new `L2Packet` for Linux)
- **Custom Packet Parsing**: Extensible parser architecture
- **Comprehensive Error Handling**: Custom error classes with detailed messages
- **MAC Address Utilities**: Flexible MAC address handling
- **PCAP Reading/Writing**: C-optimized pcap file I/O operations
- **BPF Filter Compilation**: Built-in support for Berkeley Packet Filters using libpcap

---

## New in Version 0.0.3

- **Native AF_PACKET Socket (`L2Packet`)** for Linux: a lightweight, high-performance raw socket implementation that bypasses libpcap for sending and receiving. It supports BPF filtering, blocking/non-blocking modes, and direct interface binding.
- **Platform-specific organisation**: The library now uses a `platforms/` directory to keep OS-specific code separate (e.g., `platforms/linux/L2Packet.py`).
- **Enhanced EAPOL Support**: Full parsing and construction of EAPOL, EAP-MD5, EAP-Identity, and EAP-Success/Failure frames.
- **Improved VLAN Handling**: Automatic detection of stacked VLAN tags (QinQ) with `vlannum()` and better integration with Ethernet/Dot3 parsing.
- **C-optimised PCAP I/O**: Faster reading and writing of `.pcap` files using the C extensions.

---

## Architecture Overview (0.0.3)

```
LightPacket/
├── __init__.py                   # Package entry point
├── BaseLayer.py                  # Core layer abstraction
├── l2.py                         # All layers main classes
├── Raw.py                        # Raw data layer
├── EthernetII.py                 # Ethernet layer
├── Arp.py                        # ARP layer
├── GetMac.py                     # Mac helper
├── GetIPv4.py                    # IPv4 helper
├── ppp.py                        # PPP, PPP2b, PPPoE layers
├── eapol.py                      # EAPOL and EAP Methods
├── bpf.py                        # BPF Comiplation
├── eapol.py                      # EAPOL and EAP sub-layers
├── Dot3.py                       # IEEE 802.3 layer
├── LLC.py                        # Logical Link Control layer
├── Snap.py                       # SNAP layer
├── Stp.py                        # STP Layer
├── Vlan.py                       # VLAN (802.1Q/802.1ad QinQ) layer
├── Detect_layer.py               # Automatic protocol detection
├── Consts.py                     # Protocol constants
├── Version.py                    # Version information (now 0.0.3)
├── Hex.py                        # hexdump function
├── platforms/                    # Platform-specific implementations
│   └── linux/
│       └── L2Packet.py           # AF_PACKET socket class
├── Wireless/                     # Wireless Protocols
│   └── wlan.py                   # IEEE 802.11 (WiFi,Beacon,etc ...)
├── data/
│   └── oui.txt                  # Organizationally Unique Identifier (OUI)
├── Decoration/
│   └── Colors.py                 # ANSI color formatting
├── helper/
│   ├── ls.py                     # Layer information
│   └── protos/
│       └── *.json                # JSON definitions for each protocol
├── Interfaces/                   # Platform-specific network interfaces
│   ├── LinuxInterfaces.py        # Linux interface enumeration
│   ├── LibpcapInterfacesLin.py   # libpcap interface handling
│   ├── WinInterfaces.py          # Windows interface enumeration
│   ├── NpcapInterfacesWin.py     # Npcap interface handling
│   ├── UnixInterfaces.py         # BSD/macOS interface enumeration (libpcap)
│   └── LibpcapInterfacesUnix.py  # BSD/macOS simple interface handling
├── utils/                        # Layer utilities
│   ├── CIDR.py                   # Target parsing and validation
│   ├── FCS.py                    # CRC and FCS checksums
│   ├── VlanUtils.py              # VLAN utilities
│   └── Nsec/
│       └── arp_resolution.py     # Built-in ARP scanning
├── lib/                          # C extensions
│   ├── pcap_writer.c             # Pcap writer implementation
│   ├── pcap_writer.h             # Pcap writer header
│   ├── pcap_reader.c             # Pcap reader implementation
│   └── pcap_reader.h             # Pcap reader header
├── Saving/                       # PCAP read/write functions
│   ├── pcapreader.py             # pcap_reader python wrapper
│   └── pcapwriter.py             # pcap_writer python wrapper
├── Layers/                       # Helper layer components
│   ├── L2Socket.py               # Windows L2 socket (Npcap)
│   ├── L2SocketL.py              # Linux L2 socket (libpcap)
│   ├── Mac.py                    # MAC address utilities
│   ├── IPtoa.py                  # IP address utilities
│   └── IS_LLC.py                 # LLC detection utility
├── Logger/                       # Logging and error handling
│   ├── LightLogger.py            # Custom logger with color support
│   └── Errors.py                 # Custom error classes
├── LightPacketWin.py             # Windows API wrapper
├── LightPacketLin.py             # Linux API wrapper
└── LightPacketUnix.py            # Unix-like systems API wrapper
```

---

## Installation

### Prerequisites

**Linux:**
```bash
sudo apt-get install libpcap-dev    # Debian/Ubuntu
sudo dnf install libpcap-devel      # RHEL/CentOS/Fedora
sudo pacman -S libpcap              # Arch
sudo zypper install libpcap1        # OpenSUSE/SUSE
sudo apk add libpcap-dev            # Alpine
sudo emerge net-libs/libpcap        # Gentoo
sudo xbps-install -S libpcap-devel  # Void
sudo tce-load -wi libpcap           # Tiny Core
```

**Mac:**
```bash
brew install libpcap
# or port
sudo port install libpcap
```

**BSD:**
```bash
pkg install libpcap   # FreeBSD
pkg_add libpcap       # OpenBSD/NetBSD
```

**Unix:**
```bash
pkg install system/library/libpcap      # illumos (OpenIndiana)

pkgadd -d http://get.opencsw.org/now    # Solaris
/opt/csw/bin/pkgutil -y -i libpcap1
```

**Windows:**
- Install [Npcap](https://npcap.com/) (run in WinPcap API-compatible mode)
- Ensure Python 3.8+ is installed

```powershell
winget install Nmap.Npcap
```

### Install from Source

> **Note:** For Mac and Windows you should change the lib extension in `setup.py` and for compiling as well.

```bash
git clone https://github.com/Light-Projects/LightPacket
cd LightPacket
gcc ./lib/pcap_reader.c -o ./lib/libpcap_reader.so -Wall -O2 -shared -fPIC
gcc ./lib/pcap_writer.c -o ./lib/libpcap_writer.so -Wall -O2 -shared -fPIC
python setup.py install
```

### Install from PyPI

Works for Linux/Windows/Mac.

```bash
pip install lightpacket
```

### Dependencies (optional)

```bash
# For enhanced interface detection (recommended)
pip install netifaces

# For Linux advanced routing / socket operations
pip install pyroute2
```

---

## Core Classes and Functions

### BaseLayer Class (`BaseLayer.py`)

The foundation for all protocol layers.

| Attribute | Description |
|-----------|-------------|
| `payload` | Next layer in the packet stack |
| `_raw_payload` | Raw bytes payload |

| Method | Description |
|--------|-------------|
| `build()` | Convert layer to bytes (implemented by subclasses) |
| `set_payload()` | Set the next layer |
| `get_payload_bytes()` | Get payload as bytes |
| `copy()` | Create a deep copy of the layer |
| `show()` | Display layer information |
| `__truediv__()` | Stack layers using `/` operator |
| `__rtruediv__()` | Reverse stacking |

**Example:**
```python
from LightPacket.Arp import ARP
from LightPacket.EthernetII import Ethernet

# Stack layers using division operator
packet = Ethernet() / ARP()
```

---

## Layer Construction Functions

### EthernetLayer (`EthernetII.py`)

```python
class Ethernet(BaseLayer):
    def __init__(self, dst: Union[str, bytes] = BROADCAST_MAC, src: Union[str, bytes]= GetMac(),
                 ethertype: Union[str, bytes] = None):
        super().__init__()
        self.dst = MacAddress(dst, d_or_s=1)
        self.src = MacAddress(src, d_or_s=0)
        self.ethertype = ethertype
```

**Parameters:**
- `src`: Source MAC address (auto-detected if None)
- `dst`: Destination MAC address
- `ethertype`: EtherType value (auto-detected for ARP/IPv4)

**Example:**
```python
from LightPacket.EthernetII import Ethernet

# Create Ethernet layer with default settings
eth = Ethernet()

# Create with custom MAC addresses
eth = Ethernet(
    src='00:11:22:33:44:55',
    dst='ff:ff:ff:ff:ff:ff',
    ethertype=0x0806  # ARP
)
```

---

### ArpLayer (`Arp.py`)

```python
class ARP(BaseLayer):
    def __init__(self, hwtype: int = None, ptype: int = None, maclen: int = None,
                 plen: int = None, opcode: int = None, macsrc: Union[str, bytes] = None,
                 ipsrc: str = None, macdst: Union[str, bytes] = None, ipdst: str = None):
        super().__init__()
        if macsrc is None:
            macsrc = GetMac()
        if macdst is None:
            macdst = BROADCAST_MAC
        if hwtype is None:
            hwtype = 1
        if ptype is None:
            ptype = IPv4
        if maclen is None:
            maclen = 6
        if plen is None:
            plen = 4
        if opcode is None:
            opcode = 1
        if ipsrc is None:
            ipsrc = GetIPv4()
        if ipdst is None:
            ipdst = GetIPv4Gateway()

        self.hwtype = hwtype
        self.ptype = ptype
        self.maclen = maclen
        self.plen = plen
        self.opcode = opcode
        self.macsrc = MacAddress(macsrc, d_or_s=0)
        self.ipsrc = ipsrc
        self.macdst = MacAddress(macdst, d_or_s=1)
        self.ipdst = ipdst
```

**Parameters:**
- `hwtype`: Hardware type (default: 1 for Ethernet)
- `ptype`: Protocol type (default: 0x0800 for IPv4)
- `maclen`: MAC address length (default: 6)
- `plen`: Protocol address length (default: 4)
- `opcode`: Operation code (1=request, 2=reply)
- `macsrc`: Source MAC address
- `ipsrc`: Source IP address
- `macdst`: Destination MAC address
- `ipdst`: Destination IP address

**Example:**
```python
from LightPacket.Arp import ARP

# Create ARP request
arp = ARP(
    opcode=1,
    ipsrc='192.168.1.10',
    ipdst='192.168.1.1'
)

# Create ARP reply
arp_reply = ARP(
    opcode=2,
    macsrc='00:11:22:33:44:55',
    ipsrc='192.168.1.1',
    macdst='aa:bb:cc:dd:ee:ff',
    ipdst='192.168.1.10'
)
```

---

### LLC Layer (`LLC.py`)

```python
class LLC(BaseLayer):
    def __init__(self, dsap=None, ssap=None, control=0x03):
        super().__init__()
        self.dsap = dsap
        self.ssap = ssap
        self.control = control
```

**Parameters:**
- `dsap`: Destination Service Access Point
- `ssap`: Source Service Access Point
- `control`: Control field

**Constants:**
- `SAP_LLC_SNAP = 0xAA`
- `LLC_UI = 0x03` (Unnumbered Information)

**Example:**
```python
from LightPacket.LLC import LLC

llc = LLC(dsap=0xAA, ssap=0xAA, control=0x03)
```

---

### SNAP Layer (`Snap.py`)

```python
class SNAP(BaseLayer):
    def __init__(self, oui=0x000000, pid=None):
        super().__init__()
        self.oui = oui
        self.pid = pid
```

**Parameters:**
- `oui`: Organizationally Unique Identifier
- `pid`: Protocol ID

**Example:**
```python
from LightPacket.Snap import SNAP

snap = SNAP(oui=0x000000, pid=0x0806)  # ARP over SNAP
```

---

### STP Layer (`Stp.py`)

```python
class STP(BaseLayer):
    def __init__(self, protocol_id=0x0000, protocol_version=0x00, bpdu_type=0x00, flags=0x00,
                 root_priority=0x8000, root_mac: Union[str,bytes] =b'\x00\x11\x22\x33\x44\x55',
                 root_path_cost=0, bridge_priority=0x8000,
                 bridge_mac : Union[str,bytes] =b'\x00\x11\x22\x33\x44\x55', port_id=0x8001,
                 message_age=0, max_age=5120, hello_time=512,
                 forward_delay=3840):
        super().__init__()
        self.protocol_id = protocol_id
        self.protocol_version = protocol_version
        self.bpdu_type = bpdu_type
        self.flags = flags
        self.root_priority = root_priority
        self.root_mac = MacAddress(root_mac)
        self.root_path_cost = root_path_cost
        self.bridge_priority = bridge_priority
        self.bridge_mac = MacAddress(bridge_mac)
        self.port_id = port_id
        self.message_age = message_age
        self.max_age = max_age
        self.hello_time = hello_time
        self.forward_delay = forward_delay
```

**Parameters:**
- `protocol_version`: STP protocol version (0 = 802.1D, 2 = RSTP)
- `bpdu_type`: BPDU type (0x00 = Config, 0x80 = TCN)
- `flags`: Topology change flags
- `root_priority`: Root bridge priority
- `root_mac`: Root bridge MAC address
- `root_path_cost`: Root path cost
- `bridge_priority`: Bridge priority
- `bridge_mac`: Bridge MAC address
- `port_id`: Port ID
- `message_age`: Message age in ticks
- `max_age`: Max age in ticks
- `hello_time`: Hello time in ticks
- `forward_delay`: Forward delay in ticks

**Example:**
```python
from LightPacket.Stp import STP

stp = STP(
    root_priority=0x8000,
    bridge_priority=0x8000,
    bridge_mac='00:11:22:33:44:55',
    max_age=5120,
    hello_time=512,
    forward_delay=3840
)
```

---

### Dot3Layer (`Dot3.py`)

```python
class Dot3(BaseLayer):
    def __init__(self, dst: Union[str, bytes] = BROADCAST_MAC, src: Union[str, bytes] = GetMac(),
                 length: int = 0):
        super().__init__()
        self.dst = MacAddress(dst, d_or_s=1)
        self.src = MacAddress(src, d_or_s=0)
        self.length = length
```

**Parameters:**
- `dst`: Destination MAC address
- `src`: Source MAC address
- `length`: Frame length (auto-calculated)

---

### VLANLayer (`Vlan.py`)

```python
class VLAN(BaseLayer):
    def __init__(self, tpid=0x8100, priority=0, dei=0, vlan_id=1):
        super().__init__()
        self.tpid = tpid
        self.priority = priority & 0x07
        self.dei = dei & 0x01
        self.vlan_id = vlan_id & 0x0FFF
```

**Parameters:**
- `tpid`: Tag Protocol Identifier (default: `0x8100` for 802.1Q; automatically set to `0x88A8` when stacking a `VLANLayer` inside another `VLANLayer`, i.e. QinQ)
- `priority`: Priority Code Point / PCP (3 bits, 0-7)
- `dei`: Drop Eligible Indicator (1 bit)
- `vlan_id`: VLAN Identifier (12 bits, 1-4094)

**Example:**
```python
from LightPacket.Arp import ARP
from LightPacket.Vlan import VLAN
from LightPacket.EthernetII import Ethernet

# Single-tagged 802.1Q VLAN packet
packet = Ethernet() / VLAN(vlan_id=100) / ARP()

# Double-tagged QinQ (802.1ad) packet - stack two VLAN layers
packet = Ethernet() / VLAN(vlan_id=10) / VLAN(vlan_id=20) / ARP()

# VLAN with custom priority and DEI
vlan = VLAN(priority=5, dei=1, vlan_id=200)
```

**Functions:**
- `vlannum(raw_packet)` - Count the number of stacked VLAN tags at the start of a raw packet by inspecting TPID values (`0x8100`, `0x88A8`, `0x9100`, `0x9200`)

---

### EAPOL and EAP sub-layers (`eapol.py`)

```python
from LightPacket.eapol import (
    EAPOL,EAP_TLS,EAP_MD5,EAP_STATE,
    EAP_IDENTITY,EAP_Key,EAP_TTLS,
    EAP_PEAP,EAP_FAST,EAP_LEAP,EAP_MSCHAPv2,
    EAP_NAK,EAP_NOTIFICATION,EAP_PWD,EAP_GTC,
    EAP_OTP
)

# EAPOL wrapper
eapol = EAPOL(version=2, code=0, length=0)

# EAP-Identity (Request/Response)
eap_id = EAP_IDENTITY(code=1, id=1, type=1, identity=b'user')

# EAP-MD5 (Challenge/Response)
eap_md5 = EAP_MD5(code=1, id=1, type=4, value_size=16, value=b'\x01\x02...', name=b'host')

# EAP Success/Failure
eap_success = EAP_STATE(code=3, id=1)   # code 3 = Success, 4 = Failure

# EAP-TLS (Request/Response)
eap_tls = EAP_TLS(code=1,id=103,type=13,L=1,tls_data=b'Lagier')

# EAP-TTLS (Request/Response)
eap_ttls = EAP_TTLS(code=1,id=103,type=21,L=1,tls_data=b'Lagier')

# EAP-KEY 
eap_key = EAP_Key(descriptor=2,key_info=0)


```

---

### WiFi (`wlan.py`)


```python
from LightPacket.Wireless.wlan import (
    WiFi,Beacon,Element,ProbeRequest,
    ProbeResponse
)
from LightPacket import MacAddress,GetMac

Packet = WiFi(
    duration=0x0000,
    addr1=b'\xff\xff\xff\xff\xff\xff',
    addr2=bytes(MacAddress(GetMac.GetMac())),
    addr3=bytes(MacAddress(GetMac.GetMac())),
    seq_control=0x0000,
) / Beacon(
    timestamp=0,
    beacon_interval=100,
    capability=0,
) / Element(
    ie_id=0,
    data=b'Light-AP'
) / Element(
    ie_id=45,
    data=b'n\x00\x17\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
) / Element(
    ie_id=3,
    data=b'\x06'
) / Element(
    ie_id=1,
    data=b'\x82\x84\x86\x88\x96'
) / Element(
    ie_id=48,
    data=b'\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00'
) / Element(
    ie_id=61,
    data=b'\x06\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff'
)
```

---

### RawLayer (`Raw.py`)

```python
class Raw(BaseLayer):
    def __init__(self, payload: Optional[bytes] = b'Test LightPacket Raw Layer'):
        super().__init__()
        self._raw_payload = payload or b''
```

**Parameters:**
- `payload`: Raw bytes payload

**Example:**
```python
from LightPacket.Raw import Raw

raw = Raw(b'\x01\x02\x03\x04')
```

---

## Packet Building Examples

### Basic Packet Construction

```python
from LightPacket.EthernetII import Ethernet
from LightPacket.Raw import Raw
from LightPacket.Arp import ARP

# Build an ARP request packet
packet = Ethernet() / ARP()
packet_bytes = packet.build()

# Build packet with custom MAC addresses
eth = Ethernet(
    src='00:11:22:33:44:55',
    dst='ff:ff:ff:ff:ff:ff',
    ethertype=0x0806
)
arp = ARP(
    opcode=1,
    ipsrc='192.168.1.10',
    ipdst='192.168.1.1'
)
packet = eth / arp

# Build with raw payload
eth = Ethernet()
raw = Raw(b'Custom data')
packet = eth / raw
```

### Stacking Multiple Layers

```python
from LightPacket.EthernetII import Ethernet
from LightPacket.LLC import LLC
from LightPacket.Dot3 import Dot3
from LightPacket.Arp import ARP
from LightPacket.Snap import SNAP
from LightPacket.Stp import STP

# Ethernet over LLC over SNAP
packet = Ethernet() / LLC() / SNAP() / ARP()

# Dot3 with LLC
packet = Dot3() / LLC()

# Dot3 over LLC over STP
packet = Dot3() / LLC() / STP()
```

### STP Packet Example

```python
from LightPacket.EthernetII import Ethernet
from LightPacket.LLC import LLC
from LightPacket.Stp import STP

# Build an STP configuration BPDU
stp_packet = (
    Ethernet(dst='01:80:c2:00:00:00', ethertype=0x0023) /
    LLC(dsap=0x42, ssap=0x42, control=0x03) /
    STP(
        protocol_version=0x00,
        bpdu_type=0x00,
        root_priority=0x8000,
        root_mac='00:11:22:33:44:55',
        bridge_priority=0x8000,
        bridge_mac='00:11:22:33:44:55'
    )
)
```

---

## Packet Parsing

### DetectLayer (`Detect_layer.py`)

Automatically detects and parses packet layers.

```python
from LightPacket import DetectLayer

# Parse raw packet bytes
raw_bytes = b'\xff\xff...'  # your raw packet bytes
parsed = DetectLayer().start(raw_bytes, verbose=True)

# Access parsed fields
if parsed:
    print(parsed)
```

### Individual Layer Parsers

Each layer has its own parser class:

```python

raw_bytes = b'\xff\xff...'

# Parse Ethernet layer
from LightPacket.EthernetII import EthernetParser
result = EthernetParser.load_as_ethernet_layer(raw_bytes, verbose=True)

# Parse ARP layer
from LightPacket.Arp import ArpParser
result = ArpParser.load_as_arp_layer(raw_bytes, verbose=True)

# Parse LLC layer
from LightPacket.LLC import LLCParser
result = LLCParser.load_as_llc_layer(raw_bytes, verbose=True)

# Parse STP layer
from LightPacket.Stp import STPParser
result = STPParser.load_as_stp_layer(raw_bytes, verbose=True)

# Parse VLAN layer (auto-detects and unwraps stacked QinQ tags)
from LightPacket.Vlan import VLANParser
result = VLANParser.load_as_vlan_layer(raw_bytes, verbose=True)
```

---

## Packet Sending and Receiving

### L2Socket (Cross-platform, libpcap/Npcap)

`L2Socket` is the classic cross-platform socket that uses libpcap (or Npcap on Windows). It offers `srp1`, `srp`, `recvl2`, and `set_filter`.

**Linux/macOS/BSD:**
```python
from LightPacket import L2Socket
sock = L2Socket(iface='eth0', promisc=True, snaplen=65535)
```

**Windows:**
```python
from LightPacket import L2Socket
sock = L2Socket(iface=r'\Device\NPF_{GUID}')
```

#### Socket Methods

| Method | Description |
|--------|-------------|
| `sendl2(packet)` | Send a Layer 2 packet |
| `recvl2(count=1, timeout=1.0)` | Receive packets |
| `srp1(packet, timeout=3.0, filter_str=None)` | Send and receive one response |
| `srp(packet, timeout=3.0, count=1, filter_str=None)` | Send and receive multiple responses |
| `set_filter(filter_str)` | Set BPF filter |
| `close()` | Close the socket |

**Example:**
```python
from LightPacket import L2Socket
from LightPacket.EthernetII import Ethernet
from LightPacket.Arp import ARP

# Create socket
sock = L2Socket()

# Build ARP request
packet = Ethernet() / ARP(
    opcode=1,
    ipsrc='192.168.1.10',
    ipdst='192.168.1.1'
)

# Send and receive response
response = sock.srp1(packet, timeout=3.0, filter_str='arp')

if response:
    print(f"Received: {response.hex()}")

# Close socket
sock.close()
```

#### Advanced Socket Usage

```python
# Send packet and receive multiple responses
responses = sock.srp(
    packet,
    timeout=5.0,
    count=5,
    filter_str='arp and src host 192.168.1.1'
)

# Capture packets
packets = sock.recvl2(count=10, timeout=5.0)

# Set filter to capture only ARP packets
sock.set_filter('arp')
packets = sock.recvl2(count=5)
```

---

### L2Packet (Linux-only, AF_PACKET) — New in 0.0.3

A lightweight alternative that uses the native Linux `AF_PACKET` socket. It is **faster** and has **lower overhead** than the libpcap-based `L2Socket` because it does not go through the pcap library.

```python
from LightPacket.platforms.linux.L2Packet import L2Packet

# Create a raw AF_PACKET socket on the default interface
sock = L2Packet(iface='eth0', nonstop=True, snaplen=65535)

# Send a packet (auto-builds if a layer object is passed)
sock.sendl2(packet)

# Receive packets (returns a list of raw bytes)
packets = sock.recvl2(count=5, timeout=2.0)

# Set a BPF filter
sock.set_filter('arp and host 192.168.1.1')

# Close the socket
sock.close()
```

**Parameters:**
- `iface`: Network interface name (auto-detected if `None`)
- `nonstop`: If `True`, the socket is blocking; if `False`, non-blocking (affects direct `.recv()` calls)
- `snaplen`: Maximum number of bytes to capture per packet

**Methods:**
- `sendl2(packet)` – Send a packet (bytes or layer object)
- `recvl2(count, timeout)` – Receive up to `count` packets (use `count=0` for unlimited) within `timeout` seconds
- `set_filter(filter_str)` – Compile and attach a BPF filter (requires libpcap)
- `close()` – Close the socket

> **Note:** `L2Packet` is **Linux-only** and does not support `srp1`/`srp` out-of-the-box – you can implement your own request-response logic using `sendl2` and `recvl2` with a filter. If you need full send-and-receive semantics, use `L2Socket` instead.

---

## BPF Filter Compilation

Both `L2Socket` and `L2Packet` support BPF filters via `set_filter()`. The library uses libpcap (or `tcpdump` fallback) to compile the filter string. You can also manually compile filters using `bpf.py`:

```python
from LightPacket.bpf import get_bpf_bytes

# Get a raw BPF program (used internally)
filter_bytes, bp = get_bpf_bytes('arp', 'eth0')
```

---

## PCAP File Operations

### Writing PCAP Files (`pcapwriter.py`)

```python
from LightPacket import PcapWrite

# Write a single packet
packet_data = b'\xff\xff\xff\xff\xff\xff...'
PcapWrite(packet_data, 'output.pcap')

# Write multiple packets
packets = [packet1, packet2, packet3]
PcapWrite(packets, 'output.pcap')
```

### Reading PCAP Files (`pcapreader.py`)

```python
from LightPacket import PcapRead

# Read PCAP file
packets = PcapRead('capture.pcap')

for packet in packets:
    print(f"Timestamp: {packet['ts_sec']}.{packet['ts_usec']}")
    print(f"Length: {packet['incl_len']} bytes")
    print(f"Data: {packet['data'].hex()[:50]}...")
```

---

## Interface Management

### Linux Interfaces (`LinuxInterfaces.py`)

```python
from LightPacket import NetworkInterfaces

# Get all interfaces
interfaces = NetworkInterfaces()

# List interfaces
for name, iface in interfaces.items():
    print(f"{name}: {iface['ips_v4']}")

# Get default interface
default = interfaces.default_interface()
print(default['name'], default['mac'])

# Display interfaces
interfaces.show()
```

**Functions:**
- `get_default_interface_mac_linux()` - Get default interface MAC
- `get_default_interface_ip_linux()` - Get default interface IP
- `get_default_gateway_ipv4_linux()` - Get default IPv4 gateway
- `get_default_gateway_ipv6_linux()` - Get default IPv6 gateway
- `get_default_interface_name_linux()` - Get default interface name

### Windows Interfaces (`WinInterfaces.py`)

```python
from LightPacket import NetworkInterfaces

# Get all interfaces
interfaces = NetworkInterfaces()

# Get default interface
default = interfaces.default_interface()
print(default['name'], default['guid'])

# Get Npcap interface name
from LightPacket import get_default_interface_npcap_name_windows
npcap_name = get_default_interface_npcap_name_windows()
```

**Functions:**
- `get_default_interface_mac_windows()` - Get default interface MAC
- `get_default_interface_ip_windows()` - Get default interface IP
- `get_default_gateway_ipv4_windows()` - Get default IPv4 gateway
- `get_default_gateway_ipv6_windows()` - Get default IPv6 gateway
- `get_default_interface_npcap_name_windows()` - Get Npcap device name

### macOS / BSD Interfaces (`UnixInterfaces.py`, `LibpcapInterfacesUnix.py`)

Full IPv4/IPv6 interface enumeration for macOS, FreeBSD, OpenBSD, and NetBSD, backed by libpcap with `ifconfig`/`route` fallbacks.

```python
from LightPacket import NetworkInterfaces

# Get all interfaces (uses netifaces if available, falls back to ifconfig)
interfaces = NetworkInterfaces()

# List interfaces
for name, iface in interfaces.items():
    print(f"{name}: {iface['ips_v4']}")

# Get default interface
default = interfaces.default_interface()
print(default['name'])

# Display interfaces
interfaces.show()
```

**libpcap-based enumeration (`UnixInterfaces.py`):**
```python
from LightPacket import (
    get_bsd_adapter_list,
    get_bsd_available_interfaces,
    get_bsd_available_interfaces_pretify,
    get_interface_info_bsd,
    get_interface_mac_bsd,
    get_interface_ipv4_addresses_bsd,
    get_interface_ipv6_addresses_bsd,
    get_default_interface_bsd,
    get_default_gateway_bsd,
    get_best_route_bsd,
)

# List all adapters discovered via libpcap (pcap_findalldevs)
adapters = get_bsd_adapter_list()

# Get a name-keyed dict merging pcap + system info
interfaces = get_bsd_available_interfaces()

# Pretty-print all interfaces to stdout
get_bsd_available_interfaces_pretify()

# Get full info (MAC, index, IPv4/IPv6) for one interface
info = get_interface_info_bsd('en0')

# Get the default outbound interface, its gateway, and best route to a host
default_iface = get_default_interface_bsd()
gateway = get_default_gateway_bsd()
route = get_best_route_bsd('8.8.8.8')
```

**Functions:**
- `get_interface_mac_bsd(name)` - Get an interface's MAC address via `ifconfig`
- `get_interface_ipv4_addresses_bsd(name)` - Get an interface's IPv4 addresses
- `get_interface_ipv6_addresses_bsd(name)` - Get an interface's IPv6 addresses
- `get_default_interface_bsd()` - Get the default outbound interface's full info
- `get_default_gateway_bsd()` - Get the default gateway (via `route -n get default`)
- `get_best_route_bsd(dest_ip)` - Get the best route to a destination IPv4/IPv6 address
- `get_bsd_simple_interfaces()` - Get a `NetworkInterfaces` instance (simple enumeration)
- `get_bsd_simple_interface_names()` - Get a list of interface names
- `get_bsd_simple_default_interface()` - Get the default interface (simple enumeration)

---

## Constants (`Consts.py`)

### EtherType Values

```python
from LightPacket import ETHERTYPE, IPv4, IPv6, Q_IN_Q

# Access dictionary
print(ETHERTYPE[0x0800])  # (IPv4)

# Use constants
ethertype = IPv4  # 0x0800
ethertype = Q_IN_Q  # 0x0806
ethertype = IPv6  # 0x86DD
```

### MAC Address Constants

```python
from LightPacket import BROADCAST_MAC, NULL_MAC

broadcast = BROADCAST_MAC  # 'ff:ff:ff:ff:ff:ff'
null_mac = NULL_MAC        # '00:00:00:00:00:00'
```

### LLC/SNAP Constants

```python
from LightPacket import SAP_LLC_SNAP, LLC_UI

dsap = SAP_LLC_SNAP  # 0xAA
control = LLC_UI     # 0x03
```

### SAP Values Dictionary

```python
from LightPacket import SAP_VALUES

print(SAP_VALUES[0xAA])  # "SNAP (Subnetwork Access Protocol)"
```

### STP Constants

```python
from LightPacket.Stp import STP

# STP BPDU types
# 0x00 = Configuration BPDU
# 0x80 = Topology Change Notification (TCN)
# 0x02 = RSTP BPDU
```

---

## MAC Address Utilities (`Mac.py`)

```python
from LightPacket import MacAddress

# Create from string
mac = MacAddress('00:11:22:33:44:55')

# Create from bytes
mac = MacAddress(b'\x00\x11\x22\x33\x44\x55')

# Convert to string
mac_str = str(mac)  # '00:11:22:33:44:55'

# Convert to bytes
mac_bytes = bytes(mac)  # b'\x00\x11\x22\x33\x44\x55'
```

---

## IP Address Utilities (`IPtoa.py`)

```python
from LightPacket import inet_aton, inet_ntoa, ipv6_bytes_to_str, ipv6_str_to_bytes

# IPv4
ip_bytes = inet_aton('192.168.1.1')  # b'\xc0\xa8\x01\x01'
ip_str = inet_ntoa(b'\xc0\xa8\x01\x01')  # '192.168.1.1'

# IPv6
ip_bytes = ipv6_str_to_bytes('2001:db8::1')
ip_str = ipv6_bytes_to_str(ip_bytes)
```

---

## Hex Dump Utility (`Hex.py`)

```python
from LightPacket import hexdump

data = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
print(hexdump(data))

# Output:
# 0x0000: 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff  ."3DUfw........
```

---

## Packet Display and Debugging

### Show Packet Structure

```python
# Create a packet
packet = Ethernet() / Arp()

# Display packet structure with colors
packet.show()

# Output:
# --- [ EthernetLayer ] ---
#    dst=ff:ff:ff:ff:ff:ff
#    src=auto-detected-mac
#    type=0x0806 (ARP)
#    \
#       --- [ ArpLayer ] ---
#          hwtype=1
#          ptype=0x0800
#          maclen=6
#          plen=4
#          opcode=1
#          macsrc=auto-detected-mac
#          ipsrc=auto-detected-ip
#          macdst=ff:ff:ff:ff:ff:ff
#          ipdst=auto-detected-gateway
```

### Layer Representation

```python
# Print layer object
print(Ethernet())
# <Ethernet dst=ff:ff:ff:ff:ff:ff src=aa:bb:cc:dd:ee:ff type=0x0806 (ARP) len=14 (bytes)>

print(ARP())
# <Arp opcode=1 plen=4 ptype=0x0800 maclen=6 hwtype=1 macsrc=aa:bb:cc:dd:ee:ff ipsrc=192.168.1.10 macdst=ff:ff:ff:ff:ff:ff ipdst=192.168.1.1>

print(Raw(b'\x01\x02\x03'))
# <Raw payload=b'\x01\x02\x03' len=3>

print(STP())
# <STP protoid=0x0000 version=0x00 type=Config flags=0x00 root_prio=32768 root_mac=00:11:22:33:44:55 cost=0 bridge_prio=32768 bridge_mac=00:11:22:33:44:55 port=0x8001 age=0 max_age=5120 hello=512 fwd_delay=3840 len=35>
```

---

## Error Handling

### Custom Error Classes (`Errors.py`)

```python
from LightPacket.Logger.Errors import (
    LightPacketError,
    InvalidDataLengthError,
    InvalidMacAddressError,
    InvalidIPAddressError,
    InvalidDataTypeError
)
from LightPacket import MacAddress

try:
    mac = MacAddress('invalid_mac')
except InvalidMacAddressError as e:
    print(f"MAC Error: {e}")
```

### Logger Usage (`LightLogger.py`)

```python
from LightPacket.Logger.LightLogger import Logger, ErrorCode, WarningCode

logger = Logger()

# Raise error
logger.error(
    message="Invalid MAC address",
    error_code=ErrorCode.INVALID_MAC
)

# Log warning
logger.warning(
    message="Non-hexadecimal value",
    warning_code=WarningCode.NONHEXVALUE
)
```

**Error Codes:**
- `E001`: Invalid MAC Address
- `E002`: Invalid Data Type
- `E003`: Invalid Data Length
- `E004`: Invalid IP Address
- `E005`: NotFoundError
- `E006`: CannotCompileBPF

**Warning Codes:**
- `W001`: Non-Hexadecimal Value

---

## Complete Usage Examples

### ARP Scanner using `L2Socket`

```python
from LightPacket import L2Socket
from LightPacket.Arp import ARP
from LightPacket.EthernetII import Ethernet
import time

def arp_scan(ip_range='192.168.1.1'):
    """Simple ARP scanner"""
    sock = L2Socket()
    responses = []

    # Build base Ethernet/ARP request
    eth = Ethernet()

    for ip in ip_range:
        arp = ARP(
            opcode=1,  # request
            ipdst=ip
        )
        packet = eth / arp

        # Send and wait for response
        response = sock.srp1(packet, timeout=1.0, filter_str='arp')

        if response:
            # Parse response
            from LightPacket import DetectLayer
            parsed = DetectLayer().start(response)
            if parsed:
                print(f"{ip} is at {parsed[ARP].macsrc}")
                responses.append((ip, parsed[ARP].macsrc))

        time.sleep(0.1)

    sock.close()
    return responses

# Run scan
arp_scan(['192.168.1.1', '192.168.1.10', '192.168.1.254'])
```

### ARP Scanner using `L2Packet` (Linux)

```python
from LightPacket.platforms.linux.L2Packet import L2Packet
from LightPacket import DetectLayer
from LightPacket.Arp import ARP
from LightPacket.EthernetII import Ethernet
import time

def arp_scan_linux(ip):
    sock = L2Packet()
    packet = (Ethernet() / ARP(ipdst=ip)).build()
    sock.sendl2(packet)
    # Wait for reply
    time.sleep(0.5)
    packets = sock.recvl2(count=1, timeout=1.0)
    sock.close()
    for raw in packets:
        parsed = DetectLayer().start(raw)
        if parsed and parsed[ARP].opcode == 2:
            return parsed[ARP].macsrc
    return None
```

### Packet Sniffer

```python
from LightPacket import L2Socket, DetectLayer

def sniff_packets(interface=None, count=10, filter_str=None):
    """Simple packet sniffer"""
    sock = L2Socket(iface=interface)

    if filter_str:
        sock.set_filter(filter_str)

    packets = sock.recvl2(count=count, timeout=5.0)

    for raw_packet in packets:
        parsed = DetectLayer().start(raw_packet, verbose=True)
        print("-" * 60)

    sock.close()
    return packets

# Sniff ARP packets
sniff_packets(filter_str='arp', count=5)

# Sniff on specific interface
sniff_packets(interface='eth0', count=10)
```

### STP Packet Generation

```python
from LightPacket import L2Socket
from LightPacket.EthernetII import Ethernet
from LightPacket.LLC import LLC
from LightPacket.Stp import STP

def send_stp_bpdu():
    """Send an STP configuration BPDU"""

    # Build STP packet
    stp_packet = (
        Ethernet(
            dst='01:80:c2:00:00:00',
            src='00:11:22:33:44:55',
            ethertype=0x0023
        ) /
        LLC(dsap=0x42, ssap=0x42, control=0x03) /
        STP(
            protocol_version=0x00,
            bpdu_type=0x00,
            root_priority=0x8000,
            root_mac='00:11:22:33:44:55',
            root_path_cost=0,
            bridge_priority=0x8000,
            bridge_mac='00:11:22:33:44:55',
            port_id=0x8001,
            max_age=5120,
            hello_time=512,
            forward_delay=3840
        )
    )

    # Send packet
    sock = L2Socket()
    result = sock.sendl2(stp_packet)
    sock.close()

    return result

# Send STP BPDU
send_stp_bpdu()
```

### Custom Packet Sender

```python
from LightPacket import L2Socket
from LightPacket.EthernetII import Ethernet
from LightPacket.Raw import Raw

def send_custom_data(mac_dst, mac_src, data):
    """Send custom data packet"""
    eth = Ethernet(
        dst=mac_dst,
        src=mac_src,
        ethertype=0x1234  # Custom EtherType
    )
    raw = Raw(data)
    packet = eth / raw

    sock = L2Socket()
    result = sock.sendl2(packet)
    sock.close()

    return result

# Send custom data
send_custom_data(
    mac_dst='ff:ff:ff:ff:ff:ff',
    mac_src='00:11:22:33:44:55',
    data=b'Hello Network!'
)
```

### PCAP File Processing

```python
from LightPacket import PcapRead, PcapWrite, DetectLayer
from LightPacket.Arp import ARP

def process_pcap(input_file, output_file, filter_type=None):
    """Read a PCAP file, parse packets, and write filtered packets"""

    # Read packets from PCAP file
    packets = PcapRead(input_file)
    filtered_packets = []

    for packet in packets:
        # Parse the packet
        parsed = DetectLayer().start(packet['data'])

        # Filter packets (example: only ARP packets)
        if filter_type == 'arp' and ARP in parsed:
            filtered_packets.append(packet['data'])
        elif filter_type is None:
            filtered_packets.append(packet['data'])

    # Write filtered packets to new PCAP file
    if filtered_packets:
        PcapWrite(filtered_packets, output_file)
        print(f"Wrote {len(filtered_packets)} packets to {output_file}")

    return filtered_packets

# Extract all ARP packets from a capture file
arp_packets = process_pcap('capture.pcap', 'arp_only.pcap', filter_type='arp')
```

---

## Platform-Specific Notes

### Linux

- Requires `libpcap-dev` package
- `L2Packet` provides native AF_PACKET support (new in 0.0.3)
- Default interface is automatically detected using `/sys/class/net/` and `ip` commands
- Supports both IPv4 and IPv6
- Uses `ip` command for routing information

### Windows

- Requires Npcap installation
- Only `L2Socket` (Npcap) is available
- Uses GUID-based interface names
- Npcap device names format: `\Device\NPF_{GUID}`
- Loopback interface: `\Device\NPF_Loopback`
- Uses Windows API for interface enumeration

### macOS / BSD

- Only `L2Socket` (libpcap) is available
- Requires `libpcap` (bundled on macOS at `/usr/lib/libpcap.dylib`; install via package manager on FreeBSD/OpenBSD/NetBSD)
- Interface enumeration uses `pcap_findalldevs()` with `ifconfig`/`route`/`netstat` fallbacks
- Default interface detected via `route -n get default`
- Supports both IPv4 and IPv6
- Loopback interface name: `lo` (via `get_loopback_interface_name()`)

---

## Version Information

```python
from LightPacket import version, __version__

print(f"LightPacket version: {version}")          # '0.0.3'
print(f"Package version: {__version__}")          # '0.0.3'
```

---

## License

LightPacket is released under the Mozilla Public License 2.0.

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## Support

- **Bug Reports**: [GitHub Issues](https://github.com/Light-Projects/LightPacket/issues)
- **Source Code**: [GitHub Repository](https://github.com/Light-Projects/LightPacket)

---

## Author

- **Adam Boulaaz** - *Initial work* - [GitHub](https://github.com/adamboulaaz92-jpg)