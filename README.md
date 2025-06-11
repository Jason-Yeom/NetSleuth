# Netoster 🕵️‍♂️

**Netoster: Your Network Detective**

A powerful (maybe?), cross-platform network scanner with device identification and speculation capabilities. Built in Python with both GUI and CLI interfaces, Netoster discovers devices on your network and intelligently identifies their types, vendors, and running services. Its my first github project.

## ✨ Features

- 🔍 **Dual Scanning Modes**: ARP scanning (admin) and Ping scanning (standard)
- 🎯 **Device Identification**: Intelligent speculation of device types (smartphones, computers, IoT devices, etc.)
- 🏷️ **Vendor Detection**: MAC address-based vendor identification
- 🌐 **Hostname Resolution**: Automatic hostname lookup for discovered devices
- 🔌 **Port Scanning**: Quick scan of common ports and services
- 🖥️ **Cross-Platform**: Works on Windows, macOS, and Linux
- 📱 **Interactive GUI**: User-friendly interface with detailed device information
- ⚡ **Fast & Efficient**: Multi-threaded scanning for quick results
- 🔒 **Permission Aware**: Graceful fallback when admin privileges unavailable

## 🚀 Installation

### Prerequisites

# Install Python 3.7 or higher
python3 --version
# Install required packages
pip install scapy tkinter

### Quick Start

1. **Clone or download** the Netoster script
2. **Run with full privileges** for best results:

**Linux/macOS(I LIKE LINUX!!!!!!):**
sudo python3 Netoster.py

_at the place where you downloaded the code_

**Windows:**
Right-click Command Prompt → "Run as Administrator"

python Netoster.py

## 🎮 Usage

### GUI Mode (Default)

1. Launch Netoster
2. Enter your network range (e.g., `192.168.1.1/24`)
3. Click **🔍 Scan Network**
4. View discovered devices in the table
5. Click on any device for detailed information

info)
Finding Your Network Range:

Linux/macOS:
ip route show default

Windows:
ipconfig


Common network ranges:
- `192.168.1.1/24`
- `192.168.0.1/24` 
- `192.168.219.1/24`
- `10.0.0.1/24`

## 📊 What Netoster Discovers

| Information | Description |
|-------------|-------------|
| **IP Address** | Device network address |
| **MAC Address** | Hardware identifier (ARP mode only) |
| **Vendor** | Device manufacturer |
| **Device Type** | Intelligent speculation (iPhone, Router, Printer, etc.) |
| **Hostname** | Network name resolution |
| **Open Ports** | Running services and protocols |

## 🔧 Scanning Modes

### Full Mode (Administrator/sudo)
- ✅ ARP scanning with MAC addresses
- ✅ Complete vendor identification
- ✅ Full device speculation
- ✅ Comprehensive network mapping

### Limited Mode (Standard user)
- ✅ Ping-based device discovery
- ✅ Hostname resolution
- ✅ Port scanning
- ❌ No MAC addresses or vendor info

## 🛠️ Troubleshooting

### "Permission denied" errors

Linux/macOS:
sudo python3 Netoster.py

Windows:
Run Command Prompt as Administrator

### GUI won't start (Linux)

export DISPLAY=:0.0
sudo -E python3 Netoster.py

### No devices found
- ✅ Check you're scanning the correct network range
- ✅ Ensure you're connected to WiFi/network
- ✅ Try running with administrator privileges

### Import errors

Install missing dependencies

pip install scapy
pip install tk # If tkinter missing


## 🎯 Device Types Netoster Can Identify

- 📱 **Mobile Devices**: iPhones, Android phones, tablets
- 💻 **Computers**: Laptops, desktops, MacBooks
- 🌐 **Network Equipment**: Routers, switches, access points
- 🖨️ **Printers**: HP, Canon, network printers
- 📺 **Media Devices**: Smart TVs, Roku, Chromecast, Apple TV
- 🏠 **IoT Devices**: Smart home devices, Raspberry Pi
- 🎮 **Gaming**: Consoles, gaming devices

## 📋 Requirements

- **Python**: 3.7 or higher
- **Scapy**: For network packet manipulation
- **Tkinter**: For GUI (usually included with Python)
- **Threading**: For concurrent operations
- **Socket**: For network operations

## 🔒 Security & Ethics

Netoster is designed for:
- ✅ **Your own networks**
- ✅ **Authorized network administration**
- ✅ **Security auditing with permission**
- ✅ **Educational purposes**

**Please use responsibly and only on networks you own or have explicit permission to scan.**

## 🤝 Contributing

We welcome contributions! Areas for improvement:

- 🔧 Enhanced device fingerprinting
- 🌐 Additional vendor databases
- 📊 Export functionality (CSV, JSON)
- 🎨 UI/UX improvements
- 🐛 Bug fixes and optimizations

## 📄 License

This project is open source and available under the GNU GENERAL PUBLIC LICENSE 3.0.

## 🙏 Acknowledgments

- Inspired by **Fing** network discovery tool
- Built with **Scapy** for network operations
- **Python** and **Tkinter** for cross-platform compatibility
- I am **Korean** _*I added this just for fun*_

## 📞 Support

Having issues? Check the troubleshooting section above or create an issue with:
- Your operating system
- Python version (`python3 --version`)
- Error message (if any)
- Network configuration

---

**Netoster** - Solving your network mysteries, one device at a time! 🕵️‍♂️✨
