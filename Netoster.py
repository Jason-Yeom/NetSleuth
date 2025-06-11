#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import scapy.all as scapy
import socket
import subprocess
import platform
import os
import ctypes
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Set display if needed
if os.environ.get('DISPLAY', '') == '':
    print('No display found. Using :0.0')
    os.environ['DISPLAY'] = ':0.0'

class FingLikeScanner:
    def __init__(self, root, has_admin_privileges=True):
        self.root = root
        self.has_admin = has_admin_privileges
        self.root.title(f"Netoster: Solving Your Network Mysteries - {'Full Mode' if has_admin_privileges else 'Limited Mode'}")
        self.root.geometry("800x600")

        # Device database for speculation - FIXED MISSING BRACE
        self.device_signatures = {
            'apple': ['iPhone', 'iPad', 'MacBook', 'iMac', 'Apple TV'],
            'samsung': ['Galaxy', 'Samsung TV', 'Samsung Smart'],
            'google': ['Pixel', 'Nest', 'Chromecast'],
            'amazon': ['Echo', 'Fire TV', 'Kindle'],
            'cisco': ['Router', 'Switch', 'Access Point'],
            'tp-link': ['Router', 'Range Extender'],
            'raspberry': ['Raspberry Pi']
        }  # ← FIXED: Added missing closing brace

        self.setup_ui()
        self.devices = []

        # Show permission warning if not admin
        if not self.has_admin:
            self.show_permission_warning()

    def show_permission_warning(self):
        """Show permission warning in the GUI"""
        warning_frame = ttk.Frame(self.root)
        warning_frame.pack(fill=tk.X, padx=10, pady=5)

        warning_text = "⚠️ Limited Mode: Run as Administrator/sudo for full ARP scanning with MAC addresses"
        warning_label = ttk.Label(warning_frame, text=warning_text, foreground="orange")
        warning_label.pack()

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(main_frame, text="Network Range (e.g., 192.168.1.1/24):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.network_entry = ttk.Entry(main_frame, width=30)
        self.network_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        self.network_entry.insert(0, "192.168.1.1/24")

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=3, pady=10)

        self.scan_btn = ttk.Button(button_frame, text="🔍 Scan Network", command=self.start_scan)
        self.scan_btn.grid(row=0, column=0, padx=5)

        self.refresh_btn = ttk.Button(button_frame, text="🔄 Refresh", command=self.refresh_scan)
        self.refresh_btn.grid(row=0, column=1, padx=5)

        self.clear_btn = ttk.Button(button_frame, text="🗑️ Clear", command=self.clear_results)
        self.clear_btn.grid(row=0, column=2, padx=5)

        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)

        self.status_label = ttk.Label(main_frame, text="Ready to scan...")
        self.status_label.grid(row=3, column=0, columnspan=3, sticky=tk.W, pady=5)

        columns = ('IP', 'MAC', 'Vendor', 'Device Type', 'Hostname', 'Ports')
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=15)

        for col in columns:
            self.tree.heading(col, text=col)

        self.tree.column('IP', width=120)
        self.tree.column('MAC', width=140)
        self.tree.column('Vendor', width=100)
        self.tree.column('Device Type', width=120)
        self.tree.column('Hostname', width=100)
        self.tree.column('Ports', width=100)

        self.tree.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.grid(row=4, column=3, sticky=(tk.N, tk.S), pady=5)
        self.tree.configure(yscrollcommand=scrollbar.set)

        details_frame = ttk.LabelFrame(main_frame, text="Device Details", padding="5")
        details_frame.grid(row=5, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)

        self.details_text = scrolledtext.ScrolledText(details_frame, height=8, width=80)
        self.details_text.pack(fill=tk.BOTH, expand=True)

        # FIXED: Correct tree binding syntax
        self.tree.bind('<<TreeviewSelect>>', self.on_device_select)

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)

    def start_scan(self):
        network = self.network_entry.get().strip()
        if not network:
            messagebox.showerror("Error", "Please enter a network range")
            return

        self.scan_btn.config(state='disabled')
        self.progress.start()
        self.status_label.config(text="Scanning network...")

        scan_thread = threading.Thread(target=self.scan_network, args=(network,))
        scan_thread.daemon = True
        scan_thread.start()

    def scan_network(self, network):
        if self.has_admin:
            self.scan_network_arp(network)
        else:
            self.scan_network_ping(network)

    def scan_network_arp(self, network):
        try:
            self.devices = []
            arp_request = scapy.ARP(pdst=network)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

            for element in answered_list:
                device = {
                    'ip': element[1].psrc,
                    'mac': element[1].hwsrc,
                    'vendor': self.get_vendor(element[1].hwsrc),
                    'device_type': 'Unknown',
                    'hostname': 'Unknown',
                    'ports': []
                }

                device['hostname'] = self.get_hostname(device['ip'])
                device['device_type'] = self.speculate_device_type(device)
                device['ports'] = self.quick_port_scan(device['ip'])

                self.devices.append(device)

            self.root.after(0, self.update_results)

        except Exception as e:
            error_msg = f"ARP scan error: {str(e)}"
            self.root.after(0, lambda: self.show_error(error_msg))

    def scan_network_ping(self, network):
        try:
            base_ip = '.'.join(network.split('/')[0].split('.')[:-1])
            self.devices = []
            alive_ips = []

            def ping_host(ip):
                try:
                    if platform.system() == "Windows":
                        result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip],
                                              capture_output=True, text=True, timeout=2)
                    else:
                        result = subprocess.run(['ping', '-c', '1', '-W', '1000', ip],
                                              capture_output=True, text=True, timeout=2)
                    return ip if result.returncode == 0 else None
                except:
                    return None

            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(ping_host, f"{base_ip}.{i}") for i in range(1, 255)]
                for future in futures:
                    result = future.result()
                    if result:
                        alive_ips.append(result)

            for ip in alive_ips:
                device = {
                    'ip': ip,
                    'mac': 'N/A (ping scan)',
                    'hostname': self.get_hostname(ip),
                    'vendor': 'Unknown',
                    'device_type': 'Unknown',
                    'ports': self.quick_port_scan(ip)
                }
                device['device_type'] = self.speculate_device_type(device)
                self.devices.append(device)

            self.root.after(0, self.update_results)

        except Exception as e:
            error_msg = f"Ping scan error: {str(e)}"
            self.root.after(0, lambda: self.show_error(error_msg))

    def get_vendor(self, mac):
        try:
            oui = mac.replace(':', '').upper()[:6]
            vendor_map = {
                '001122': 'Cisco',
                'AABBCC': 'Apple',
                'DDEEFF': 'Samsung',
                '001CF0': 'Apple',
                '0050E4': 'Apple',
                'B4B5FE': 'Apple',
                '3C0754': 'Apple',
                '8CFABA': 'Apple'
            }
            return vendor_map.get(oui, 'Unknown')
        except:
            return 'Unknown'

    def get_hostname(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return 'Unknown'

    def speculate_device_type(self, device):
        vendor = device['vendor'].lower()
        hostname = device['hostname'].lower()

        for key, types in self.device_signatures.items():
            if key in vendor or key in hostname:
                if 'apple' in key:
                    if any(x in hostname for x in ['iphone', 'ipad']):
                        return 'Mobile Device'
                    elif any(x in hostname for x in ['macbook', 'imac']):
                        return 'Computer'
                    elif 'apple-tv' in hostname:
                        return 'Media Device'
                    else:
                        return 'Apple Device'
                elif 'samsung' in key:
                    return 'Samsung Device'
                elif 'cisco' in key:
                    return 'Network Equipment'
                elif 'raspberry' in key or 'raspberrypi' in hostname:
                    return 'IoT Device'

        if any(x in hostname for x in ['router', 'gateway']):
            return 'Router'
        elif any(x in hostname for x in ['printer', 'hp-', 'canon-']):
            return 'Printer'
        elif any(x in hostname for x in ['tv', 'roku', 'chromecast']):
            return 'Media Device'
        elif any(x in hostname for x in ['phone', 'android', 'samsung']):
            return 'Mobile Device'

        return 'Unknown Device'

    def quick_port_scan(self, ip):
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        open_ports = []

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass

        return open_ports

    def update_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for device in self.devices:
            ports_str = ', '.join(map(str, device['ports'][:3]))
            if len(device['ports']) > 3:
                ports_str += '...'

            self.tree.insert('', 'end', values=(
                device['ip'],
                device['mac'],
                device['vendor'],
                device['device_type'],
                device['hostname'],
                ports_str
            ))

        self.progress.stop()
        self.scan_btn.config(state='normal')
        self.status_label.config(text=f"Scan complete. Found {len(self.devices)} devices.")

    def on_device_select(self, event):
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            values = item['values']

            device = None
            for d in self.devices:
                if d['ip'] == values[0]:
                    device = d
                    break

            if device:
                details = f"""Device Details for {device['ip']}
{'='*50}
IP Address: {device['ip']}
MAC Address: {device['mac']}
Vendor: {device['vendor']}
Device Type: {device['device_type']}
Hostname: {device['hostname']}
Open Ports: {', '.join(map(str, device['ports'])) if device['ports'] else 'None detected'}

Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
                self.details_text.delete(1.0, tk.END)
                self.details_text.insert(1.0, details)

    def refresh_scan(self):
        self.start_scan()

    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.details_text.delete(1.0, tk.END)
        self.devices = []
        self.status_label.config(text="Results cleared.")

    def show_error(self, message):
        self.progress.stop()
        self.scan_btn.config(state='normal')
        self.status_label.config(text="Scan failed.")
        messagebox.showerror("Error", message)


def check_permissions():
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return os.geteuid() == 0


def main():
    has_admin = check_permissions()

    if not has_admin:
        print("⚠️ This tool requires elevated privileges:")
        if platform.system() == "Windows":
            print("   Right-click Command Prompt → 'Run as Administrator'")
        else:
            print("   Run with: sudo python3 script.py")
    else:
        print("✅ Running with administrator privileges - Full ARP scanning available")

    root = tk.Tk()
    app = FingLikeScanner(root, has_admin_privileges=has_admin)
    root.mainloop()


if __name__ == "__main__":
    main()
