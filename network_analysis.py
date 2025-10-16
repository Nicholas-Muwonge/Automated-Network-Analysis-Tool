import subprocess
import json
import pandas as pd
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import ipaddress
from datetime import datetime
import os

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Packet capture features disabled.")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_analysis.log'),
        logging.StreamHandler()
    ]
)

@dataclass
class NetworkDevice:
    """Data class to store device information"""
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    open_ports: List[Dict] = None
    os_info: Optional[str] = None
    last_seen: Optional[str] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []

class NetworkAnalyzer:
    
    def __init__(self, target_network: str = None, interface: str = None):
        self.target_network = target_network or self._detect_network()
        self.interface = interface or self._detect_interface()
        self.discovered_devices: Dict[str, NetworkDevice] = {}
        self.packets_captured = []
        
        logging.info(f"Initialized NetworkAnalyzer for network: {self.target_network}")
    
    def _detect_network(self) -> str:
        try:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'default' in line:
                    parts = line.split()
                    if len(parts) >= 8:
                        return parts[2] + '/24'  # Assuming /24 subnet
        except Exception as e:
            logging.warning(f"Could not auto-detect network: {e}")
        
        return "192.168.1.0/24"  
    def _detect_interface(self) -> str:
        """Detect primary network interface"""
        try:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'default' in line:
                    parts = line.split()
                    return parts[4] if len(parts) > 4 else 'eth0'
        except Exception as e:
            logging.warning(f"Could not auto-detect interface: {e}")
        
        return 'eth0'
    
    def arp_scan(self, timeout: int = 10) -> Dict[str, NetworkDevice]:
        """Perform ARP scan to discover devices on the network"""
        if not SCAPY_AVAILABLE:
            logging.error("Scapy not available for ARP scanning")
            return {}
        
        logging.info(f"Starting ARP scan on {self.target_network}")
        
        try:
            arp_request = ARP(pdst=self.target_network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            answered_list = srp(arp_request_broadcast, timeout=timeout, verbose=False)[0]
            
            for sent, received in answered_list:
                ip_addr = received.psrc
                mac_addr = received.hwsrc
                
                vendor = self._get_vendor_from_mac(mac_addr)
                
                device = NetworkDevice(
                    ip_address=ip_addr,
                    mac_address=mac_addr,
                    vendor=vendor,
                    last_seen=datetime.now().isoformat()
                )
                
                self.discovered_devices[ip_addr] = device
                logging.info(f"Discovered device: {ip_addr} - {mac_addr} - {vendor}")
            
            logging.info(f"ARP scan completed. Found {len(self.discovered_devices)} devices")
            
        except Exception as e:
            logging.error(f"ARP scan failed: {e}")
        
        return self.discovered_devices
    
    def _get_vendor_from_mac(self, mac_address: str) -> str:
        """Get vendor information from MAC address (basic implementation)"""
        vendor_ouis = {
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:1C:42': 'Parallels',
            '00:1D:0F': 'Cisco',
            '00:24:8C': 'Dell',
            '00:25:90': 'Dell',
            '00:26:B9': 'Dell',
            '00:15:5D': 'Microsoft',
            '00:1B:21': 'Intel',
            '00:1C:C0': 'Intel',
            '00:1D:E1': 'Intel',
            '00:23:14': 'Intel',
            '00:25:00': 'Intel',
            '00:26:C7': 'Intel',
            '00:50:BA': 'IBM',
            '00:14:5F': 'IBM',
            '00:04:AC': 'IBM',
            '00:16:76': 'Apple',
            '00:17:F2': 'Apple',
            '00:19:E3': 'Apple',
            '00:1C:B3': 'Apple',
            '00:1D:4F': 'Apple',
            '00:1E:52': 'Apple',
            '00:1E:C2': 'Apple',
            '00:1F:5B': 'Apple',
            '00:1F:F3': 'Apple',
            '00:21:E9': 'Apple',
            '00:22:41': 'Apple',
            '00:23:12': 'Apple',
            '00:23:32': 'Apple',
            '00:23:6C': 'Apple',
            '00:23:DF': 'Apple',
            '00:24:36': 'Apple',
            '00:25:00': 'Apple',
            '00:25:BC': 'Apple',
            '00:26:08': 'Apple',
            '00:26:4A': 'Apple',
            '00:26:B0': 'Apple',
            '00:30:65': 'Apple',
            '00:3E:E1': 'Apple',
            '00:50:F2': 'Apple',
            '00:56:CD': 'Apple',
            '00:61:71': 'Apple',
            '00:88:65': 'Apple',
            '00:A0:40': 'Apple',
            '00:C0:0C': 'Apple',
            '00:C0:0D': 'Apple',
            '00:C0:0E': 'Apple',
            '00:C0:0F': 'Apple',
            '00:C0:10': 'Apple',
            '00:C0:11': 'Apple',
            '00:C0:12': 'Apple',
            '00:C0:13': 'Apple',
            '00:C0:14': 'Apple',
            '00:C0:15': 'Apple',
            '00:C0:16': 'Apple',
            '00:C0:17': 'Apple',
            '00:C0:18': 'Apple',
            '00:C0:19': 'Apple',
            '00:C0:1A': 'Apple',
            '00:C0:1B': 'Apple',
            '00:C0:1C': 'Apple',
            '00:C0:1D': 'Apple',
            '00:C0:1E': 'Apple',
            '00:C0:1F': 'Apple',
            '00:C0:20': 'Apple',
            '00:C0:21': 'Apple',
            '00:C0:22': 'Apple',
            '00:C0:23': 'Apple',
            '00:C0:24': 'Apple',
            '00:C0:25': 'Apple',
            '00:C0:26': 'Apple',
            '00:C0:27': 'Apple',
            '00:C0:28': 'Apple',
            '00:C0:29': 'Apple',
            '00:C0:2A': 'Apple',
            '00:C0:2B': 'Apple',
            '00:C0:2C': 'Apple',
            '00:C0:2D': 'Apple',
            '00:C0:2E': 'Apple',
            '00:C0:2F': 'Apple',
            '00:C0:30': 'Apple',
            '00:C0:31': 'Apple',
            '00:C0:32': 'Apple',
            '00:C0:33': 'Apple',
            '00:C0:34': 'Apple',
            '00:C0:35': 'Apple',
            '00:C0:36': 'Apple',
            '00:C0:37': 'Apple',
            '00:C0:38': 'Apple',
            '00:C0:39': 'Apple',
            '00:C0:3A': 'Apple',
            '00:C0:3B': 'Apple',
            '00:C0:3C': 'Apple',
            '00:C0:3D': 'Apple',
            '00:C0:3E': 'Apple',
            '00:C0:3F': 'Apple',
            '00:C0:40': 'Apple',
            '00:C0:41': 'Apple',
            '00:C0:42': 'Apple',
            '00:C0:43': 'Apple',
            '00:C0:44': 'Apple',
            '00:C0:45': 'Apple',
            '00:C0:46': 'Apple',
            '00:C0:47': 'Apple',
            '00:C0:48': 'Apple',
            '00:C0:49': 'Apple',
            '00:C0:4A': 'Apple',
            '00:C0:4B': 'Apple',
            '00:C0:4C': 'Apple',
            '00:C0:4D': 'Apple',
            '00:C0:4E': 'Apple',
            '00:C0:4F': 'Apple',
            '00:C0:50': 'Apple',
            '00:C0:51': 'Apple',
            '00:C0:52': 'Apple',
            '00:C0:53': 'Apple',
            '00:C0:54': 'Apple',
            '00:C0:55': 'Apple',
            '00:C0:56': 'Apple',
            '00:C0:57': 'Apple',
            '00:C0:58': 'Apple',
            '00:C0:59': 'Apple',
            '00:C0:5A': 'Apple',
            '00:C0:5B': 'Apple',
            '00:C0:5C': 'Apple',
            '00:C0:5D': 'Apple',
            '00:C0:5E': 'Apple',
            '00:C0:5F': 'Apple',
            '00:C0:60': 'Apple',
            '00:C0:61': 'Apple',
            '00:C0:62': 'Apple',
            '00:C0:63': 'Apple',
            '00:C0:64': 'Apple',
            '00:C0:65': 'Apple',
            '00:C0:66': 'Apple',
            '00:C0:67': 'Apple',
            '00:C0:68': 'Apple',
            '00:C0:69': 'Apple',
            '00:C0:6A': 'Apple',
            '00:C0:6B': 'Apple',
            '00:C0:6C': 'Apple',
            '00:C0:6D': 'Apple',
            '00:C0:6E': 'Apple',
            '00:C0:6F': 'Apple',
            '00:C0:70': 'Apple',
            '00:C0:71': 'Apple',
            '00:C0:72': 'Apple',
            '00:C0:73': 'Apple',
            '00:C0:74': 'Apple',
            '00:C0:75': 'Apple',
            '00:C0:76': 'Apple',
            '00:C0:77': 'Apple',
            '00:C0:78': 'Apple',
            '00:C0:79': 'Apple',
            '00:C0:7A': 'Apple',
            '00:C0:7B': 'Apple',
            '00:C0:7C': 'Apple',
            '00:C0:7D': 'Apple',
            '00:C0:7E': 'Apple',
            '00:C0:7F': 'Apple',
            '00:C0:80': 'Apple',
            '00:C0:81': 'Apple',
            '00:C0:82': 'Apple',
            '00:C0:83': 'Apple',
            '00:C0:84': 'Apple',
            '00:C0:85': 'Apple',
            '00:C0:86': 'Apple',
            '00:C0:87': 'Apple',
            '00:C0:88': 'Apple',
            '00:C0:89': 'Apple',
            '00:C0:8A': 'Apple',
            '00:C0:8B': 'Apple',
            '00:C0:8C': 'Apple',
            '00:C0:8D': 'Apple',
            '00:C0:8E': 'Apple',
            '00:C0:8F': 'Apple',
            '00:C0:90': 'Apple',
            '00:C0:91': 'Apple',
            '00:C0:92': 'Apple',
            '00:C0:93': 'Apple',
            '00:C0:94': 'Apple',
            '00:C0:95': 'Apple',
            '00:C0:96': 'Apple',
            '00:C0:97': 'Apple',
            '00:C0:98': 'Apple',
            '00:C0:99': 'Apple',
            '00:C0:9A': 'Apple',
            '00:C0:9B': 'Apple',
            '00:C0:9C': 'Apple',
            '00:C0:9D': 'Apple',
            '00:C0:9E': 'Apple',
            '00:C0:9F': 'Apple',
            '00:C0:A0': 'Apple',
            '00:C0:A1': 'Apple',
            '00:C0:A2': 'Apple',
            '00:C0:A3': 'Apple',
            '00:C0:A4': 'Apple',
            '00:C0:A5': 'Apple',
            '00:C0:A6': 'Apple',
            '00:C0:A7': 'Apple',
            '00:C0:A8': 'Apple',
            '00:C0:A9': 'Apple',
            '00:C0:AA': 'Apple',
            '00:C0:AB': 'Apple',
            '00:C0:AC': 'Apple',
            '00:C0:AD': 'Apple',
            '00:C0:AE': 'Apple',
            '00:C0:AF': 'Apple',
            '00:C0:B0': 'Apple',
            '00:C0:B1': 'Apple',
            '00:C0:B2': 'Apple',
            '00:C0:B3': 'Apple',
            '00:C0:B4': 'Apple',
            '00:C0:B5': 'Apple',
            '00:C0:B6': 'Apple',
            '00:C0:B7': 'Apple',
            '00:C0:B8': 'Apple',
            '00:C0:B9': 'Apple',
            '00:C0:BA': 'Apple',
            '00:C0:BB': 'Apple',
            '00:C0:BC': 'Apple',
            '00:C0:BD': 'Apple',
            '00:C0:BE': 'Apple',
            '00:C0:BF': 'Apple',
            '00:C0:C0': 'Apple',
            '00:C0:C1': 'Apple',
            '00:C0:C2': 'Apple',
            '00:C0:C3': 'Apple',
            '00:C0:C4': 'Apple',
            '00:C0:C5': 'Apple',
            '00:C0:C6': 'Apple',
            '00:C0:C7': 'Apple',
            '00:C0:C8': 'Apple',
            '00:C0:C9': 'Apple',
            '00:C0:CA': 'Apple',
            '00:C0:CB': 'Apple',
            '00:C0:CC': 'Apple',
            '00:C0:CD': 'Apple',
            '00:C0:CE': 'Apple',
            '00:C0:CF': 'Apple',
            '00:C0:D0': 'Apple',
            '00:C0:D1': 'Apple',
            '00:C0:D2': 'Apple',
            '00:C0:D3': 'Apple',
            '00:C0:D4': 'Apple',
            '00:C0:D5': 'Apple',
            '00:C0:D6': 'Apple',
            '00:C0:D7': 'Apple',
            '00:C0:D8': 'Apple',
            '00:C0:D9': 'Apple',
            '00:C0:DA': 'Apple',
            '00:C0:DB': 'Apple',
            '00:C0:DC': 'Apple',
            '00:C0:DD': 'Apple',
            '00:C0:DE': 'Apple',
            '00:C0:DF': 'Apple',
            '00:C0:E0': 'Apple',
            '00:C0:E1': 'Apple',
            '00:C0:E2': 'Apple',
            '00:C0:E3': 'Apple',
            '00:C0:E4': 'Apple',
            '00:C0:E5': 'Apple',
            '00:C0:E6': 'Apple',
            '00:C0:E7': 'Apple',
            '00:C0:E8': 'Apple',
            '00:C0:E9': 'Apple',
            '00:C0:EA': 'Apple',
            '00:C0:EB': 'Apple',
            '00:C0:EC': 'Apple',
            '00:C0:ED': 'Apple',
            '00:C0:EE': 'Apple',
            '00:C0:EF': 'Apple',
            '00:C0:F0': 'Apple',
            '00:C0:F1': 'Apple',
            '00:C0:F2': 'Apple',
            '00:C0:F3': 'Apple',
            '00:C0:F4': 'Apple',
            '00:C0:F5': 'Apple',
            '00:C0:F6': 'Apple',
            '00:C0:F7': 'Apple',
            '00:C0:F8': 'Apple',
            '00:C0:F9': 'Apple',
            '00:C0:FA': 'Apple',
            '00:C0:FB': 'Apple',
            '00:C0:FC': 'Apple',
            '00:C0:FD': 'Apple',
            '00:C0:FE': 'Apple',
            '00:C0:FF': 'Apple',
        }
        
        mac_prefix = mac_address.upper()[:8]
        return vendor_ouis.get(mac_prefix, 'Unknown')
    
    def nmap_scan(self, target: str = None, scan_type: str = "quick") -> Dict[str, Any]:
        """Perform Nmap scan on target device"""
        target = target or self.target_network
        
        logging.info(f"Starting Nmap scan on {target}")
        
        nmap_commands = {
            "quick": "-T4 -F",  # Fast scan
            "standard": "-T4 -A",  # OS and version detection
            "detailed": "-T4 -A -v -p-",  # All ports with verbose output
            "udp": "-T4 -sU -p 53,67,68,69,123,135,137,138,139,161,162,445,514,520,631,1434,1900,4500,49152",  # Common UDP ports
        }
        
        command = f"nmap {nmap_commands.get(scan_type, '-T4 -A')} {target} -oX -"
        
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                return self._parse_nmap_xml(result.stdout)
            else:
                logging.error(f"Nmap scan failed: {result.stderr}")
                return {}
                
        except Exception as e:
            logging.error(f"Nmap execution failed: {e}")
            return {}
    
    def _parse_nmap_xml(self, xml_output: str) -> Dict[str, Any]:
        """Parse Nmap XML output"""
        try:
            import xml.etree.ElementTree as ET
            
            root = ET.fromstring(xml_output)
            scan_results = {}
            
            for host in root.findall('host'):
                # Get IP address
                ip_elem = host.find('address[@addrtype="ipv4"]')
                if ip_elem is None:
                    continue
                
                ip_addr = ip_elem.get('addr')
                host_info = {
                    'ip_address': ip_addr,
                    'hostnames': [],
                    'ports': [],
                    'os_info': {},
                    'status': host.find('status').get('state') if host.find('status') is not None else 'unknown'
                }
                
                hostnames_elem = host.find('hostnames')
                if hostnames_elem:
                    for hostname in hostnames_elem.findall('hostname'):
                        host_info['hostnames'].append({
                            'name': hostname.get('name'),
                            'type': hostname.get('type')
                        })
                
                ports_elem = host.find('ports')
                if ports_elem:
                    for port in ports_elem.findall('port'):
                        port_info = {
                            'port': port.get('portid'),
                            'protocol': port.get('protocol'),
                            'state': port.find('state').get('state') if port.find('state') is not None else 'unknown',
                            'service': {}
                        }
                        
                        service_elem = port.find('service')
                        if service_elem is not None:
                            port_info['service'] = {
                                'name': service_elem.get('name', ''),
                                'product': service_elem.get('product', ''),
                                'version': service_elem.get('version', ''),
                                'extrainfo': service_elem.get('extrainfo', '')
                            }
                        
                        host_info['ports'].append(port_info)
                
                os_elem = host.find('os')
                if os_elem:
                    for os_match in os_elem.findall('osmatch'):
                        os_info = {
                            'name': os_match.get('name'),
                            'accuracy': os_match.get('accuracy')
                        }
                        host_info['os_info'] = os_info
                        break  
                
                scan_results[ip_addr] = host_info
            
            return scan_results
            
        except Exception as e:
            logging.error(f"Failed to parse Nmap XML: {e}")
            return {}
    
    def packet_capture(self, count: int = 100, timeout: int = 30) -> List[Dict]:
        """Capture and analyze network packets"""
        if not SCAPY_AVAILABLE:
            logging.error("Scapy not available for packet capture")
            return []
        
        logging.info(f"Starting packet capture for {count} packets or {timeout} seconds")
        
        try:
            packets = sniff(count=count, timeout=timeout, iface=self.interface)
            analyzed_packets = []
            
            for packet in packets:
                packet_info = self._analyze_packet(packet)
                if packet_info:
                    analyzed_packets.append(packet_info)
            
            self.packets_captured = analyzed_packets
            logging.info(f"Captured and analyzed {len(analyzed_packets)} packets")
            
            return analyzed_packets
            
        except Exception as e:
            logging.error(f"Packet capture failed: {e}")
            return []
    
    def _analyze_packet(self, packet) -> Optional[Dict]:
        """Analyze individual packet and extract relevant information"""
        try:
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'length': len(packet),
                'summary': packet.summary()
            }
            
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_info.update({
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'protocol': ip_layer.proto,
                    'ttl': ip_layer.ttl
                })
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info.update({
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'flags': str(tcp_layer.flags),
                    'payload_size': len(tcp_layer.payload) if tcp_layer.payload else 0
                })
            
            if packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info.update({
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport,
                    'payload_size': len(udp_layer.payload) if udp_layer.payload else 0
                })
            
            if packet.haslayer(ARP):
                arp_layer = packet[ARP]
                packet_info.update({
                    'operation': 'request' if arp_layer.op == 1 else 'reply',
                    'src_mac': arp_layer.hwsrc,
                    'src_ip': arp_layer.psrc,
                    'dst_mac': arp_layer.hwdst,
                    'dst_ip': arp_layer.pdst
                })
            
            return packet_info
            
        except Exception as e:
            logging.warning(f"Failed to analyze packet: {e}")
            return None
    
    def generate_report(self, output_format: str = "all") -> Dict[str, Any]:
        """Generate comprehensive network analysis report"""
        report = {
            'scan_timestamp': datetime.now().isoformat(),
            'target_network': self.target_network,
            'discovered_devices': [],
            'nmap_results': {},
            'packet_analysis': self.packets_captured,
            'summary': {}
        }
        
        for ip, device in self.discovered_devices.items():
            device_dict = {
                'ip_address': device.ip_address,
                'mac_address': device.mac_address,
                'vendor': device.vendor,
                'hostname': device.hostname,
                'open_ports': device.open_ports,
                'os_info': device.os_info,
                'last_seen': device.last_seen
            }
            report['discovered_devices'].append(device_dict)
        
        for device in self.discovered_devices.values():
            nmap_result = self.nmap_scan(device.ip_address, "quick")
            if nmap_result:
                report['nmap_results'][device.ip_address] = nmap_result.get(device.ip_address, {})
        
        report['summary'] = {
            'total_devices': len(self.discovered_devices),
            'total_packets_captured': len(self.packets_captured),
            'devices_with_open_ports': sum(1 for device in report['discovered_devices'] if device.get('open_ports')),
            'scan_duration': 'N/A'  
        }
        
        if output_format in ["json", "all"]:
            self._save_json_report(report)
        
        if output_format in ["csv", "all"]:
            self._save_csv_reports(report)
        
        if output_format in ["html", "all"]:
            self._save_html_report(report)
        
        return report
    
    def _save_json_report(self, report: Dict[str, Any]):
        """Save report as JSON file"""
        filename = f"network_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        logging.info(f"JSON report saved as {filename}")
    
    def _save_csv_reports(self, report: Dict[str, Any]):
        """Save reports as CSV files using Pandas"""
        try:
            if report['discovered_devices']:
                devices_df = pd.DataFrame(report['discovered_devices'])
                devices_filename = f"devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                devices_df.to_csv(devices_filename, index=False)
                logging.info(f"Devices CSV saved as {devices_filename}")
            
            ports_data = []
            for ip, nmap_data in report['nmap_results'].items():
                for port in nmap_data.get('ports', []):
                    ports_data.append({
                        'ip_address': ip,
                        'port': port.get('port'),
                        'protocol': port.get('protocol'),
                        'state': port.get('state'),
                        'service_name': port.get('service', {}).get('name'),
                        'service_product': port.get('service', {}).get('product')
                    })
            
            if ports_data:
                ports_df = pd.DataFrame(ports_data)
                ports_filename = f"ports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                ports_df.to_csv(ports_filename, index=False)
                logging.info(f"Ports CSV saved as {ports_filename}")
            
            if report['packet_analysis']:
                packets_df = pd.DataFrame(report['packet_analysis'])
                packets_filename = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                packets_df.to_csv(packets_filename, index=False)
                logging.info(f"Packets CSV saved as {packets_filename}")
                
        except Exception as e:
            logging.error(f"Failed to save CSV reports: {e}")
    
    def _save_html_report(self, report: Dict[str, Any]):
        """Generate HTML report"""
        try:
            filename = f"network_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Network Analysis Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .section {{ margin-bottom: 30px; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    .summary {{ background-color: #e8f4f8; padding: 15px; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <h1>Network Analysis Report</h1>
                <div class="summary">
                    <h2>Summary</h2>
                    <p><strong>Scan Time:</strong> {report['scan_timestamp']}</p>
                    <p><strong>Target Network:</strong> {report['target_network']}</p>
                    <p><strong>Total Devices Found:</strong> {report['summary']['total_devices']}</p>
                    <p><strong>Packets Captured:</strong> {report['summary']['total_packets_captured']}</p>
                </div>
                
                <div class="section">
                    <h2>Discovered Devices</h2>
                    <table>
                        <tr>
                            <th>IP Address</th>
                            <th>MAC Address</th>
                            <th>Vendor</th>
                            <th>Hostname</th>
                            <th>Last Seen</th>
                        </tr>
            """
            
            for device in report['discovered_devices']:
                html_content += f"""
                        <tr>
                            <td>{device['ip_address']}</td>
                            <td>{device['mac_address'] or 'N/A'}</td>
                            <td>{device['vendor'] or 'Unknown'}</td>
                            <td>{device['hostname'] or 'N/A'}</td>
                            <td>{device['last_seen'] or 'N/A'}</td>
                        </tr>
                """
            
            html_content += """
                    </table>
                </div>
                
                <div class="section">
                    <h2>Open Ports</h2>
                    <table>
                        <tr>
                            <th>IP Address</th>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Product</th>
                        </tr>
            """
            
            for ip, nmap_data in report['nmap_results'].items():
                for port in nmap_data.get('ports', []):
                    if port.get('state') == 'open':
                        html_content += f"""
                                <tr>
                                    <td>{ip}</td>
                                    <td>{port.get('port', 'N/A')}</td>
                                    <td>{port.get('protocol', 'N/A')}</td>
                                    <td>{port.get('state', 'N/A')}</td>
                                    <td>{port.get('service', {}).get('name', 'N/A')}</td>
                                    <td>{port.get('service', {}).get('product', 'N/A')}</td>
                                </tr>
                        """
            
            html_content += """
                    </table>
                </div>
            </body>
            </html>
            """
            
            with open(filename, 'w') as f:
                f.write(html_content)
            
            logging.info(f"HTML report saved as {filename}")
            
        except Exception as e:
            logging.error(f"Failed to generate HTML report: {e}")

def main():
    """Main function to demonstrate the network analysis tool"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Automated Network Analysis Tool')
    parser.add_argument('--network', '-n', help='Target network (e.g., 192.168.1.0/24)')
    parser.add_argument('--interface', '-i', help='Network interface to use')
    parser.add_argument('--packets', '-p', type=int, default=50, help='Number of packets to capture')
    parser.add_argument('--output', '-o', default='all', choices=['json', 'csv', 'html', 'all'],
                       help='Output format')
    
    args = parser.parse_args()
    
    analyzer = NetworkAnalyzer(target_network=args.network, interface=args.interface)
    
    print("Starting network discovery...")
    analyzer.arp_scan()
    
    print("Capturing network packets...")
    analyzer.packet_capture(count=args.packets)
    
    print("Generating reports...")
    report = analyzer.generate_report(output_format=args.output)
    
    print(f"\n=== Network Analysis Complete ===")
    print(f"Discovered devices: {report['summary']['total_devices']}")
    print(f"Packets analyzed: {report['summary']['total_packets_captured']}")
    print(f"Reports generated in selected formats")
    
    if report['discovered_devices']:
        print(f"\nDiscovered Devices:")
        for device in report['discovered_devices']:
            print(f"  {device['ip_address']} - {device['mac_address']} - {device['vendor']}")

if __name__ == "__main__":
    main()