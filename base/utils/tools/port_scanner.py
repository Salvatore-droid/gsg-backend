import asyncio
import socket
import nmap
import logging
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            111,   # RPC
            135,   # RPC
            139,   # NetBIOS
            143,   # IMAP
            443,   # HTTPS
            445,   # SMB
            993,   # IMAPS
            995,   # POP3S
            1433,  # MSSQL
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            5900,  # VNC
            6379,  # Redis
            27017  # MongoDB
        ]

    async def scan_ports(self, domain, ports=None):
        """Comprehensive port scanning"""
        if ports is None:
            ports = self.common_ports
        
        try:
            # Resolve domain to IP
            ip_address = await self._resolve_domain(domain)
            if not ip_address:
                return []
            
            # Run nmap scan
            open_ports = await self._nmap_scan(ip_address, ports)
            
            return open_ports
            
        except Exception as e:
            logger.error(f"Port scanning failed: {str(e)}")
            return []

    async def _resolve_domain(self, domain):
        """Resolve domain to IP address"""
        try:
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                ip_address = await loop.run_in_executor(
                    executor, 
                    lambda: socket.gethostbyname(domain)
                )
            return ip_address
        except Exception as e:
            logger.error(f"Domain resolution failed: {str(e)}")
            return None

    async def _nmap_scan(self, ip_address, ports):
        """Perform nmap scan"""
        try:
            port_list = ','.join(map(str, ports))
            
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                await loop.run_in_executor(
                    executor,
                    lambda: self.nm.scan(ip_address, arguments=f'-p {port_list} -sS')
                )
            
            open_ports = []
            for protocol in self.nm[ip_address].all_protocols():
                port_info = self.nm[ip_address][protocol]
                for port, info in port_info.items():
                    if info['state'] == 'open':
                        open_ports.append({
                            'port': port,
                            'protocol': protocol,
                            'service': info.get('name', 'unknown'),
                            'version': info.get('version', ''),
                            'state': info['state']
                        })
            
            return open_ports
            
        except Exception as e:
            logger.error(f"Nmap scan failed: {str(e)}")
            return []

    async def comprehensive_scan(self, domain):
        """Perform comprehensive port scan with service detection"""
        try:
            ip_address = await self._resolve_domain(domain)
            if not ip_address:
                return []
            
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                await loop.run_in_executor(
                    executor,
                    lambda: self.nm.scan(ip_address, arguments='-sS -sV -O -A')
                )
            
            scan_results = []
            if ip_address in self.nm.all_hosts():
                host = self.nm[ip_address]
                
                for protocol in host.all_protocols():
                    ports = host[protocol]
                    for port, info in ports.items():
                        if info['state'] == 'open':
                            result = {
                                'port': port,
                                'protocol': protocol,
                                'service': info.get('name', 'unknown'),
                                'version': info.get('version', ''),
                                'state': info['state'],
                                'product': info.get('product', ''),
                                'extrainfo': info.get('extrainfo', ''),
                                'cpe': info.get('cpe', '')
                            }
                            scan_results.append(result)
            
            return scan_results
            
        except Exception as e:
            logger.error(f"Comprehensive scan failed: {str(e)}")
            return []

# Create scanner instance
scanner = PortScanner()

# Async scan functions
async def scan_ports(domain, ports=None):
    return await scanner.scan_ports(domain, ports)

async def comprehensive_scan(domain):
    return await scanner.comprehensive_scan(domain)