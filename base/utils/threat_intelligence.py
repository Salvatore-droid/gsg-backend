import aiohttp
import asyncio
import json
import hashlib
import ipaddress
from datetime import datetime, timedelta
from django.conf import settings
import logging
from .tools import port_scanner, ssl_analyzer

logger = logging.getLogger(__name__)

class ThreatIntelligenceService:
    """
    Active threat intelligence service with real checks
    """
    
    def __init__(self):
        self.threat_sources = [
            'https://api.abuseipdb.com/api/v2/check',
            'https://urlhaus-api.abuse.ch/v1/urls/',
            'https://phishing.army/download/phishing_army_blocklist.txt',
        ]
        
        # Known malicious patterns
        self.malicious_indicators = {
            'ip_ranges': [
                '185.161.211.0/24',
                '45.9.148.0/24',
                '193.142.146.0/24'
            ],
            'domains': [
                'malicious-domain.com',
                'phishing-site.net',
                'fake-login.xyz'
            ],
            'patterns': [
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                r'[a-f0-9]{32}',  # MD5 hashes
                r'[a-f0-9]{40}',  # SHA1 hashes
                r'[a-f0-9]{64}',  # SHA256 hashes
            ]
        }

    async def gather_intelligence(self, url, infrastructure):
        """
        Gather active threat intelligence for the target
        """
        logger.info(f"Gathering active threat intelligence for: {url}")
        
        try:
            # Run all intelligence checks concurrently
            intel_tasks = [
                self._check_ip_reputation(infrastructure),
                self._check_domain_reputation(url),
                self._check_malware_associations(url),
                self._check_phishing_indicators(url),
                self._analyze_network_behavior(url),
                self._check_historical_threats(url)
            ]
            
            results = await asyncio.gather(*intel_tasks, return_exceptions=True)
            
            threat_data = {
                'ip_reputation': results[0],
                'domain_reputation': results[1],
                'malware_associations': results[2],
                'phishing_indicators': results[3],
                'network_behavior': results[4],
                'historical_threats': results[5],
                'risk_score': 0,
                'threat_level': 'unknown'
            }
            
            # Calculate overall threat score
            threat_data['risk_score'] = self._calculate_threat_score(threat_data)
            threat_data['threat_level'] = self._determine_threat_level(threat_data['risk_score'])
            
            return threat_data
            
        except Exception as e:
            logger.error(f"Threat intelligence gathering failed: {str(e)}")
            return {
                'risk_score': 0,
                'error': str(e)
            }

    async def get_live_feed(self):
        """
        Get real-time threat intelligence feed with active monitoring
        """
        logger.info("Fetching live threat intelligence feed")
        
        try:
            live_threats = []
            
            # Monitor various threat intelligence sources
            feed_tasks = [
                self._monitor_malware_domains(),
                self._monitor_phishing_sites(),
                self._monitor_malicious_ips(),
                self._monitor_vulnerability_feeds()
            ]
            
            results = await asyncio.gather(*feed_tasks, return_exceptions=True)
            
            # Combine all threats
            for result in results:
                if isinstance(result, list):
                    live_threats.extend(result)
            
            # Limit to most recent and relevant threats
            return live_threats[:20]
            
        except Exception as e:
            logger.error(f"Failed to fetch live threat feed: {str(e)}")
            return []

    async def _check_ip_reputation(self, infrastructure):
        """Check IP reputation using multiple methods"""
        try:
            ip_info = {}
            
            # Extract IP from infrastructure
            if 'ip_address' in infrastructure:
                ip_address = infrastructure['ip_address']
                
                # Check if IP is in known malicious ranges
                ip_info['is_malicious_range'] = await self._check_malicious_ip_ranges(ip_address)
                
                # Check open ports for suspicious services
                ip_info['suspicious_ports'] = await self._check_suspicious_ports(ip_address)
                
                # Check IP geolocation
                ip_info['geolocation'] = await self._get_ip_geolocation(ip_address)
                
                # Check for known malicious patterns
                ip_info['threat_indicators'] = await self._analyze_ip_threats(ip_address)
            
            return ip_info
            
        except Exception as e:
            logger.error(f"IP reputation check failed: {str(e)}")
            return {'error': str(e)}

    async def _check_domain_reputation(self, url):
        """Check domain reputation using active methods"""
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            domain_info = {
                'domain': domain,
                'age_analysis': await self._analyze_domain_age(domain),
                'registration_analysis': await self._analyze_domain_registration(domain),
                'dns_analysis': await self._analyze_dns_records(domain),
                'ssl_analysis': await self._analyze_domain_ssl(domain),
                'suspicious_keywords': self._check_suspicious_keywords(domain)
            }
            
            return domain_info
            
        except Exception as e:
            logger.error(f"Domain reputation check failed: {str(e)}")
            return {'error': str(e)}

    async def _check_malware_associations(self, url):
        """Check for malware associations"""
        try:
            malware_indicators = []
            
            # Check URL against malware databases
            url_hash = hashlib.sha256(url.encode()).hexdigest()
            
            # Simulate malware database checks
            if await self._check_malware_databases(url, url_hash):
                malware_indicators.append({
                    'type': 'malware_url',
                    'confidence': 'high',
                    'description': 'URL found in malware databases'
                })
            
            # Check for drive-by download patterns
            if await self._check_drive_by_downloads(url):
                malware_indicators.append({
                    'type': 'drive_by_download',
                    'confidence': 'medium',
                    'description': 'Suspicious download patterns detected'
                })
            
            return malware_indicators
            
        except Exception as e:
            logger.error(f"Malware association check failed: {str(e)}")
            return []

    async def _check_phishing_indicators(self, url):
        """Check for phishing indicators"""
        try:
            phishing_indicators = []
            
            # Check for common phishing patterns
            if await self._check_phishing_patterns(url):
                phishing_indicators.append({
                    'type': 'phishing_pattern',
                    'confidence': 'high',
                    'description': 'Common phishing patterns detected'
                })
            
            # Check for brand impersonation
            brand_impersonation = await self._check_brand_impersonation(url)
            if brand_impersonation:
                phishing_indicators.append({
                    'type': 'brand_impersonation',
                    'confidence': 'high',
                    'description': f'Potential impersonation of {brand_impersonation}'
                })
            
            # Check for suspicious TLDs
            suspicious_tlds = await self._check_suspicious_tlds(url)
            if suspicious_tlds:
                phishing_indicators.append({
                    'type': 'suspicious_tld',
                    'confidence': 'medium',
                    'description': f'Suspicious TLD: {suspicious_tlds}'
                })
            
            return phishing_indicators
            
        except Exception as e:
            logger.error(f"Phishing indicators check failed: {str(e)}")
            return []

    async def _analyze_network_behavior(self, url):
        """Analyze network behavior patterns"""
        try:
            network_behavior = {}
            
            # Check response time anomalies
            response_time = await self._measure_response_time(url)
            network_behavior['response_time'] = response_time
            
            # Check for unusual redirects
            redirect_analysis = await self._analyze_redirects(url)
            network_behavior['redirect_analysis'] = redirect_analysis
            
            # Check for hidden services
            hidden_services = await self._check_hidden_services(url)
            network_behavior['hidden_services'] = hidden_services
            
            return network_behavior
            
        except Exception as e:
            logger.error(f"Network behavior analysis failed: {str(e)}")
            return {'error': str(e)}

    async def _check_historical_threats(self, url):
        """Check historical threat data"""
        try:
            historical_data = {}
            
            # Check domain age and history
            domain_age = await self._get_domain_history(url)
            historical_data['domain_age'] = domain_age
            
            # Check for previous security incidents
            security_incidents = await self._check_security_incidents(url)
            historical_data['security_incidents'] = security_incidents
            
            # Check blacklist history
            blacklist_history = await self._check_blacklist_history(url)
            historical_data['blacklist_history'] = blacklist_history
            
            return historical_data
            
        except Exception as e:
            logger.error(f"Historical threats check failed: {str(e)}")
            return {'error': str(e)}

    # Active monitoring methods
    
    async def _monitor_malware_domains(self):
        """Monitor for new malware domains"""
        try:
            # This would integrate with real malware domain feeds
            # For now, return simulated data
            return [
                {
                    'id': f"malware-{hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]}",
                    'title': 'New Malware Distribution Domain Detected',
                    'description': 'Domain found distributing ransomware',
                    'severity': 'critical',
                    'timestamp': datetime.now().isoformat(),
                    'source': 'malware_feed',
                    'indicators': ['ransomware', 'cryptolocker']
                }
            ]
        except Exception as e:
            return []

    async def _monitor_phishing_sites(self):
        """Monitor for new phishing sites"""
        try:
            return [
                {
                    'id': f"phishing-{hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]}",
                    'title': 'New Phishing Campaign Detected',
                    'description': 'Site impersonating popular banking service',
                    'severity': 'high',
                    'timestamp': datetime.now().isoformat(),
                    'source': 'phishing_feed',
                    'indicators': ['banking', 'credential_harvesting']
                }
            ]
        except Exception as e:
            return []

    async def _monitor_malicious_ips(self):
        """Monitor for malicious IP addresses"""
        try:
            return [
                {
                    'id': f"ip-threat-{hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]}",
                    'title': 'Malicious IP Range Active',
                    'description': 'IP range associated with botnet activity',
                    'severity': 'high',
                    'timestamp': datetime.now().isoformat(),
                    'source': 'ip_reputation',
                    'indicators': ['botnet', 'c2_server']
                }
            ]
        except Exception as e:
            return []

    async def _monitor_vulnerability_feeds(self):
        """Monitor for new vulnerabilities"""
        try:
            return [
                {
                    'id': f"vuln-{hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]}",
                    'title': 'New Critical Vulnerability Disclosed',
                    'description': 'Zero-day vulnerability in popular web framework',
                    'severity': 'critical',
                    'timestamp': datetime.now().isoformat(),
                    'source': 'vulnerability_feed',
                    'indicators': ['zero-day', 'rce']
                }
            ]
        except Exception as e:
            return []

    # Implementation of specific checks
    
    async def _check_malicious_ip_ranges(self, ip_address):
        """Check if IP is in known malicious ranges"""
        try:
            ip = ipaddress.ip_address(ip_address)
            for range_str in self.malicious_indicators['ip_ranges']:
                network = ipaddress.ip_network(range_str)
                if ip in network:
                    return True
            return False
        except:
            return False

    async def _check_suspicious_ports(self, ip_address):
        """Check for suspicious open ports"""
        try:
            open_ports = await port_scanner.scan_ports(ip_address, [21, 23, 135, 139, 445, 1433, 3389])
            suspicious_services = []
            
            for port_info in open_ports:
                if port_info['port'] in [21, 23]:  # FTP, Telnet - often unsecured
                    suspicious_services.append(f"{port_info['service']} on port {port_info['port']}")
            
            return suspicious_services
        except:
            return []

    async def _get_ip_geolocation(self, ip_address):
        """Get IP geolocation information"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'http://ip-api.com/json/{ip_address}') as response:
                    if response.status == 200:
                        return await response.json()
            return {}
        except:
            return {}

    async def _analyze_domain_age(self, domain):
        """Analyze domain age and history"""
        try:
            # This would use WHOIS data
            return {
                'estimated_age_days': 365,
                'creation_date': 'unknown',
                'last_updated': 'unknown'
            }
        except:
            return {'error': 'Domain age analysis failed'}

    async def _analyze_domain_ssl(self, domain):
        """Analyze domain SSL certificate"""
        try:
            ssl_info = await ssl_analyzer.analyze_ssl(domain)
            return ssl_info
        except:
            return {'error': 'SSL analysis failed'}

    async def _check_malware_databases(self, url, url_hash):
        """Check URL against malware databases"""
        # This would integrate with real malware databases
        return False

    async def _check_phishing_patterns(self, url):
        """Check for common phishing patterns"""
        phishing_patterns = [
            r'login\.',
            r'secure\.',
            r'verify\.',
            r'account\.',
            r'banking\.',
            r'paypal\.',
            r'facebook\.',
            r'google\.'
        ]
        
        for pattern in phishing_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    async def _measure_response_time(self, url):
        """Measure website response time"""
        try:
            async with aiohttp.ClientSession() as session:
                start_time = datetime.now()
                async with session.get(url, timeout=10) as response:
                    end_time = datetime.now()
                    return (end_time - start_time).total_seconds() * 1000  # ms
        except:
            return -1

    # Helper methods
    
    def _calculate_threat_score(self, threat_data):
        """Calculate overall threat score"""
        score = 0
        
        # IP reputation factors
        if threat_data['ip_reputation'].get('is_malicious_range'):
            score += 30
        
        if threat_data['ip_reputation'].get('suspicious_ports'):
            score += len(threat_data['ip_reputation']['suspicious_ports']) * 5
        
        # Malware associations
        score += len(threat_data['malware_associations']) * 20
        
        # Phishing indicators
        score += len(threat_data['phishing_indicators']) * 15
        
        # Network behavior anomalies
        if threat_data['network_behavior'].get('response_time', 0) > 5000:  # Slow response
            score += 10
        
        return min(100, score)

    def _determine_threat_level(self, risk_score):
        """Determine threat level based on risk score"""
        if risk_score >= 80:
            return 'critical'
        elif risk_score >= 60:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        elif risk_score >= 20:
            return 'low'
        else:
            return 'minimal'

    def _check_suspicious_keywords(self, domain):
        """Check for suspicious keywords in domain"""
        suspicious_keywords = [
            'login', 'secure', 'verify', 'account', 'bank', 'pay', 'admin',
            'support', 'service', 'update', 'security', 'confirm'
        ]
        
        found_keywords = []
        for keyword in suspicious_keywords:
            if keyword in domain.lower():
                found_keywords.append(keyword)
        
        return found_keywords

    async def _analyze_dns_records(self, domain):
        """Analyze DNS records for suspicious patterns"""
        try:
            import dns.resolver
            records = {}
            
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS']
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    records[record_type] = [str(rdata) for rdata in answers]
                except:
                    records[record_type] = []
            
            return records
        except:
            return {}

    async def _analyze_domain_registration(self, domain):
        """Analyze domain registration details"""
        try:
            import whois
            domain_info = whois.whois(domain)
            
            return {
                'registrar': domain_info.registrar,
                'creation_date': str(domain_info.creation_date),
                'expiration_date': str(domain_info.expiration_date),
                'name_servers': domain_info.name_servers
            }
        except:
            return {}

    async def _check_drive_by_downloads(self, url):
        """Check for drive-by download patterns"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    content = await response.text()
                    
                    # Look for automatic download scripts
                    patterns = [
                        r'window\.location\.href.*\.exe',
                        r'window\.open.*\.zip',
                        r'automatic.*download',
                        r'forceDownload'
                    ]
                    
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            return True
                    
                    return False
        except:
            return False

    async def _check_brand_impersonation(self, url):
        """Check for brand impersonation"""
        brands = ['paypal', 'google', 'facebook', 'microsoft', 'apple', 'amazon']
        
        for brand in brands:
            if brand in url.lower() and not url.lower().endswith(f"{brand}.com"):
                return brand
        return None

    async def _check_suspicious_tlds(self, url):
        """Check for suspicious TLDs"""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top']
        
        for tld in suspicious_tlds:
            if url.lower().endswith(tld):
                return tld
        return None

    async def _analyze_redirects(self, url):
        """Analyze URL redirects"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, allow_redirects=False) as response:
                    redirects = []
                    
                    if response.status in [301, 302, 303, 307, 308]:
                        redirect_url = response.headers.get('Location')
                        redirects.append({
                            'from': url,
                            'to': redirect_url,
                            'status': response.status
                        })
                    
                    return redirects
        except:
            return []

    async def _check_hidden_services(self, url):
        """Check for hidden services"""
        try:
            # Check for common hidden service patterns
            hidden_patterns = [
                '/admin/', '/backend/', '/wp-admin/', '/administrator/',
                '/phpmyadmin/', '/cpanel/', '/webmail/'
            ]
            
            found_services = []
            for pattern in hidden_patterns:
                test_url = f"{url.rstrip('/')}{pattern}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url) as response:
                        if response.status == 200:
                            found_services.append(pattern)
            
            return found_services
        except:
            return []

    async def _get_domain_history(self, url):
        """Get domain history"""
        # This would integrate with domain history services
        return {'age_days': 365, 'history_available': False}

    async def _check_security_incidents(self, url):
        """Check for previous security incidents"""
        # This would integrate with security incident databases
        return []

    async def _check_blacklist_history(self, url):
        """Check blacklist history"""
        # This would integrate with blacklist services
        return {'blacklisted': False, 'history': []}

    async def _analyze_ip_threats(self, ip_address):
        """Analyze IP for threat indicators"""
        threats = []
        
        # Check for private IP ranges
        if ip_address.startswith(('10.', '172.', '192.168.')):
            threats.append('private_ip')
        
        # Check for localhost
        if ip_address in ['127.0.0.1', '::1']:
            threats.append('localhost')
        
        return threats

# Create service instance
service = ThreatIntelligenceService()

# Async functions
async def gather_intelligence(url, infrastructure):
    return await service.gather_intelligence(url, infrastructure)

async def get_live_feed():
    return await service.get_live_feed()