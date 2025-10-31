import aiohttp
import asyncio
import subprocess
import json
import re
import socket
import ssl
import dns.resolver
from urllib.parse import urlparse
from django.conf import settings
import logging
import nmap
import requests
from bs4 import BeautifulSoup
import whois
import ssl
import cryptography.x509
from cryptography.hazmat.backends import default_backend
import concurrent.futures
import tempfile
import os
from .tools import sql_injection_scanner, xss_scanner, csrf_scanner, port_scanner, ssl_analyzer, header_analyzer, cms_detector

logger = logging.getLogger(__name__)

class SecurityScanner:
    """
    Comprehensive security scanner integrating multiple security tools
    """
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.session = aiohttp.ClientSession()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)
    
    async def perform_recon(self, url):
        """
        Perform comprehensive reconnaissance
        """
        logger.info(f"Starting comprehensive reconnaissance for: {url}")
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Run all reconnaissance tasks concurrently
            recon_tasks = [
                self._get_detailed_dns_info(domain),
                self._get_comprehensive_http_headers(url),
                self._detect_technology_stack(url),
                self._scan_ports_comprehensive(domain),
                self._get_whois_info(domain),
                self._analyze_ssl_certificate(domain),
                self._crawl_for_endpoints(url),
                self._check_cloud_infrastructure(domain)
            ]
            
            results = await asyncio.gather(*recon_tasks, return_exceptions=True)
            
            recon_data = {
                'dns_info': results[0],
                'http_headers': results[1],
                'technology_stack': results[2],
                'open_ports': results[3],
                'whois_info': results[4],
                'ssl_info': results[5],
                'discovered_endpoints': results[6],
                'cloud_infrastructure': results[7],
                'subdomains': await self._find_subdomains(domain)
            }
            
            return recon_data
            
        except Exception as e:
            logger.error(f"Reconnaissance failed: {str(e)}")
            return {'error': str(e)}
    
    async def run_vulnerability_scan(self, url, scan_type):
        """
        Run comprehensive vulnerability scans
        """
        logger.info(f"Starting {scan_type} vulnerability scan for: {url}")
        
        vulnerabilities = []
        
        try:
            scan_tasks = []
            
            if scan_type in ['web', 'full']:
                scan_tasks.extend([
                    self._comprehensive_sql_injection_scan(url),
                    self._comprehensive_xss_scan(url),
                    self._csrf_audit(url),
                    self._file_inclusion_scan(url),
                    self._command_injection_scan(url),
                    self._directory_traversal_scan(url),
                    self._server_security_scan(url)
                ])
            
            if scan_type in ['api', 'full']:
                scan_tasks.extend([
                    self._api_security_scan(url),
                    self._authentication_scan(url),
                    self._authorization_scan(url)
                ])
            
            if scan_type in ['infrastructure', 'full']:
                scan_tasks.extend([
                    self._infrastructure_security_scan(url),
                    self._network_security_scan(url),
                    self._service_vulnerability_scan(url)
                ])
            
            # Run all vulnerability scans
            scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            for result in scan_results:
                if isinstance(result, list):
                    vulnerabilities.extend(result)
            
            # Remove duplicates
            unique_vulns = []
            seen_titles = set()
            for vuln in vulnerabilities:
                if vuln['title'] not in seen_titles:
                    unique_vulns.append(vuln)
                    seen_titles.add(vuln['title'])
            
            return unique_vulns
            
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {str(e)}")
            return [{
                'title': 'Scan Error',
                'description': f'Vulnerability scanning failed: {str(e)}',
                'severity': 'high',
                'evidence': {'error': str(e)},
                'recommendation': 'Check scanner configuration and target availability',
                'cvss_score': 5.0
            }]
    
    async def check_compliance(self, url, requirements):
        """
        Comprehensive compliance checking
        """
        logger.info(f"Checking compliance for: {url}")
        
        try:
            compliance_tasks = []
            
            if not requirements or 'all' in requirements:
                requirements = ['gdpr', 'pci', 'hipaa', 'nist', 'owasp']
            
            if 'gdpr' in requirements:
                compliance_tasks.append(self._check_gdpr_compliance(url))
            if 'pci' in requirements:
                compliance_tasks.append(self._check_pci_compliance(url))
            if 'hipaa' in requirements:
                compliance_tasks.append(self._check_hipaa_compliance(url))
            if 'nist' in requirements:
                compliance_tasks.append(self._check_nist_compliance(url))
            if 'owasp' in requirements:
                compliance_tasks.append(self._check_owasp_compliance(url))
            
            results = await asyncio.gather(*compliance_tasks)
            
            compliance_results = {
                'compliance_score': 0,
                'checks_passed': 0,
                'checks_failed': 0,
                'details': {}
            }
            
            for result in results:
                standard = result.pop('standard')
                compliance_results['details'][standard] = result
                compliance_results['checks_passed'] += result.get('passed_checks', 0)
                compliance_results['checks_failed'] += result.get('failed_checks', 0)
            
            total_checks = compliance_results['checks_passed'] + compliance_results['checks_failed']
            if total_checks > 0:
                compliance_results['compliance_score'] = (
                    compliance_results['checks_passed'] / total_checks
                ) * 100
            
            return compliance_results
            
        except Exception as e:
            logger.error(f"Compliance check failed: {str(e)}")
            return {
                'compliance_score': 0,
                'error': str(e)
            }
    
    async def quick_scan(self, url):
        """
        Perform quick but comprehensive security assessment
        """
        logger.info(f"Starting quick comprehensive scan for: {url}")
        
        try:
            quick_tasks = [
                self._check_security_headers(url),
                self._analyze_ssl_tls(url),
                self._quick_vulnerability_check(url),
                self._check_content_security(url),
                self._check_exposed_information(url)
            ]
            
            results = await asyncio.gather(*quick_tasks, return_exceptions=True)
            
            findings = {
                'security_headers': results[0],
                'ssl_tls': results[1],
                'vulnerabilities': results[2],
                'content_security': results[3],
                'information_exposure': results[4],
                'risk_level': 'unknown',
                'risk_score': 0
            }
            
            # Calculate comprehensive risk score
            risk_score = self._calculate_quick_risk_score(findings)
            findings['risk_score'] = risk_score
            
            if risk_score >= 80:
                findings['risk_level'] = 'critical'
            elif risk_score >= 60:
                findings['risk_level'] = 'high'
            elif risk_score >= 40:
                findings['risk_level'] = 'medium'
            elif risk_score >= 20:
                findings['risk_level'] = 'low'
            else:
                findings['risk_level'] = 'minimal'
            
            return findings
            
        except Exception as e:
            logger.error(f"Quick scan failed: {str(e)}")
            return {'error': str(e)}
    
    # Advanced Reconnaissance Methods
    
    async def _get_detailed_dns_info(self, domain):
        """Get comprehensive DNS information"""
        try:
            dns_info = {}
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_info[record_type.lower()] = [str(rdata) for rdata in answers]
                except Exception as e:
                    dns_info[record_type.lower()] = []
            
            # Check for DNS security features
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                txt_records = [str(rdata) for rdata in answers]
                dns_info['security_txt'] = any('v=spf1' in record or 'DMARC' in record for record in txt_records)
            except:
                dns_info['security_txt'] = False
            
            return dns_info
        except Exception as e:
            return {'error': str(e)}
    
    async def _get_comprehensive_http_headers(self, url):
        """Analyze HTTP headers comprehensively"""
        try:
            async with self.session.get(url) as response:
                headers = dict(response.headers)
                
                security_analysis = {
                    'headers_present': headers,
                    'security_headers': {},
                    'missing_security_headers': [],
                    'header_analysis': {}
                }
                
                # Required security headers
                required_headers = {
                    'Content-Security-Policy': 'Content Security Policy',
                    'Strict-Transport-Security': 'HTTP Strict Transport Security',
                    'X-Content-Type-Options': 'X-Content-Type-Options',
                    'X-Frame-Options': 'X-Frame-Options',
                    'X-XSS-Protection': 'X-XSS-Protection',
                    'Referrer-Policy': 'Referrer Policy',
                    'Permissions-Policy': 'Permissions Policy'
                }
                
                for header, description in required_headers.items():
                    if header in headers:
                        security_analysis['security_headers'][header] = {
                            'value': headers[header],
                            'description': description
                        }
                    else:
                        security_analysis['missing_security_headers'].append(header)
                
                # Analyze header values
                security_analysis['header_analysis'] = header_analyzer.analyze_headers(headers)
                
                return security_analysis
        except Exception as e:
            return {'error': str(e)}
    
    async def _detect_technology_stack(self, url):
        """Detect complete technology stack"""
        try:
            tech_stack = await cms_detector.detect_technologies(url)
            return tech_stack
        except Exception as e:
            return {'error': str(e)}
    
    async def _scan_ports_comprehensive(self, domain):
        """Comprehensive port scanning"""
        try:
            open_ports = await port_scanner.scan_ports(domain)
            return open_ports
        except Exception as e:
            return {'error': str(e)}
    
    async def _get_whois_info(self, domain):
        """Get WHOIS information"""
        try:
            domain_info = whois.whois(domain)
            return {
                'registrar': domain_info.registrar,
                'creation_date': str(domain_info.creation_date),
                'expiration_date': str(domain_info.expiration_date),
                'name_servers': domain_info.name_servers,
                'status': domain_info.status
            }
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_ssl_certificate(self, domain):
        """Comprehensive SSL/TLS analysis"""
        try:
            ssl_info = await ssl_analyzer.analyze_ssl(domain)
            return ssl_info
        except Exception as e:
            return {'error': str(e)}
    
    async def _crawl_for_endpoints(self, url):
        """Crawl for hidden endpoints"""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    endpoints = set()
                    
                    # Find links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        if href.startswith('/') or url in href:
                            endpoints.add(href)
                    
                    # Find scripts and assets
                    for script in soup.find_all('script', src=True):
                        endpoints.add(script['src'])
                    
                    for img in soup.find_all('img', src=True):
                        endpoints.add(img['src'])
                    
                    return list(endpoints)
        except Exception as e:
            return []
    
    async def _check_cloud_infrastructure(self, domain):
        """Check for cloud infrastructure"""
        try:
            # Check common cloud patterns
            cloud_indicators = {
                'aws': False,
                'azure': False,
                'gcp': False,
                'cloudflare': False
            }
            
            # Check DNS for cloud indicators
            dns_info = await self._get_detailed_dns_info(domain)
            
            cname_records = dns_info.get('cname', [])
            for record in cname_records:
                if 'aws' in record.lower():
                    cloud_indicators['aws'] = True
                if 'azure' in record.lower():
                    cloud_indicators['azure'] = True
                if 'google' in record.lower() or 'gcp' in record.lower():
                    cloud_indicators['gcp'] = True
                if 'cloudflare' in record.lower():
                    cloud_indicators['cloudflare'] = True
            
            return cloud_indicators
        except Exception as e:
            return {'error': str(e)}
    
    async def _find_subdomains(self, domain):
        """Find subdomains"""
        try:
            common_subdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'cpanel', 'whm', 'autodiscover']
            
            found_subdomains = []
            for sub in common_subdomains:
                subdomain = f"{sub}.{domain}"
                try:
                    socket.gethostbyname(subdomain)
                    found_subdomains.append(subdomain)
                except socket.gaierror:
                    continue
            
            return found_subdomains
        except Exception as e:
            return []
    
    # Vulnerability Scanning Methods
    
    async def _comprehensive_sql_injection_scan(self, url):
        """Comprehensive SQL injection scanning"""
        try:
            vulnerabilities = await sql_injection_scanner.scan(url)
            return vulnerabilities
        except Exception as e:
            logger.error(f"SQL injection scan failed: {str(e)}")
            return []
    
    async def _comprehensive_xss_scan(self, url):
        """Comprehensive XSS scanning"""
        try:
            vulnerabilities = await xss_scanner.scan(url)
            return vulnerabilities
        except Exception as e:
            logger.error(f"XSS scan failed: {str(e)}")
            return []
    
    async def _csrf_audit(self, url):
        """CSRF vulnerability audit"""
        try:
            vulnerabilities = await csrf_scanner.audit(url)
            return vulnerabilities
        except Exception as e:
            logger.error(f"CSRF audit failed: {str(e)}")
            return []
    
    async def _file_inclusion_scan(self, url):
        """File inclusion vulnerability scan"""
        try:
            # Implement LFI/RFI scanning
            vulnerabilities = []
            test_params = ['file', 'page', 'path', 'load', 'template']
            
            for param in test_params:
                test_url = f"{url}?{param}=../../../../etc/passwd"
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    if 'root:' in content and 'bin/bash' in content:
                        vulnerabilities.append({
                            'title': 'Local File Inclusion Vulnerability',
                            'description': f'The parameter {param} is vulnerable to local file inclusion',
                            'severity': 'high',
                            'evidence': {'url': test_url, 'parameter': param},
                            'recommendation': 'Validate and sanitize all user input, use whitelists for file paths',
                            'cvss_score': 8.2
                        })
            
            return vulnerabilities
        except Exception as e:
            logger.error(f"File inclusion scan failed: {str(e)}")
            return []
    
    async def _command_injection_scan(self, url):
        """Command injection vulnerability scan"""
        try:
            vulnerabilities = []
            test_commands = [';id', '|id', '&&id', '||id']
            
            # Test various parameters
            test_params = ['cmd', 'command', 'exec', 'execute', 'ping']
            
            for param in test_params:
                for cmd in test_commands:
                    test_url = f"{url}?{param}=127.0.0.1{cmd}"
                    async with self.session.get(test_url) as response:
                        content = await response.text()
                        if 'uid=' in content and 'gid=' in content:
                            vulnerabilities.append({
                                'title': 'Command Injection Vulnerability',
                                'description': f'The parameter {param} is vulnerable to command injection',
                                'severity': 'critical',
                                'evidence': {'url': test_url, 'parameter': param, 'command': cmd},
                                'recommendation': 'Use proper input validation and avoid shell command execution with user input',
                                'cvss_score': 9.8
                            })
                            break
            
            return vulnerabilities
        except Exception as e:
            logger.error(f"Command injection scan failed: {str(e)}")
            return []
    
    async def _directory_traversal_scan(self, url):
        """Directory traversal vulnerability scan"""
        try:
            vulnerabilities = []
            traversal_patterns = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '%2e%2e%2fetc%2fpasswd'
            ]
            
            test_params = ['file', 'path', 'directory', 'folder', 'template']
            
            for param in test_params:
                for pattern in traversal_patterns:
                    test_url = f"{url}?{param}={pattern}"
                    async with self.session.get(test_url) as response:
                        content = await response.text()
                        if 'root:' in content or '[extensions]' in content:
                            vulnerabilities.append({
                                'title': 'Directory Traversal Vulnerability',
                                'description': f'The parameter {param} is vulnerable to directory traversal',
                                'severity': 'high',
                                'evidence': {'url': test_url, 'parameter': param, 'pattern': pattern},
                                'recommendation': 'Validate and sanitize file paths, use base directory restrictions',
                                'cvss_score': 7.5
                            })
                            break
            
            return vulnerabilities
        except Exception as e:
            logger.error(f"Directory traversal scan failed: {str(e)}")
            return []
    
    async def _server_security_scan(self, url):
        """Server security configuration scan"""
        try:
            vulnerabilities = []
            
            # Check for exposed server information
            async with self.session.get(url) as response:
                headers = dict(response.headers)
                
                server_header = headers.get('Server', '')
                if server_header:
                    vulnerabilities.append({
                        'title': 'Exposed Server Version',
                        'description': f'Server header exposes: {server_header}',
                        'severity': 'low',
                        'evidence': {'header': 'Server', 'value': server_header},
                        'recommendation': 'Remove or obscure server version information',
                        'cvss_score': 3.7
                    })
                
                # Check for insecure HTTP methods
                if 'Allow' in headers:
                    methods = headers['Allow'].split(',')
                    dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                    for method in dangerous_methods:
                        if method in methods:
                            vulnerabilities.append({
                                'title': 'Dangerous HTTP Method Enabled',
                                'description': f'HTTP {method} method is enabled',
                                'severity': 'medium',
                                'evidence': {'header': 'Allow', 'value': headers['Allow']},
                                'recommendation': 'Disable unnecessary HTTP methods',
                                'cvss_score': 5.3
                            })
            
            return vulnerabilities
        except Exception as e:
            logger.error(f"Server security scan failed: {str(e)}")
            return []
    
    async def _api_security_scan(self, url):
        """API security scanning"""
        try:
            vulnerabilities = []
            
            # Test common API endpoints
            api_endpoints = ['/api/v1/users', '/api/v1/admin', '/api/v1/config', '/graphql', '/rest/api']
            
            for endpoint in api_endpoints:
                test_url = f"{url}{endpoint}"
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for exposed data
                        if 'password' in content.lower() or 'email' in content.lower():
                            vulnerabilities.append({
                                'title': 'Exposed API Endpoint',
                                'description': f'API endpoint {endpoint} exposes sensitive information',
                                'severity': 'high',
                                'evidence': {'endpoint': endpoint, 'status': response.status},
                                'recommendation': 'Implement proper authentication and authorization for API endpoints',
                                'cvss_score': 7.5
                            })
            
            return vulnerabilities
        except Exception as e:
            logger.error(f"API security scan failed: {str(e)}")
            return []
    
    async def _authentication_scan(self, url):
        """Authentication mechanism scanning"""
        try:
            vulnerabilities = []
            
            # Test for default credentials
            default_credentials = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('root', 'root'),
                ('test', 'test')
            ]
            
            login_endpoints = ['/login', '/admin', '/wp-login.php', '/administrator']
            
            for endpoint in login_endpoints:
                test_url = f"{url}{endpoint}"
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        # This would normally involve actual login attempts
                        # For security reasons, we'll just note the presence
                        vulnerabilities.append({
                            'title': 'Authentication Endpoint Discovered',
                            'description': f'Login endpoint found: {endpoint}',
                            'severity': 'info',
                            'evidence': {'endpoint': endpoint},
                            'recommendation': 'Ensure strong authentication mechanisms and monitor for brute force attacks',
                            'cvss_score': 2.5
                        })
            
            return vulnerabilities
        except Exception as e:
            logger.error(f"Authentication scan failed: {str(e)}")
            return []
    
    async def _authorization_scan(self, url):
        """Authorization bypass testing"""
        try:
            vulnerabilities = []
            
            # Test for directory listing
            directories = ['/images', '/css', '/js', '/uploads', '/admin', '/backup']
            
            for directory in directories:
                test_url = f"{url}{directory}"
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        if '<title>Index of' in content or '<h1>Directory listing for' in content:
                            vulnerabilities.append({
                                'title': 'Directory Listing Enabled',
                                'description': f'Directory listing enabled for: {directory}',
                                'severity': 'medium',
                                'evidence': {'directory': directory},
                                'recommendation': 'Disable directory listing in web server configuration',
                                'cvss_score': 5.3
                            })
            
            return vulnerabilities
        except Exception as e:
            logger.error(f"Authorization scan failed: {str(e)}")
            return []
    
    async def _infrastructure_security_scan(self, url):
        """Infrastructure security scanning"""
        try:
            vulnerabilities = []
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Check for common infrastructure issues
            open_ports = await self._scan_ports_comprehensive(domain)
            
            for port_info in open_ports:
                if port_info['port'] in [21, 23, 135, 139, 445]:  # Known risky services
                    vulnerabilities.append({
                        'title': f'Risky Service on Port {port_info["port"]}',
                        'description': f'Service {port_info["service"]} running on port {port_info["port"]}',
                        'severity': 'medium',
                        'evidence': {'port': port_info['port'], 'service': port_info['service']},
                        'recommendation': 'Close unnecessary ports and services',
                        'cvss_score': 5.9
                    })
            
            return vulnerabilities
        except Exception as e:
            logger.error(f"Infrastructure security scan failed: {str(e)}")
            return []
    
    async def _network_security_scan(self, url):
        """Network security scanning"""
        try:
            vulnerabilities = []
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Check DNS security
            dns_info = await self._get_detailed_dns_info(domain)
            
            if not dns_info.get('security_txt', False):
                vulnerabilities.append({
                    'title': 'Missing DNS Security Records',
                    'description': 'No SPF/DMARC/DKIM records found',
                    'severity': 'low',
                    'evidence': {'dns_records': dns_info},
                    'recommendation': 'Implement SPF, DMARC, and DKIM records for email security',
                    'cvss_score': 3.1
                })
            
            return vulnerabilities
        except Exception as e:
            logger.error(f"Network security scan failed: {str(e)}")
            return []
    
    async def _service_vulnerability_scan(self, url):
        """Service-specific vulnerability scanning"""
        try:
            vulnerabilities = []
            
            # This would integrate with vulnerability databases
            # For now, return placeholder
            return vulnerabilities
        except Exception as e:
            logger.error(f"Service vulnerability scan failed: {str(e)}")
            return []
    
    # Compliance Checking Methods
    
    async def _check_gdpr_compliance(self, url):
        """GDPR compliance checking"""
        checks = {
            'passed': 0,
            'failed': 0,
            'details': []
        }
        
        try:
            # Check for privacy policy
            async with self.session.get(url) as response:
                content = await response.text()
                
                privacy_indicators = ['privacy policy', 'gdpr', 'data protection']
                has_privacy = any(indicator in content.lower() for indicator in privacy_indicators)
                
                if has_privacy:
                    checks['passed'] += 1
                    checks['details'].append({'check': 'Privacy Policy', 'status': 'PASS'})
                else:
                    checks['failed'] += 1
                    checks['details'].append({'check': 'Privacy Policy', 'status': 'FAIL'})
            
            # Check for cookie consent
            cookie_indicators = ['cookie', 'consent', 'gdpr-consent']
            has_cookie_consent = any(indicator in content.lower() for indicator in cookie_indicators)
            
            if has_cookie_consent:
                checks['passed'] += 1
                checks['details'].append({'check': 'Cookie Consent', 'status': 'PASS'})
            else:
                checks['failed'] += 1
                checks['details'].append({'check': 'Cookie Consent', 'status': 'FAIL'})
            
            return {
                'standard': 'gdpr',
                'total_checks': 2,
                'passed_checks': checks['passed'],
                'failed_checks': checks['failed'],
                'details': checks['details']
            }
        except Exception as e:
            return {
                'standard': 'gdpr',
                'error': str(e)
            }
    
    async def _check_pci_compliance(self, url):
        """PCI DSS compliance checking"""
        try:
            # Check SSL/TLS
            ssl_info = await self._analyze_ssl_tls(url)
            
            checks = {
                'passed': 0,
                'failed': 0,
                'details': []
            }
            
            if ssl_info.get('secure', False):
                checks['passed'] += 1
                checks['details'].append({'check': 'Strong SSL/TLS', 'status': 'PASS'})
            else:
                checks['failed'] += 1
                checks['details'].append({'check': 'Strong SSL/TLS', 'status': 'FAIL'})
            
            # Check for sensitive data exposure
            async with self.session.get(url) as response:
                content = await response.text()
                
                sensitive_patterns = [
                    r'\b\d{16}\b',  # Credit card numbers
                    r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                ]
                
                has_sensitive_data = False
                for pattern in sensitive_patterns:
                    if re.search(pattern, content):
                        has_sensitive_data = True
                        break
                
                if not has_sensitive_data:
                    checks['passed'] += 1
                    checks['details'].append({'check': 'No Sensitive Data Exposure', 'status': 'PASS'})
                else:
                    checks['failed'] += 1
                    checks['details'].append({'check': 'No Sensitive Data Exposure', 'status': 'FAIL'})
            
            return {
                'standard': 'pci',
                'total_checks': 2,
                'passed_checks': checks['passed'],
                'failed_checks': checks['failed'],
                'details': checks['details']
            }
        except Exception as e:
            return {
                'standard': 'pci',
                'error': str(e)
            }
    
    async def _check_hipaa_compliance(self, url):
        """HIPAA compliance checking"""
        try:
            checks = {
                'passed': 0,
                'failed': 0,
                'details': []
            }
            
            # Check for secure transmission
            if url.startswith('https://'):
                checks['passed'] += 1
                checks['details'].append({'check': 'Secure Transmission (HTTPS)', 'status': 'PASS'})
            else:
                checks['failed'] += 1
                checks['details'].append({'check': 'Secure Transmission (HTTPS)', 'status': 'FAIL'})
            
            return {
                'standard': 'hipaa',
                'total_checks': 1,
                'passed_checks': checks['passed'],
                'failed_checks': checks['failed'],
                'details': checks['details']
            }
        except Exception as e:
            return {
                'standard': 'hipaa',
                'error': str(e)
            }
    
    async def _check_nist_compliance(self, url):
        """NIST cybersecurity framework compliance"""
        try:
            checks = {
                'passed': 0,
                'failed': 0,
                'details': []
            }
            
            # Basic NIST checks
            security_headers = await self._check_security_headers(url)
            if security_headers.get('secure', False):
                checks['passed'] += 1
                checks['details'].append({'check': 'Security Headers', 'status': 'PASS'})
            else:
                checks['failed'] += 1
                checks['details'].append({'check': 'Security Headers', 'status': 'FAIL'})
            
            return {
                'standard': 'nist',
                'total_checks': 1,
                'passed_checks': checks['passed'],
                'failed_checks': checks['failed'],
                'details': checks['details']
            }
        except Exception as e:
            return {
                'standard': 'nist',
                'error': str(e)
            }
    
    async def _check_owasp_compliance(self, url):
        """OWASP security standards compliance"""
        try:
            checks = {
                'passed': 0,
                'failed': 0,
                'details': []
            }
            
            # Run basic OWASP checks
            vuln_scan = await self._quick_vulnerability_check(url)
            if not vuln_scan:
                checks['passed'] += 1
                checks['details'].append({'check': 'No Critical Vulnerabilities', 'status': 'PASS'})
            else:
                checks['failed'] += 1
                checks['details'].append({'check': 'No Critical Vulnerabilities', 'status': 'FAIL'})
            
            return {
                'standard': 'owasp',
                'total_checks': 1,
                'passed_checks': checks['passed'],
                'failed_checks': checks['failed'],
                'details': checks['details']
            }
        except Exception as e:
            return {
                'standard': 'owasp',
                'error': str(e)
            }
    
    # Quick Scan Components
    
    async def _check_security_headers(self, url):
        """Comprehensive security headers check"""
        try:
            headers_analysis = await self._get_comprehensive_http_headers(url)
            return headers_analysis
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_ssl_tls(self, url):
        """SSL/TLS configuration analysis"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            ssl_info = await ssl_analyzer.analyze_ssl(domain)
            return ssl_info
        except Exception as e:
            return {'error': str(e)}
    
    async def _quick_vulnerability_check(self, url):
        """Quick vulnerability assessment"""
        try:
            vulnerabilities = []
            
            # Check for common vulnerabilities quickly
            quick_checks = [
                self._check_sql_injection_quick(url),
                self._check_xss_quick(url),
                self._check_csrf_quick(url)
            ]
            
            results = await asyncio.gather(*quick_checks)
            for result in results:
                if result:
                    vulnerabilities.append(result)
            
            return vulnerabilities
        except Exception as e:
            return [{'error': str(e)}]
    
    async def _check_content_security(self, url):
        """Content security analysis"""
        try:
            async with self.session.get(url) as response:
                content = await response.text()
                
                analysis = {
                    'mixed_content': False,
                    'insecure_forms': False,
                    'external_resources': []
                }
                
                # Check for mixed content
                if 'http:' in content and url.startswith('https://'):
                    analysis['mixed_content'] = True
                
                # Check form actions
                soup = BeautifulSoup(content, 'html.parser')
                forms = soup.find_all('form')
                for form in forms:
                    action = form.get('action', '')
                    if action.startswith('http://'):
                        analysis['insecure_forms'] = True
                
                return analysis
        except Exception as e:
            return {'error': str(e)}
    
    async def _check_exposed_information(self, url):
        """Check for exposed sensitive information"""
        try:
            async with self.session.get(url) as response:
                content = await response.text()
                headers = dict(response.headers)
                
                exposed_info = {
                    'emails': re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content),
                    'phone_numbers': re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', content),
                    'comments': re.findall(r'<!--.*?-->', content, re.DOTALL),
                    'server_info': headers.get('Server', ''),
                    'framework_info': headers.get('X-Powered-By', '')
                }
                
                return exposed_info
        except Exception as e:
            return {'error': str(e)}
    
    # Quick vulnerability check methods
    
    async def _check_sql_injection_quick(self, url):
        """Quick SQL injection check"""
        try:
            test_payload = "' OR '1'='1"
            test_url = f"{url}?id={test_payload}"
            async with self.session.get(test_url) as response:
                content = await response.text()
                if 'sql' in content.lower() or 'syntax' in content.lower():
                    return {
                        'title': 'Potential SQL Injection Vulnerability',
                        'severity': 'high',
                        'type': 'sql_injection'
                    }
            return None
        except Exception as e:
            return None
    
    async def _check_xss_quick(self, url):
        """Quick XSS check"""
        try:
            test_payload = "<script>alert('XSS')</script>"
            test_url = f"{url}?q={test_payload}"
            async with self.session.get(test_url) as response:
                content = await response.text()
                if test_payload in content:
                    return {
                        'title': 'Potential XSS Vulnerability',
                        'severity': 'medium',
                        'type': 'xss'
                    }
            return None
        except Exception as e:
            return None
    
    async def _check_csrf_quick(self, url):
        """Quick CSRF check"""
        try:
            async with self.session.get(url) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    inputs = form.find_all('input')
                    has_csrf_token = any(
                        input.get('name', '').lower() in ['csrf', 'csrfmiddlewaretoken', '_token'] 
                        for input in inputs
                    )
                    
                    if not has_csrf_token:
                        return {
                            'title': 'Potential CSRF Vulnerability',
                            'severity': 'medium',
                            'type': 'csrf'
                        }
            return None
        except Exception as e:
            return None
    
    def _calculate_quick_risk_score(self, findings):
        """Calculate risk score for quick scan"""
        risk_score = 0
        
        # Security headers weight: 25%
        headers = findings.get('security_headers', {})
        missing_headers = len(headers.get('missing_security_headers', []))
        risk_score += min(missing_headers * 5, 25)
        
        # SSL/TLS weight: 25%
        ssl_info = findings.get('ssl_tls', {})
        if not ssl_info.get('secure', False):
            risk_score += 25
        
        # Vulnerabilities weight: 30%
        vulnerabilities = findings.get('vulnerabilities', [])
        risk_score += min(len(vulnerabilities) * 10, 30)
        
        # Content security weight: 10%
        content_security = findings.get('content_security', {})
        if content_security.get('mixed_content', False):
            risk_score += 5
        if content_security.get('insecure_forms', False):
            risk_score += 5
        
        # Information exposure weight: 10%
        info_exposure = findings.get('information_exposure', {})
        exposed_emails = len(info_exposure.get('emails', []))
        risk_score += min(exposed_emails * 2, 10)
        
        return min(100, risk_score)
    
    async def close(self):
        """Clean up resources"""
        await self.session.close()
        self.executor.shutdown()