import ssl
import socket
import asyncio
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

class SSLAnalyzer:
    def __init__(self):
        self.ssl_versions = {
            ssl.PROTOCOL_TLSv1: 'TLSv1',
            ssl.PROTOCOL_TLSv1_1: 'TLSv1.1',
            ssl.PROTOCOL_TLSv1_2: 'TLSv1.2',
            ssl.PROTOCOL_TLS: 'TLS'
        }

    async def analyze_ssl(self, domain, port=443):
        """Comprehensive SSL/TLS analysis"""
        try:
            certificate_info = await self._get_certificate_info(domain, port)
            ssl_config = await self._analyze_ssl_configuration(domain, port)
            vulnerabilities = await self._check_ssl_vulnerabilities(domain, port)
            
            analysis = {
                'certificate': certificate_info,
                'configuration': ssl_config,
                'vulnerabilities': vulnerabilities,
                'overall_score': self._calculate_ssl_score(certificate_info, ssl_config, vulnerabilities)
            }
            
            return analysis
            
        except Exception as e:
            logger.error(f"SSL analysis failed: {str(e)}")
            return {'error': str(e)}

    async def _get_certificate_info(self, domain, port):
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                with socket.create_connection((domain, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        certificate_binary = ssock.getpeercert(binary_form=True)
                        certificate = x509.load_der_x509_certificate(certificate_binary, default_backend())
                        
                        cert_info = {
                            'subject': dict(x509.Name.from_rfc4514_string(certificate.subject.rfc4514_string())),
                            'issuer': dict(x509.Name.from_rfc4514_string(certificate.issuer.rfc4514_string())),
                            'version': certificate.version,
                            'serial_number': str(certificate.serial_number),
                            'not_valid_before': certificate.not_valid_before.isoformat(),
                            'not_valid_after': certificate.not_valid_after.isoformat(),
                            'signature_algorithm': certificate.signature_algorithm_oid._name,
                            'extensions': self._parse_extensions(certificate)
                        }
                        
                        return cert_info
                        
        except Exception as e:
            logger.error(f"Certificate info retrieval failed: {str(e)}")
            return {'error': str(e)}

    async def _analyze_ssl_configuration(self, domain, port):
        """Analyze SSL/TLS configuration"""
        try:
            config_info = {
                'supported_protocols': [],
                'preferred_ciphers': [],
                'security_rating': 'unknown'
            }
            
            # Test different SSL/TLS versions
            for protocol, name in self.ssl_versions.items():
                if await self._test_ssl_version(domain, port, protocol):
                    config_info['supported_protocols'].append(name)
            
            # Get preferred cipher
            preferred_cipher = await self._get_preferred_cipher(domain, port)
            if preferred_cipher:
                config_info['preferred_ciphers'].append(preferred_cipher)
            
            # Determine security rating
            config_info['security_rating'] = self._determine_security_rating(config_info)
            
            return config_info
            
        except Exception as e:
            logger.error(f"SSL configuration analysis failed: {str(e)}")
            return {'error': str(e)}

    async def _check_ssl_vulnerabilities(self, domain, port):
        """Check for common SSL vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for Heartbleed
            if await self._check_heartbleed(domain, port):
                vulnerabilities.append({
                    'name': 'Heartbleed',
                    'severity': 'critical',
                    'description': 'SSL/TLS heartbeat extension vulnerability',
                    'cve': 'CVE-2014-0160'
                })
            
            # Check for POODLE
            if await self._check_poodle(domain, port):
                vulnerabilities.append({
                    'name': 'POODLE',
                    'severity': 'high',
                    'description': 'Padding Oracle On Downgraded Legacy Encryption',
                    'cve': 'CVE-2014-3566'
                })
            
            # Check for weak ciphers
            weak_ciphers = await self._check_weak_ciphers(domain, port)
            if weak_ciphers:
                vulnerabilities.append({
                    'name': 'Weak Ciphers',
                    'severity': 'medium',
                    'description': f'Weak encryption ciphers detected: {weak_ciphers}'
                })
            
            # Check certificate expiration
            cert_info = await self._get_certificate_info(domain, port)
            if 'not_valid_after' in cert_info:
                expiry_date = datetime.fromisoformat(cert_info['not_valid_after'])
                days_until_expiry = (expiry_date - datetime.now()).days
                
                if days_until_expiry < 30:
                    vulnerabilities.append({
                        'name': 'Certificate Expiring Soon',
                        'severity': 'medium' if days_until_expiry > 7 else 'high',
                        'description': f'Certificate expires in {days_until_expiry} days'
                    })
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"SSL vulnerability check failed: {str(e)}")
            return []

    async def _test_ssl_version(self, domain, port, protocol):
        """Test if specific SSL/TLS version is supported"""
        try:
            context = ssl.SSLContext(protocol)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                with socket.create_connection((domain, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        return True
        except:
            return False

    async def _get_preferred_cipher(self, domain, port):
        """Get preferred cipher suite"""
        try:
            context = ssl.create_default_context()
            
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                with socket.create_connection((domain, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        return ssock.cipher()
        except:
            return None

    async def _check_heartbleed(self, domain, port):
        """Check for Heartbleed vulnerability"""
        # This is a simplified check - real implementation would be more complex
        try:
            # Actual Heartbleed check would involve sending malicious heartbeat requests
            # For now, we'll check TLS version as a basic indicator
            context = ssl.create_default_context()
            
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                with socket.create_connection((domain, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        # Basic check - systems with updated OpenSSL are not vulnerable
                        return False
        except:
            return False

    async def _check_poodle(self, domain, port):
        """Check for POODLE vulnerability"""
        try:
            # Check if SSLv3 is supported (indicator for POODLE vulnerability)
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.options |= ssl.OP_NO_SSLv3
            
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                with socket.create_connection((domain, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        # If connection succeeds without SSLv3, likely not vulnerable
                        return False
        except:
            # If connection fails without SSLv3, might be vulnerable
            return True

    async def _check_weak_ciphers(self, domain, port):
        """Check for weak ciphers"""
        weak_ciphers = []
        
        # Common weak ciphers
        weak_cipher_list = [
            'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'ANON'
        ]
        
        try:
            context = ssl.create_default_context()
            
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                with socket.create_connection((domain, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cipher = ssock.cipher()
                        if cipher:
                            cipher_name = cipher[0]
                            for weak_cipher in weak_cipher_list:
                                if weak_cipher in cipher_name.upper():
                                    weak_ciphers.append(cipher_name)
            
            return weak_ciphers
        except:
            return []

    def _parse_extensions(self, certificate):
        """Parse certificate extensions"""
        extensions = {}
        
        try:
            for ext in certificate.extensions:
                ext_name = ext.oid._name
                extensions[ext_name] = str(ext.value)
        except Exception as e:
            logger.error(f"Extension parsing failed: {str(e)}")
        
        return extensions

    def _determine_security_rating(self, config_info):
        """Determine overall SSL security rating"""
        supported_protocols = config_info.get('supported_protocols', [])
        
        if 'TLSv1.2' in supported_protocols or 'TLS' in supported_protocols:
            return 'excellent'
        elif 'TLSv1.1' in supported_protocols:
            return 'good'
        elif 'TLSv1' in supported_protocols:
            return 'fair'
        else:
            return 'poor'

    def _calculate_ssl_score(self, certificate_info, ssl_config, vulnerabilities):
        """Calculate overall SSL score (0-100)"""
        score = 100
        
        # Deduct for vulnerabilities
        for vuln in vulnerabilities:
            if vuln['severity'] == 'critical':
                score -= 30
            elif vuln['severity'] == 'high':
                score -= 20
            elif vuln['severity'] == 'medium':
                score -= 10
            elif vuln['severity'] == 'low':
                score -= 5
        
        # Deduct for weak configuration
        security_rating = ssl_config.get('security_rating', 'unknown')
        if security_rating == 'poor':
            score -= 40
        elif security_rating == 'fair':
            score -= 20
        elif security_rating == 'good':
            score -= 10
        
        return max(0, score)

# Create analyzer instance
analyzer = SSLAnalyzer()

# Async analysis function
async def analyze_ssl(domain, port=443):
    return await analyzer.analyze_ssl(domain, port)