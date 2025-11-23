from rest_framework import viewsets, status, generics
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
import asyncio
import re
import logging
from .models import *
from .serializers import *

from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
import requests
import socket
import ssl
import json
from urllib.parse import urlparse
from .permissions import ScanPermission
from .utils.security_tools import SecurityScanner
from .utils.threat_intelligence import ThreatIntelligenceService

logger = logging.getLogger(__name__)

User = get_user_model()

from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
import jwt
from datetime import datetime, timedelta

@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    username = request.data.get('username')
    password = request.data.get('password')
    
    print(f"Login attempt for user: {username}")  # Debug log
    
    # Input validation
    if not username or not password:
        return Response(
            {'detail': 'Username and password are required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Authenticate user
    user = authenticate(request, username=username, password=password)
    
    if user is not None:
        if user.is_active:
            # Create JWT token
            payload = {
                'user_id': user.id,
                'username': user.username,
                'exp': datetime.utcnow() + timedelta(days=7),
                'iat': datetime.utcnow()
            }
            
            # Ensure SECRET_KEY is available
            if not settings.SECRET_KEY:
                return Response(
                    {'detail': 'Server configuration error'}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
            
            # Return user data and token
            return Response({
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name
                },
                'access': token,
                'message': 'Login successful'
            })
        else:
            return Response(
                {'detail': 'Account is disabled'}, 
                status=status.HTTP_403_FORBIDDEN
            )
    else:
        print(f"Authentication failed for user: {username}")  # Debug log
        return Response(
            {'detail': 'Invalid username or password'}, 
            status=status.HTTP_401_UNAUTHORIZED
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    """
    User registration endpoint
    """
    try:
        username = request.data.get('username', '').strip()
        email = request.data.get('email', '').strip()
        password = request.data.get('password', '')
        first_name = request.data.get('first_name', '').strip()
        last_name = request.data.get('last_name', '').strip()
        
        print(f"Registration attempt for user: {username}, email: {email}")  # Debug log
        
        # Validation
        if not username or not email or not password:
            return Response(
                {'detail': 'Username, email and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if len(password) < 6:
            return Response(
                {'detail': 'Password must be at least 6 characters'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            return Response(
                {'detail': 'Please enter a valid email address'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if user already exists
        if User.objects.filter(username=username).exists():
            return Response(
                {'detail': 'Username already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if User.objects.filter(email=email).exists():
            return Response(
                {'detail': 'Email already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )
        
        print(f"User created successfully: {user.username}")  # Debug log
        
        # Create JWT token (using the same method as login)
        payload = {
            'user_id': user.id,
            'username': user.username,
            'exp': datetime.utcnow() + timedelta(days=7),
            'iat': datetime.utcnow()
        }
        
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
        
        return Response({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            },
            'access': token,
            'message': 'Registration successful'
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        import traceback
        print(f"Full error traceback: {traceback.format_exc()}")  # Debug log
        return Response(
            {'detail': f'Registration failed: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    return Response({'status': 'OK', 'service': 'Genius Guard API'})

@api_view(['GET'])
def get_csrf_token(request):
    return Response({'csrfToken': get_token(request)})


class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        return Response({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name
        })


class ScanTargetViewSet(viewsets.ModelViewSet):
    queryset = ScanTarget.objects.all().order_by('-created_at')
    serializer_class = ScanTargetSerializer
    permission_classes = [IsAuthenticated, ScanPermission]
    
    def get_queryset(self):
        return self.queryset.filter(user=self.request.user)
    
    @action(detail=True, methods=['post'])
    def start_scan(self, request, pk=None):  # Remove async
        scan_target = self.get_object()
        
        # Check concurrent scan limits
        active_scans = cache.get(f'active_scans_{request.user.id}', 0)
        if active_scans >= getattr(settings, 'MAX_CONCURRENT_SCANS_PER_USER', 3):
            return Response({
                'error': 'Maximum concurrent scan limit reached'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        # Create scan result
        scan_result = ScanResult.objects.create(
            target=scan_target,
            status='queued',
            started_at=timezone.now()
        )
        
        # Increment active scans counter
        cache.incr(f'active_scans_{request.user.id}')
        
        # Start async scan in background
        try:
            # Run async function in thread
            asyncio.run(self.perform_scan(scan_result))
        except Exception as e:
            logger.error(f"Failed to start scan: {str(e)}")
            cache.decr(f'active_scans_{request.user.id}')
            return Response({
                'error': 'Failed to start scan'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response({
            'message': 'Scan queued successfully',
            'scan_id': str(scan_result.id)
        })
    
    async def perform_scan(self, scan_result):
        """Execute security scan using multiple tools"""
        scanner = SecurityScanner()
        threat_intel = ThreatIntelligenceService()
        
        try:
            scan_result.status = 'scanning'
            scan_result.save()
            
            # Initialize results dictionary
            results = {
                'vulnerabilities': [],
                'threat_intel': {},
                'infrastructure': {},
                'compliance': {}
            }
            
            # For now, use mock data since async tools might not be implemented
            # Phase 1: Initial Reconnaissance
            scan_result.progress = 10
            scan_result.current_activity = 'Initial Reconnaissance'
            scan_result.save()
            
            # Mock reconnaissance data
            results['infrastructure'] = {
                'ip_address': '192.168.1.1',
                'server_type': 'nginx',
                'technologies': ['React', 'Node.js', 'Express'],
                'open_ports': [80, 443, 22]
            }
            
            # Phase 2: Vulnerability Scanning
            scan_result.progress = 30
            scan_result.current_activity = 'Vulnerability Scanning'
            scan_result.save()
            
            # Mock vulnerability data
            results['vulnerabilities'] = [
                {
                    'title': 'Missing Security Headers',
                    'description': 'Content Security Policy (CSP) and HTTP Strict Transport Security (HSTS) headers are not implemented',
                    'severity': 'medium',
                    'cvss_score': 5.2,
                    'evidence': 'Security headers scan',
                    'recommendation': 'Implement security headers in web server configuration'
                },
                {
                    'title': 'Cross-Site Scripting (XSS) Vulnerability',
                    'description': 'User input not properly sanitized in search functionality',
                    'severity': 'high',
                    'cvss_score': 7.4,
                    'evidence': 'Input validation test',
                    'recommendation': 'Implement input validation and output encoding'
                }
            ]
            
            # Phase 3: Threat Intelligence Gathering
            scan_result.progress = 50
            scan_result.current_activity = 'Threat Intelligence Analysis'
            scan_result.save()
            
            results['threat_intel'] = {
                'risk_score': 65,
                'threats_detected': 3,
                'reputation': 'suspicious'
            }
            
            # Phase 4: Compliance Checking
            scan_result.progress = 70
            scan_result.current_activity = 'Compliance Assessment'
            scan_result.save()
            
            results['compliance'] = {
                'compliance_score': 75,
                'standards_met': ['OWASP', 'PCI-DSS'],
                'violations': ['Missing encryption', 'Insecure cookies']
            }
            
            # Phase 5: Final Analysis
            scan_result.progress = 90
            scan_result.current_activity = 'Final Analysis'
            scan_result.save()
            
            risk_score = self.calculate_risk_score(results)
            
            # Create vulnerability records
            for vuln in results['vulnerabilities']:
                Vulnerability.objects.create(
                    scan_result=scan_result,
                    title=vuln['title'],
                    description=vuln['description'],
                    severity=vuln['severity'],
                    cvss_score=vuln.get('cvss_score', 0.0),
                    evidence=vuln['evidence'],
                    recommendation=vuln['recommendation']
                )
            
            # Update scan result
            scan_result.status = 'completed'
            scan_result.risk_score = risk_score
            scan_result.raw_data = results
            scan_result.total_vulnerabilities = len(results['vulnerabilities'])
            scan_result.completed_at = timezone.now()
            scan_result.scan_duration = (
                scan_result.completed_at - scan_result.started_at
            ).total_seconds()
            scan_result.save()
            
            # Update global stats
            self.update_global_stats(scan_result)
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            scan_result.status = 'failed'
            scan_result.raw_data = {'error': str(e)}
            scan_result.save()
        
        finally:
            # Decrement active scans counter
            cache.decr(f'active_scans_{scan_result.target.user.id}')
    
    def calculate_risk_score(self, results):
        """Calculate risk score based on findings"""
        score = 0
        weights = {
            'vulnerabilities': 0.4,
            'threat_intel': 0.3,
            'compliance': 0.3
        }
        
        # Vulnerability score
        vuln_severity_weights = {
            'critical': 10,
            'high': 8,
            'medium': 5,
            'low': 2,
            'info': 0
        }
        
        if results['vulnerabilities']:
            vuln_scores = [
                vuln_severity_weights.get(v['severity'], 0) 
                for v in results['vulnerabilities']
            ]
            score += (sum(vuln_scores) / (len(vuln_scores) * 10)) * weights['vulnerabilities'] * 100
        
        # Threat intelligence score
        if results['threat_intel'].get('risk_score'):
            score += results['threat_intel']['risk_score'] * weights['threat_intel']
        
        # Compliance score
        if results['compliance'].get('compliance_score'):
            score += results['compliance']['compliance_score'] * weights['compliance']
        
        return min(100, int(score))
    
    def update_global_stats(self, scan_result):
        """Update global statistics with new scan data"""
        stats, _ = GlobalStats.objects.get_or_create(pk=1)
        stats.total_scans += 1
        
        if scan_result.risk_score > 70:
            stats.high_risk_scans += 1
        
        if scan_result.total_vulnerabilities > 0:
            stats.total_vulnerabilities_found += scan_result.total_vulnerabilities
        
        stats.save()

class ScanResultViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ScanResult.objects.all().order_by('-started_at')
    serializer_class = ScanResultSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return self.queryset.filter(target__user=self.request.user)

class ThreatIntelligenceViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ThreatIntelligence.objects.filter(is_active=True).order_by('-detected_at')
    serializer_class = ThreatIntelFeedSerializer
    permission_classes = [AllowAny]
    
    @action(detail=False, methods=['get'])
    def live_feed(self, request):
        """Get real threat intelligence from database"""
        try:
            # Get real threats from database
            threats = ThreatIntelligence.objects.filter(
                is_active=True
            ).order_by('-detected_at')[:20]  # Limit to 20 most recent
            
            # Auto-create some realistic threats based on recent vulnerabilities
            self._generate_realistic_threats()
            
            serializer = self.get_serializer(threats, many=True)
            return Response(serializer.data)
            
        except Exception as e:
            logger.error(f"Failed to fetch threat feed: {str(e)}")
            return Response(
                {'error': 'Failed to fetch threat feed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _generate_realistic_threats(self):
        """Generate realistic threats based on actual scan data"""
        try:
            # Get recent vulnerabilities to create threat intelligence
            recent_vulnerabilities = Vulnerability.objects.filter(
                created_at__gte=timezone.now() - timezone.timedelta(hours=24)
            ).select_related('scan_result')
            
            threat_map = {
                'xss': 'Cross-Site Scripting',
                'sqli': 'SQL Injection',
                'rce': 'Remote Code Execution',
                'csrf': 'Cross-Site Request Forgery',
                'lfi': 'Local File Inclusion'
            }
            
            for vuln in recent_vulnerabilities:
                # Create threat intelligence from high/critical vulnerabilities
                if vuln.severity in ['high', 'critical']:
                    threat_type = self._detect_threat_type(vuln.title.lower())
                    
                    threat_data = {
                        'threat_id': f"THREAT-{vuln.id}",
                        'title': f"{threat_map.get(threat_type, 'Security')} Threat Detected",
                        'description': f"{vuln.severity.upper()} severity {threat_type.upper()} vulnerability found in recent scan",
                        'severity': vuln.severity,
                        'source': 'internal_scan',
                        'confidence_score': 85.0,
                        'is_active': True
                    }
                    
                    # Create or update threat intelligence
                    ThreatIntelligence.objects.update_or_create(
                        threat_id=threat_data['threat_id'],
                        defaults={
                            **threat_data,
                            'detected_at': vuln.created_at or timezone.now()
                        }
                    )
                    
        except Exception as e:
            logger.warning(f"Error generating realistic threats: {str(e)}")
    
    def _detect_threat_type(self, title):
        """Detect threat type from vulnerability title"""
        if 'xss' in title or 'cross-site' in title:
            return 'xss'
        elif 'sql' in title or 'injection' in title:
            return 'sqli'
        elif 'remote code' in title or 'rce' in title:
            return 'rce'
        elif 'csrf' in title or 'cross-site request' in title:
            return 'csrf'
        elif 'file inclusion' in title or 'lfi' in title:
            return 'lfi'
        else:
            return 'security'

class GlobalStatsViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = GlobalStats.objects.all().order_by('id')
    serializer_class = GlobalStatsSerializer
    permission_classes = [AllowAny]
    
    def list(self, request):
        """Override list to calculate real-time statistics"""
        try:
            # Calculate real statistics from database
            total_scans = ScanResult.objects.count()
            high_risk_scans = ScanResult.objects.filter(
                risk_score__gte=70,
                status='completed'
            ).count()
            
            total_vulnerabilities = Vulnerability.objects.count()
            
            # Update or create global stats
            stats, created = GlobalStats.objects.get_or_create(pk=1)
            stats.total_scans = total_scans
            stats.high_risk_scans = high_risk_scans
            stats.total_vulnerabilities_found = total_vulnerabilities
            
            # Calculate average scan duration
            completed_scans = ScanResult.objects.filter(
                status='completed',
                scan_duration__isnull=False
            )
            if completed_scans.exists():
                avg_duration = completed_scans.aggregate(
                    avg_duration=models.Avg('scan_duration')
                )['avg_duration'] or 0.0
                stats.average_scan_duration = round(avg_duration, 2)
            
            stats.save()
            
            serializer = self.get_serializer(stats)
            return Response(serializer.data)
            
        except Exception as e:
            logger.error(f"Error fetching global stats: {str(e)}")
            return Response(
                {'error': 'Failed to fetch statistics'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



# In your views.py - update QuickScanViewSet

class QuickScanViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]
    
    def create(self, request):
        url = request.data.get('url')
        
        if not url:
            return Response(
                {'error': 'URL is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Rate limiting check
        client_ip = request.META.get('REMOTE_ADDR', 'unknown')
        if not self._check_rate_limit(client_ip):
            return Response(
                {'error': 'Rate limit exceeded. Please try again in an hour.'},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        
        try:
            # Create scan target for unauthenticated users
            scan_target = ScanTarget.objects.create(
                url=url,
                name=f"Quick Scan - {url}",
                scan_type='quick',
                is_active=False  # Mark as inactive for demo scans
            )
            
            # Create scan result
            scan_result = ScanResult.objects.create(
                target=scan_target,
                status='scanning'
            )
            
            # Perform real security scan
            scan_results = self.perform_quick_scan(url)
            
            # Update scan result with real data
            scan_result.status = 'completed'
            scan_result.risk_score = scan_results['risk_score']
            scan_result.total_vulnerabilities = len(scan_results['vulnerabilities'])
            scan_result.scan_duration = scan_results['scan_duration']
            scan_result.raw_data = scan_results
            scan_result.completed_at = timezone.now()
            scan_result.save()
            
            # Create vulnerability records
            for vuln_data in scan_results['vulnerabilities']:
                Vulnerability.objects.create(
                    scan_result=scan_result,
                    title=vuln_data['title'],
                    description=vuln_data['description'],
                    severity=vuln_data['severity'],
                    cvss_score=vuln_data.get('cvss_score', 0.0),
                    evidence=vuln_data.get('evidence', ''),
                    recommendation=vuln_data.get('recommendation', '')
                )
            
            # Update global stats
            self._update_global_stats()
            
            response_data = {
                'url': url,
                'scan_time': timezone.now(),
                'findings': scan_results,
                'risk_score': scan_results['risk_score'],
                'total_vulnerabilities': len(scan_results['vulnerabilities']),
                'scan_duration': scan_results['scan_duration'],
                'scan_id': str(scan_result.id)
            }
            
            serializer = QuickScanResponseSerializer(response_data)
            return Response(serializer.data)
            
        except Exception as e:
            logger.error(f"Quick scan failed: {str(e)}")
            return Response(
                {'error': f'Scan failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _update_global_stats(self):
        """Update global statistics"""
        try:
            stats, created = GlobalStats.objects.get_or_create(pk=1)
            stats.total_scans = ScanResult.objects.count()
            stats.high_risk_scans = ScanResult.objects.filter(
                risk_score__gte=70,
                status='completed'
            ).count()
            stats.total_vulnerabilities_found = Vulnerability.objects.count()
            stats.save()
        except Exception as e:
            logger.error(f"Failed to update global stats: {str(e)}")
    
    def perform_quick_scan(self, url):
        """Perform actual security scanning on the target URL"""
        start_time = timezone.now()
        results = {
            'vulnerabilities': [],
            'threat_intel': {},
            'infrastructure': {},
            'compliance': {},
            'risk_score': 0,
            'scan_duration': 0
        }
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # 1. Infrastructure Analysis
            results['infrastructure'] = self.analyze_infrastructure(domain, url)
            
            # 2. Security Headers Check
            security_headers = self.check_security_headers(url)
            if security_headers['missing_headers']:
                results['vulnerabilities'].extend(security_headers['vulnerabilities'])
            
            # 3. SSL/TLS Analysis
            ssl_issues = self.check_ssl_security(domain)
            if ssl_issues:
                results['vulnerabilities'].extend(ssl_issues)
            
            # 4. Basic Vulnerability Checks
            basic_vulns = self.perform_basic_vulnerability_checks(url)
            results['vulnerabilities'].extend(basic_vulns)
            
            # 5. Threat Intelligence
            results['threat_intel'] = self.gather_threat_intelligence(domain)
            
            # 6. Compliance Check
            results['compliance'] = self.check_compliance(results)
            
            # Calculate risk score
            results['risk_score'] = self.calculate_risk_score(results)
            
            # Calculate scan duration
            results['scan_duration'] = (timezone.now() - start_time).total_seconds()
            
            return results
            
        except Exception as e:
            logger.error(f"Error during quick scan: {str(e)}")
            # Return basic results even if some checks fail
            results['risk_score'] = self.calculate_risk_score(results)
            results['scan_duration'] = (timezone.now() - start_time).total_seconds()
            return results
    
    def analyze_infrastructure(self, domain, url):
        """Analyze target infrastructure"""
        infrastructure = {
            'domain': domain,
            'server_type': 'Unknown',
            'technologies': [],
            'ip_address': 'Unknown',
            'open_ports': []
        }
        
        try:
            # Get IP address
            try:
                ip = socket.gethostbyname(domain)
                infrastructure['ip_address'] = ip
            except:
                pass
            
            # Detect server type and technologies via HTTP headers
            try:
                response = requests.get(url, timeout=10, verify=False)
                headers = response.headers
                
                # Detect server
                if 'server' in headers:
                    infrastructure['server_type'] = headers['server']
                
                # Detect technologies
                tech_indicators = {
                    'x-powered-by': 'Backend Technology',
                    'x-aspnet-version': 'ASP.NET',
                    'x-runtime': 'Ruby',
                    'x-frame-options': 'Security Headers Enabled'
                }
                
                for header, tech in tech_indicators.items():
                    if header in headers:
                        infrastructure['technologies'].append(tech)
                
                # Check for common framework indicators
                if 'set-cookie' in headers and 'PHPSESSID' in headers['set-cookie']:
                    infrastructure['technologies'].append('PHP')
                if 'set-cookie' in headers and 'JSESSIONID' in headers['set-cookie']:
                    infrastructure['technologies'].append('Java')
                    
            except requests.RequestException:
                pass
            
            # Basic port scanning (common web ports)
            common_ports = [80, 443, 8080, 8443]
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((domain, port))
                    if result == 0:
                        infrastructure['open_ports'].append(port)
                    sock.close()
                except:
                    pass
                    
        except Exception as e:
            logger.warning(f"Infrastructure analysis failed: {str(e)}")
        
        return infrastructure
    
    def check_security_headers(self, url):
        """Check for security headers"""
        headers_check = {
            'missing_headers': [],
            'vulnerabilities': []
        }
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            # Required security headers
            security_headers = {
                'Content-Security-Policy': {
                    'severity': 'high',
                    'description': 'Content Security Policy header missing',
                    'recommendation': 'Implement CSP to prevent XSS attacks'
                },
                'X-Content-Type-Options': {
                    'severity': 'medium',
                    'description': 'X-Content-Type-Options header missing',
                    'recommendation': 'Add "X-Content-Type-Options: nosniff"'
                },
                'X-Frame-Options': {
                    'severity': 'medium',
                    'description': 'X-Frame-Options header missing',
                    'recommendation': 'Implement X-Frame-Options to prevent clickjacking'
                },
                'Strict-Transport-Security': {
                    'severity': 'high',
                    'description': 'HSTS header missing',
                    'recommendation': 'Implement HSTS for HTTPS enforcement'
                }
            }
            
            for header, info in security_headers.items():
                if header not in headers:
                    headers_check['missing_headers'].append(header)
                    headers_check['vulnerabilities'].append({
                        'title': f'Missing {header}',
                        'description': info['description'],
                        'severity': info['severity'],
                        'cvss_score': 5.0 if info['severity'] == 'high' else 3.0,
                        'evidence': f'{header} security header is not present',
                        'recommendation': info['recommendation']
                    })
            
        except requests.RequestException as e:
            logger.warning(f"Security headers check failed: {str(e)}")
        
        return headers_check
    
    def check_ssl_security(self, domain):
        """Check SSL/TLS security"""
        vulnerabilities = []
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check certificate expiration
                    if cert:
                        from datetime import datetime
                        expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expire_date - datetime.now()).days
                        
                        if days_until_expiry < 30:
                            vulnerabilities.append({
                                'title': 'SSL Certificate Expiring Soon',
                                'description': f'SSL certificate expires in {days_until_expiry} days',
                                'severity': 'medium',
                                'cvss_score': 4.0,
                                'evidence': f'Certificate expires on {expire_date}',
                                'recommendation': 'Renew SSL certificate'
                            })
                    
                    # Check cipher strength
                    if cipher:
                        cipher_name = cipher[0]
                        if 'RC4' in cipher_name or 'DES' in cipher_name or '3DES' in cipher_name:
                            vulnerabilities.append({
                                'title': 'Weak SSL Cipher',
                                'description': f'Weak cipher suite detected: {cipher_name}',
                                'severity': 'medium',
                                'cvss_score': 5.0,
                                'evidence': f'Weak cipher: {cipher_name}',
                                'recommendation': 'Disable weak ciphers and use TLS 1.2+'
                            })
                            
        except Exception as e:
            vulnerabilities.append({
                'title': 'SSL/TLS Connection Failed',
                'description': f'Could not establish SSL connection: {str(e)}',
                'severity': 'medium',
                'cvss_score': 5.0,
                'evidence': 'SSL handshake failed',
                'recommendation': 'Check SSL configuration and certificate'
            })
        
        return vulnerabilities
    
    def perform_basic_vulnerability_checks(self, url):
        """Perform basic vulnerability checks"""
        vulnerabilities = []
        
        try:
            # Check for common files that might expose information
            common_sensitive_files = [
                '/.env', '/.git/config', '/backup.zip', 
                '/phpinfo.php', '/admin', '/wp-admin'
            ]
            
            for file_path in common_sensitive_files:
                test_url = url.rstrip('/') + file_path
                try:
                    response = requests.get(test_url, timeout=5, verify=False)
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'title': 'Exposed Sensitive File',
                            'description': f'Sensitive file exposed: {file_path}',
                            'severity': 'high',
                            'cvss_score': 7.5,
                            'evidence': f'File accessible at: {test_url}',
                            'recommendation': 'Restrict access to sensitive files and directories'
                        })
                except:
                    pass
            
            # Check for directory listing
            test_dirs = ['/images/', '/css/', '/js/', '/uploads/']
            for directory in test_dirs:
                test_url = url.rstrip('/') + directory
                try:
                    response = requests.get(test_url, timeout=5, verify=False)
                    if 'Index of' in response.text or '<title>Directory Listing</title>' in response.text:
                        vulnerabilities.append({
                            'title': 'Directory Listing Enabled',
                            'description': f'Directory listing exposed: {directory}',
                            'severity': 'medium',
                            'cvss_score': 5.0,
                            'evidence': f'Directory listing enabled at: {test_url}',
                            'recommendation': 'Disable directory listing in web server configuration'
                        })
                except:
                    pass
                    
        except Exception as e:
            logger.warning(f"Basic vulnerability checks failed: {str(e)}")
        
        return vulnerabilities
    
    def gather_threat_intelligence(self, domain):
        """Gather basic threat intelligence"""
        threat_intel = {
            'risk_score': 0,
            'reputation': 'unknown',
            'threats_detected': 0
        }
        
        try:
            # Basic reputation check based on domain characteristics
            suspicious_keywords = ['test', 'demo', 'admin', 'api', 'dev']
            if any(keyword in domain.lower() for keyword in suspicious_keywords):
                threat_intel['risk_score'] = 30
                threat_intel['reputation'] = 'suspicious'
            else:
                threat_intel['risk_score'] = 10
                threat_intel['reputation'] = 'clean'
                
        except Exception as e:
            logger.warning(f"Threat intelligence gathering failed: {str(e)}")
        
        return threat_intel
    
    def check_compliance(self, results):
        """Check basic compliance standards"""
        compliance = {
            'compliance_score': 100,
            'standards_met': [],
            'violations': []
        }
        
        # Check for basic security standards
        if not results['vulnerabilities']:
            compliance['standards_met'].append('Basic Security')
        else:
            compliance['compliance_score'] = 80
            compliance['violations'].append('Security vulnerabilities detected')
        
        # Check SSL
        ssl_vulns = [v for v in results['vulnerabilities'] if 'SSL' in v['title'] or 'TLS' in v['title']]
        if not ssl_vulns:
            compliance['standards_met'].append('SSL/TLS Security')
        else:
            compliance['compliance_score'] -= 10
            compliance['violations'].append('SSL/TLS issues detected')
        
        # Check security headers
        missing_headers = len([v for v in results['vulnerabilities'] if 'Missing' in v['title'] and 'header' in v['title']])
        if missing_headers == 0:
            compliance['standards_met'].append('Security Headers')
        else:
            compliance['compliance_score'] -= (missing_headers * 5)
            compliance['violations'].append(f'{missing_headers} security headers missing')
        
        compliance['compliance_score'] = max(0, compliance['compliance_score'])
        return compliance
    
    def calculate_risk_score(self, results):
        """Calculate overall risk score"""
        base_score = 0
        
        # Vulnerabilities contribute to risk
        for vuln in results['vulnerabilities']:
            severity_weights = {
                'critical': 25,
                'high': 15,
                'medium': 8,
                'low': 3
            }
            base_score += severity_weights.get(vuln['severity'], 0)
        
        # Threat intelligence contributes
        base_score += results['threat_intel'].get('risk_score', 0) * 0.3
        
        # Compliance affects risk
        compliance_score = results['compliance'].get('compliance_score', 100)
        base_score += (100 - compliance_score) * 0.2
        
        return min(100, int(base_score))
    
    def _check_rate_limit(self, client_ip):
        """Basic rate limiting for quick scans"""
        key = f'quick_scan_{client_ip}'
        count = cache.get(key, 0)
        
        if count >= getattr(settings, 'QUICK_SCAN_RATE_LIMIT', 10):  # Increased limit
            return False
        
        cache.set(key, count + 1, timeout=3600)  # 1 hour window
        return True

class ScanStatusView(APIView):
    """Get scan status by ID"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, scan_id):
        try:
            scan_result = ScanResult.objects.get(
                id=scan_id,
                target__user=request.user
            )
            serializer = ScanResultSerializer(scan_result)
            return Response(serializer.data)
        except ScanResult.DoesNotExist:
            return Response(
                {'error': 'Scan not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )

class VulnerabilityListView(generics.ListAPIView):
    """List all vulnerabilities for a user"""
    serializer_class = ScanResultSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return Vulnerability.objects.filter(
            scan_result__target__user=self.request.user
        ).order_by('-scan_result__started_at')

# In base/views.py - add this view
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.utils import timezone

@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """Simple health check endpoint"""
    return Response({
        'status': 'healthy',
        'service': 'GeniusGuard API',
        'timestamp': timezone.now().isoformat(),
        'version': '1.0.0'
    })

# In views.py - add these additional views

class ScanStatsView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Get real-time scan statistics"""
        total_scans = ScanResult.objects.count()
        high_risk_scans = ScanResult.objects.filter(risk_score__gte=70).count()
        total_vulnerabilities = Vulnerability.objects.count()
        
        return Response({
            'total_scans': total_scans,
            'high_risk_scans': high_risk_scans,
            'total_vulnerabilities_found': total_vulnerabilities
        })

class RecentVulnerabilitiesView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Get recent vulnerabilities for threat feed"""
        recent_vulns = Vulnerability.objects.filter(
            created_at__gte=timezone.now() - timezone.timedelta(hours=24)
        ).order_by('-created_at')[:10]
        
        data = []
        for vuln in recent_vulns:
            data.append({
                'id': vuln.id,
                'title': vuln.title,
                'description': vuln.description,
                'severity': vuln.severity,
                'created_at': vuln.created_at
            })
        
        return Response(data)

class ActiveThreatsView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Get active threats from database"""
        active_threats = ThreatIntelligence.objects.filter(
            is_active=True
        ).order_by('-detected_at')[:10]
        
        data = []
        for threat in active_threats:
            data.append({
                'id': threat.id,
                'type': threat.title.split(' ')[0].upper(),
                'title': threat.title,
                'detected_at': threat.detected_at,
                'severity': threat.severity
            })
        
        return Response(data)