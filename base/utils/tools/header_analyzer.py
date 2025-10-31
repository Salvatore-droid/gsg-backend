import aiohttp
import asyncio
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class HeaderAnalyzer:
    def __init__(self):
        self.security_headers = {
            'Content-Security-Policy': {
                'required': True,
                'description': 'Prevents XSS attacks by controlling resources the browser is allowed to load',
                'severity': 'high'
            },
            'Strict-Transport-Security': {
                'required': True,
                'description': 'Forces browsers to use HTTPS instead of HTTP',
                'severity': 'high'
            },
            'X-Content-Type-Options': {
                'required': True,
                'description': 'Prevents MIME type sniffing',
                'severity': 'medium'
            },
            'X-Frame-Options': {
                'required': True,
                'description': 'Prevents clickjacking attacks',
                'severity': 'high'
            },
            'X-XSS-Protection': {
                'required': False,
                'description': 'Enables XSS filtering in browsers',
                'severity': 'medium'
            },
            'Referrer-Policy': {
                'required': False,
                'description': 'Controls how much referrer information is included with requests',
                'severity': 'low'
            },
            'Permissions-Policy': {
                'required': False,
                'description': 'Controls which browser features and APIs can be used',
                'severity': 'medium'
            },
            'Cache-Control': {
                'required': False,
                'description': 'Controls caching mechanisms',
                'severity': 'low'
            }
        }

    async def analyze_headers(self, url):
        """Comprehensive security headers analysis"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    headers = dict(response.headers)
                    
                    analysis = {
                        'missing_headers': [],
                        'present_headers': {},
                        'security_score': 0,
                        'recommendations': [],
                        'vulnerabilities': []
                    }
                    
                    # Check each security header
                    for header, info in self.security_headers.items():
                        if header in headers:
                            header_analysis = self._analyze_single_header(header, headers[header])
                            analysis['present_headers'][header] = header_analysis
                            
                            if not header_analysis.get('secure', True):
                                analysis['vulnerabilities'].append({
                                    'title': f'Insecure {header} Configuration',
                                    'description': header_analysis.get('issue', ''),
                                    'severity': info['severity'],
                                    'evidence': {
                                        'header': header,
                                        'value': headers[header],
                                        'issue': header_analysis.get('issue', '')
                                    },
                                    'recommendation': header_analysis.get('recommendation', ''),
                                    'cvss_score': self._get_cvss_score(info['severity'])
                                })
                        else:
                            if info['required']:
                                analysis['missing_headers'].append(header)
                                analysis['vulnerabilities'].append({
                                    'title': f'Missing Security Header: {header}',
                                    'description': info['description'],
                                    'severity': info['severity'],
                                    'evidence': {'missing_header': header},
                                    'recommendation': f'Implement {header} with secure configuration',
                                    'cvss_score': self._get_cvss_score(info['severity'])
                                })
                    
                    # Calculate security score
                    analysis['security_score'] = self._calculate_security_score(analysis)
                    
                    # Generate recommendations
                    analysis['recommendations'] = self._generate_recommendations(analysis)
                    
                    return analysis
                    
        except Exception as e:
            logger.error(f"Header analysis failed: {str(e)}")
            return {'error': str(e)}

    def _analyze_single_header(self, header, value):
        """Analyze individual header configuration"""
        analysis = {'value': value, 'secure': True}
        
        if header == 'Content-Security-Policy':
            analysis.update(self._analyze_csp(value))
        elif header == 'Strict-Transport-Security':
            analysis.update(self._analyze_hsts(value))
        elif header == 'X-Frame-Options':
            analysis.update(self._analyze_xfo(value))
        elif header == 'X-Content-Type-Options':
            analysis.update(self._analyze_xcto(value))
        elif header == 'X-XSS-Protection':
            analysis.update(self._analyze_xxp(value))
        elif header == 'Referrer-Policy':
            analysis.update(self._analyze_referrer_policy(value))
        elif header == 'Permissions-Policy':
            analysis.update(self._analyze_permissions_policy(value))
        
        return analysis

    def _analyze_csp(self, value):
        """Analyze Content-Security-Policy header"""
        analysis = {'secure': True}
        
        # Check for unsafe directives
        unsafe_patterns = [
            "'unsafe-inline'",
            "'unsafe-eval'",
            "data:",
            "*"
        ]
        
        for pattern in unsafe_patterns:
            if pattern in value:
                analysis['secure'] = False
                analysis['issue'] = f'CSP contains unsafe directive: {pattern}'
                analysis['recommendation'] = 'Remove unsafe directives and use nonces/hashes instead'
                break
        
        return analysis

    def _analyze_hsts(self, value):
        """Analyze Strict-Transport-Security header"""
        analysis = {'secure': True}
        
        # Check for includeSubDomains and max-age
        if 'includeSubDomains' not in value:
            analysis['secure'] = False
            analysis['issue'] = 'HSTS missing includeSubDomains directive'
            analysis['recommendation'] = 'Add includeSubDomains to protect all subdomains'
        
        if 'max-age=' in value:
            max_age = int(value.split('max-age=')[1].split(';')[0])
            if max_age < 31536000:  # 1 year
                analysis['secure'] = False
                analysis['issue'] = f'HSTS max-age too short: {max_age}'
                analysis['recommendation'] = 'Set max-age to at least 31536000 (1 year)'
        
        return analysis

    def _analyze_xfo(self, value):
        """Analyze X-Frame-Options header"""
        analysis = {'secure': True}
        
        valid_values = ['DENY', 'SAMEORIGIN']
        if value not in valid_values:
            analysis['secure'] = False
            analysis['issue'] = f'Invalid X-Frame-Options value: {value}'
            analysis['recommendation'] = 'Set X-Frame-Options to DENY or SAMEORIGIN'
        
        return analysis

    def _analyze_xcto(self, value):
        """Analyze X-Content-Type-Options header"""
        analysis = {'secure': True}
        
        if value != 'nosniff':
            analysis['secure'] = False
            analysis['issue'] = f'Invalid X-Content-Type-Options value: {value}'
            analysis['recommendation'] = 'Set X-Content-Type-Options to nosniff'
        
        return analysis

    def _analyze_xxp(self, value):
        """Analyze X-XSS-Protection header"""
        analysis = {'secure': True}
        
        # Modern browsers have deprecated this, but it's still good to have
        if '1; mode=block' not in value:
            analysis['secure'] = False
            analysis['issue'] = 'X-XSS-Protection not properly configured'
            analysis['recommendation'] = 'Set X-XSS-Protection to 1; mode=block'
        
        return analysis

    def _analyze_referrer_policy(self, value):
        """Analyze Referrer-Policy header"""
        analysis = {'secure': True}
        
        secure_values = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']
        if value not in secure_values:
            analysis['secure'] = False
            analysis['issue'] = f'Potentially insecure Referrer-Policy: {value}'
            analysis['recommendation'] = 'Use a more restrictive referrer policy'
        
        return analysis

    def _analyze_permissions_policy(self, value):
        """Analyze Permissions-Policy header"""
        analysis = {'secure': True}
        
        # Check for dangerous features being allowed
        dangerous_features = ['camera', 'microphone', 'geolocation']
        for feature in dangerous_features:
            if f"{feature}=*" in value:
                analysis['secure'] = False
                analysis['issue'] = f'Dangerous feature {feature} allowed globally'
                analysis['recommendation'] = f'Restrict {feature} to specific origins'
                break
        
        return analysis

    def _calculate_security_score(self, analysis):
        """Calculate security headers score (0-100)"""
        max_score = len(self.security_headers) * 10
        actual_score = 0
        
        # Score present headers
        for header, info in analysis['present_headers'].items():
            if info.get('secure', False):
                actual_score += 10
            else:
                actual_score += 5  # Partial credit for having but misconfigured
        
        # Penalize missing required headers
        for header in analysis['missing_headers']:
            if self.security_headers[header]['required']:
                actual_score -= 5
        
        return max(0, min(100, (actual_score / max_score) * 100))

    def _generate_recommendations(self, analysis):
        """Generate security recommendations"""
        recommendations = []
        
        # Recommendations for missing headers
        for header in analysis['missing_headers']:
            info = self.security_headers[header]
            recommendations.append({
                'priority': 'high' if info['required'] else 'medium',
                'header': header,
                'action': f'Implement {header}',
                'reason': info['description']
            })
        
        # Recommendations for misconfigured headers
        for header, info in analysis['present_headers'].items():
            if not info.get('secure', True):
                recommendations.append({
                    'priority': 'medium',
                    'header': header,
                    'action': f'Fix {header} configuration',
                    'reason': info.get('issue', 'Insecure configuration')
                })
        
        return recommendations

    def _get_cvss_score(self, severity):
        """Convert severity to CVSS score"""
        scores = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0
        }
        return scores.get(severity, 5.0)

# Create analyzer instance
analyzer = HeaderAnalyzer()

# Async analysis function
async def analyze_headers(url):
    return await analyzer.analyze_headers(url)

def analyze_headers_dict(headers):
    """Analyze headers from a dictionary (for use in other scanners)"""
    analyzer = HeaderAnalyzer()
    
    # Create a mock analysis
    analysis = {
        'missing_headers': [],
        'present_headers': {},
        'security_score': 0,
        'recommendations': [],
        'vulnerabilities': []
    }
    
    # Check each security header
    for header, info in analyzer.security_headers.items():
        if header in headers:
            header_analysis = analyzer._analyze_single_header(header, headers[header])
            analysis['present_headers'][header] = header_analysis
        else:
            if info['required']:
                analysis['missing_headers'].append(header)
    
    analysis['security_score'] = analyzer._calculate_security_score(analysis)
    analysis['recommendations'] = analyzer._generate_recommendations(analysis)
    
    return analysis