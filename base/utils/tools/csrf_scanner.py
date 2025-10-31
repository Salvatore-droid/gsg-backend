import aiohttp
import asyncio
import re
from urllib.parse import urlparse
import logging
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class CSRFScanner:
    def __init__(self):
        self.csrf_token_names = [
            'csrf', 'csrfmiddlewaretoken', '_token', 'authenticity_token',
            'csrf_token', 'csrf-token', 'anticsrf', '__requestverificationtoken',
            'token', 'security_token'
        ]

    async def audit(self, url):
        """Comprehensive CSRF vulnerability audit"""
        vulnerabilities = []
        
        try:
            # Analyze forms for CSRF protection
            form_vulns = await self._analyze_forms(url)
            vulnerabilities.extend(form_vulns)
            
            # Check for state-changing operations
            state_vulns = await self._check_state_changing_operations(url)
            vulnerabilities.extend(state_vulns)
            
        except Exception as e:
            logger.error(f"CSRF audit failed: {str(e)}")
        
        return vulnerabilities

    async def _analyze_forms(self, url):
        """Analyze forms for CSRF protection"""
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    content = await response.text()
                    
                    forms = self._extract_forms(content)
                    
                    for form in forms:
                        form_action = form.get('action', '')
                        form_method = form.get('method', 'get').lower()
                        form_inputs = form.get('inputs', {})
                        
                        # Skip forms that don't change state or are GET requests
                        if form_method == 'get':
                            continue
                        
                        # Check if form has CSRF protection
                        has_csrf_protection = self._has_csrf_protection(form_inputs)
                        
                        if not has_csrf_protection:
                            vulnerabilities.append({
                                'title': 'Missing CSRF Protection',
                                'description': f'Form at {form_action} lacks CSRF protection',
                                'severity': 'medium',
                                'evidence': {
                                    'form_action': form_action,
                                    'method': form_method,
                                    'inputs': list(form_inputs.keys())
                                },
                                'recommendation': 'Implement CSRF tokens for all state-changing forms',
                                'cvss_score': 6.5
                            })
        
        except Exception as e:
            logger.error(f"Form analysis failed: {str(e)}")
        
        return vulnerabilities

    async def _check_state_changing_operations(self, url):
        """Check for state-changing operations without CSRF protection"""
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    content = await response.text()
                    
                    # Look for AJAX calls that might change state
                    ajax_patterns = [
                        r"\$\.post\(",
                        r"\$\.ajax\(.*type:\s*['\"]post['\"]",
                        r"fetch\(.*method:\s*['\"]post['\"]",
                        r"XMLHttpRequest.*open\(['\"]post['\"]",
                        r"axios\.post\(",
                        r"axios\(.*method:\s*['\"]post['\"]"
                    ]
                    
                    for pattern in ajax_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            # Check if the AJAX call includes CSRF protection
                            if not self._check_ajax_csrf_protection(content, match):
                                vulnerabilities.append({
                                    'title': 'Potential CSRF in AJAX Call',
                                    'description': f'AJAX call without CSRF protection detected',
                                    'severity': 'medium',
                                    'evidence': {
                                        'ajax_call': match.strip(),
                                        'pattern': pattern
                                    },
                                    'recommendation': 'Include CSRF tokens in all AJAX requests that change state',
                                    'cvss_score': 6.1
                                })
        
        except Exception as e:
            logger.error(f"State-changing operations check failed: {str(e)}")
        
        return vulnerabilities

    def _has_csrf_protection(self, form_inputs):
        """Check if form has CSRF protection"""
        for input_name in form_inputs:
            if any(token_name in input_name.lower() for token_name in self.csrf_token_names):
                return True
        return False

    def _check_ajax_csrf_protection(self, content, ajax_call):
        """Check if AJAX call includes CSRF protection"""
        csrf_indicators = [
            'csrf',
            'token',
            'X-CSRF-Token',
            'X-XSRF-TOKEN'
        ]
        
        for indicator in csrf_indicators:
            if indicator.lower() in ajax_call.lower():
                return True
        
        # Check for CSRF token in headers
        header_patterns = [
            r"headers:\s*{[^}]*csrf[^}]*}",
            r"headers:\s*{[^}]*token[^}]*}",
            r"beforeSend:.*csrf",
            r"beforeSend:.*token"
        ]
        
        for pattern in header_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                return True
        
        return False

    def _extract_forms(self, html_content):
        """Extract forms from HTML content"""
        forms = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': {}
                }
                
                # Extract input fields
                for input_tag in form.find_all('input'):
                    input_name = input_tag.get('name')
                    if input_name:
                        form_data['inputs'][input_name] = input_tag.get('value', '')
                
                forms.append(form_data)
                
        except Exception as e:
            logger.error(f"Form extraction failed: {str(e)}")
        
        return forms

# Create scanner instance
scanner = CSRFScanner()

# Async audit function
async def audit(url):
    return await scanner.audit(url)