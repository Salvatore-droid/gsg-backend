import aiohttp
import asyncio
import re
import logging
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class CMSDetector:
    def __init__(self):
        self.cms_signatures = {
            'WordPress': {
                'patterns': [
                    r'wp-content|wp-includes',
                    r'wordpress',
                    r'/wp-json/'
                ],
                'meta_generator': r'WordPress',
                'files': ['/wp-admin/', '/wp-login.php', '/readme.html']
            },
            'Joomla': {
                'patterns': [
                    r'joomla',
                    r'/media/jui/',
                    r'/media/system/'
                ],
                'meta_generator': r'Joomla',
                'files': ['/administrator/', '/components/com_content/']
            },
            'Drupal': {
                'patterns': [
                    r'drupal',
                    r'sites/all/',
                    r'/core/assets/'
                ],
                'meta_generator': r'Drupal',
                'files': ['/user/login', '/core/']
            },
            'Magento': {
                'patterns': [
                    r'magento',
                    r'/static/version',
                    r'/js/mage/'
                ],
                'meta_generator': r'Magento',
                'files': ['/admin/', '/customer/account/login/']
            },
            'Shopify': {
                'patterns': [
                    r'shopify',
                    r'cdn.shopify.com',
                    r'shopify-checkout'
                ],
                'meta_generator': r'Shopify',
                'files': ['/cart', '/account/login']
            }
        }
        
        self.technology_signatures = {
            'JavaScript Frameworks': {
                'React': ['react', 'react-dom'],
                'Angular': ['ng-', 'angular'],
                'Vue.js': ['vue', 'v-'],
                'jQuery': ['jquery']
            },
            'Web Servers': {
                'Apache': ['apache', 'server: apache'],
                'Nginx': ['nginx'],
                'IIS': ['microsoft-iis', 'server: microsoft-iis']
            },
            'Programming Languages': {
                'PHP': ['php', 'x-powered-by: php'],
                'Python': ['python', 'django', 'flask'],
                'Node.js': ['node', 'express'],
                'Ruby': ['ruby', 'rails']
            },
            'Database': {
                'MySQL': ['mysql'],
                'PostgreSQL': ['postgresql'],
                'MongoDB': ['mongodb']
            }
        }

    async def detect_technologies(self, url):
        """Comprehensive technology stack detection"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    content = await response.text()
                    headers = dict(response.headers)
                    
                    technologies = {
                        'cms': await self._detect_cms(content, headers, url),
                        'javascript_frameworks': self._detect_js_frameworks(content),
                        'web_server': self._detect_web_server(headers),
                        'programming_language': self._detect_programming_language(headers, content),
                        'database': self._detect_database(content),
                        'cdn': self._detect_cdn(headers),
                        'analytics': self._detect_analytics(content),
                        'libraries': self._detect_libraries(content)
                    }
                    
                    return technologies
                    
        except Exception as e:
            logger.error(f"Technology detection failed: {str(e)}")
            return {'error': str(e)}

    async def _detect_cms(self, content, headers, url):
        """Detect Content Management System"""
        detected_cms = []
        
        for cms_name, signatures in self.cms_signatures.items():
            # Check patterns in content
            for pattern in signatures['patterns']:
                if re.search(pattern, content, re.IGNORECASE):
                    detected_cms.append(cms_name)
                    break
            
            # Check meta generator tag
            if 'meta_generator' in signatures:
                generator_pattern = signatures['meta_generator']
                if re.search(generator_pattern, content, re.IGNORECASE):
                    if cms_name not in detected_cms:
                        detected_cms.append(cms_name)
            
            # Check for specific files (async)
            if await self._check_cms_files(url, signatures.get('files', [])):
                if cms_name not in detected_cms:
                    detected_cms.append(cms_name)
        
        return detected_cms if detected_cms else ['Unknown']

    async def _check_cms_files(self, base_url, files):
        """Check for CMS-specific files"""
        if not files:
            return False
            
        async with aiohttp.ClientSession() as session:
            for file_path in files:
                try:
                    test_url = f"{base_url.rstrip('/')}{file_path}"
                    async with session.get(test_url, timeout=5) as response:
                        if response.status in [200, 301, 302]:
                            return True
                except:
                    continue
        
        return False

    def _detect_js_frameworks(self, content):
        """Detect JavaScript frameworks"""
        detected_frameworks = []
        
        for category, frameworks in self.technology_signatures['JavaScript Frameworks'].items():
            for framework, patterns in frameworks.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        detected_frameworks.append(framework)
                        break
        
        return detected_frameworks

    def _detect_web_server(self, headers):
        """Detect web server technology"""
        server_header = headers.get('Server', '').lower()
        powered_by = headers.get('X-Powered-By', '').lower()
        
        servers = []
        
        for server, patterns in self.technology_signatures['Web Servers'].items():
            for pattern in patterns:
                if pattern in server_header or pattern in powered_by:
                    servers.append(server)
                    break
        
        return servers if servers else ['Unknown']

    def _detect_programming_language(self, headers, content):
        """Detect programming language"""
        powered_by = headers.get('X-Powered-By', '').lower()
        server_header = headers.get('Server', '').lower()
        
        languages = []
        
        # Check headers first
        for lang, patterns in self.technology_signatures['Programming Languages'].items():
            for pattern in patterns:
                if pattern in powered_by or pattern in server_header:
                    languages.append(lang)
                    break
        
        # Check content for framework signatures
        if not languages:
            for lang, patterns in self.technology_signatures['Programming Languages'].items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        if lang not in languages:
                            languages.append(lang)
                        break
        
        return languages if languages else ['Unknown']

    def _detect_database(self, content):
        """Detect database technology"""
        databases = []
        
        for db, patterns in self.technology_signatures['Database'].items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    databases.append(db)
                    break
        
        return databases if databases else ['Unknown']

    def _detect_cdn(self, headers):
        """Detect Content Delivery Network"""
        cdn_indicators = {
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'CloudFront': ['cloudfront', 'x-amz-cf-id'],
            'Akamai': ['akamai'],
            'Fastly': ['fastly'],
            'MaxCDN': ['maxcdn']
        }
        
        detected_cdn = []
        
        for cdn, indicators in cdn_indicators.items():
            for indicator in indicators:
                if any(indicator in key.lower() or indicator in value.lower() 
                      for key, value in headers.items()):
                    detected_cdn.append(cdn)
                    break
        
        return detected_cdn

    def _detect_analytics(self, content):
        """Detect analytics tools"""
        analytics_tools = {
            'Google Analytics': ['google-analytics', 'ga.js', 'analytics.js', 'gtag.js'],
            'Google Tag Manager': ['googletagmanager', 'gtm.js'],
            'Facebook Pixel': ['facebook-pixel', 'fbq('],
            'Hotjar': ['hotjar'],
            'Mixpanel': ['mixpanel'],
            'Adobe Analytics': ['adobe-analytics', 'omniture']
        }
        
        detected_analytics = []
        
        for tool, patterns in analytics_tools.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    detected_analytics.append(tool)
                    break
        
        return detected_analytics

    def _detect_libraries(self, content):
        """Detect common libraries"""
        libraries = {
            'Bootstrap': ['bootstrap', 'bootstrap.min.js', 'bootstrap.min.css'],
            'jQuery UI': ['jquery-ui', 'jquery.ui'],
            'Font Awesome': ['font-awesome', 'fa-'],
            'Modernizr': ['modernizr'],
            'Moment.js': ['moment.js', 'moment.min.js'],
            'Lodash': ['lodash', 'lodash.min.js'],
            'Underscore.js': ['underscore', 'underscore.min.js']
        }
        
        detected_libraries = []
        
        for lib, patterns in libraries.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    detected_libraries.append(lib)
                    break
        
        return detected_libraries

    async def get_technology_versions(self, url, technologies):
        """Get version information for detected technologies"""
        versions = {}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    content = await response.text()
                    
                    # WordPress version detection
                    if 'WordPress' in technologies.get('cms', []):
                        wp_version = self._detect_wordpress_version(content)
                        if wp_version:
                            versions['WordPress'] = wp_version
                    
                    # Look for version patterns in general
                    version_patterns = {
                        'jQuery': r'jquery[.-](\d+\.\d+\.\d+)',
                        'Bootstrap': r'bootstrap[.-](\d+\.\d+\.\d+)',
                        'React': r'react[.-](\d+\.\d+\.\d+)'
                    }
                    
                    for tech, pattern in version_patterns.items():
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            versions[tech] = match.group(1)
        
        except Exception as e:
            logger.error(f"Version detection failed: {str(e)}")
        
        return versions

    def _detect_wordpress_version(self, content):
        """Detect WordPress version"""
        # Check meta generator tag
        generator_match = re.search(r'<meta name="generator" content="WordPress (\d+\.\d+(?:\.\d+)?)"', content)
        if generator_match:
            return generator_match.group(1)
        
        # Check readme.html
        readme_match = re.search(r'Version (\d+\.\d+(?:\.\d+)?)', content)
        if readme_match:
            return readme_match.group(1)
        
        # Check wp-includes version
        includes_match = re.search(r'wp-includes/js/wp-embed\.js\?ver=(\d+\.\d+(?:\.\d+)?)', content)
        if includes_match:
            return includes_match.group(1)
        
        return None

# Create detector instance
detector = CMSDetector()

# Async detection function
async def detect_technologies(url):
    return await detector.detect_technologies(url)

async def get_technology_versions(url, technologies):
    return await detector.get_technology_versions(url, technologies)