import requests
import dns.resolver
import ssl
import socket
import json
from bs4 import BeautifulSoup
from cachetools import TTLCache
from dotenv import load_dotenv
import os
import re
import time
import logging
import random
from urllib.parse import quote

# Add python-whois import (install via pip install python-whois)
try:
    import whois as python_whois
except ImportError:
    python_whois = None

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv('VITE_VIRUSTOTAL_API_KEY')
WHOISXMLAPI_KEY = os.getenv('VITE_WHOISXMLAPI_KEY')

# Cache results to avoid hitting API limits (TTL: 1 hour)
whois_cache = TTLCache(maxsize=100, ttl=3600)
subdomain_cache = TTLCache(maxsize=100, ttl=3600)

def get_ip(domain: str) -> str:
    """Resolve domain to IP."""
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        logger.error(f"IP resolution failed for {domain}: {str(e)}")
        return None

def get_whois_data(domain: str) -> dict:
    """Fetch WHOIS data with enhanced fallback and retries."""
    if domain in whois_cache:
        return whois_cache[domain]

    result = {
        'registrar': 'N/A',
        'registrant': 'N/A',
        'created': 'N/A',
        'updated': 'N/A',
        'expires': 'N/A',
        'name_servers': 'N/A',
        'status': 'N/A',
        'source': 'N/A'
    }
    
    api_success = False
    
    try:
        # Try WHOISXML API with retries
        if WHOISXMLAPI_KEY:
            for attempt in range(3):
                try:
                    url = f'https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOISXMLAPI_KEY}&domainName={domain}&outputFormat=JSON'
                    response = requests.get(url, timeout=15)
                    response.raise_for_status()
                    data = response.json()
                    whois_data = data.get('WhoisRecord', {})
                    
                    result.update({
                        'registrar': whois_data.get('registrarName', 'N/A'),
                        'registrant': whois_data.get('registrant', {}).get('name', 'Privacy Protected') if whois_data.get('registrant') else 'Privacy Protected',
                        'created': whois_data.get('createdDate', 'N/A'),
                        'updated': whois_data.get('updatedDate', 'N/A'),
                        'expires': whois_data.get('expiresDate', 'N/A'),
                        'name_servers': ', '.join(whois_data.get('nameServers', {}).get('hostNames', ['N/A'])),
                        'status': ', '.join(whois_data.get('status', ['N/A'])),
                        'source': 'WHOISXML API'
                    })
                    api_success = True
                    break
                except requests.exceptions.RequestException as e:
                    logger.warning(f"WHOISXML API attempt {attempt+1} failed for {domain}: {str(e)}. Retrying...")
                    time.sleep(5)

        if not api_success:
            # Fallback 1: who.is with improved parsing
            try:
                response = requests.get(f'https://who.is/whois/{domain}', timeout=15)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
                whois_info = soup.find('div', class_='col-md-8 queryResponseBodyStyle')
                if whois_info:
                    text = whois_info.get_text().lower()
                    registrar_match = re.search(r'registrar:\s*([^\n]+)', text)
                    created_match = re.search(r'creation date:\s*([^\n]+)', text)
                    updated_match = re.search(r'updated date:\s*([^\n]+)', text)
                    expires_match = re.search(r'expiry date:\s*([^\n]+)', text)
                    ns_match = re.search(r'name server:\s*([^\n]+)', text, re.MULTILINE)
                    status_match = re.search(r'status:\s*([^\n]+)', text)
                    
                    result.update({
                        'registrar': registrar_match.group(1).strip() if registrar_match else 'N/A',
                        'registrant': 'Privacy Protected',
                        'created': created_match.group(1).strip() if created_match else 'N/A',
                        'updated': updated_match.group(1).strip() if updated_match else 'N/A',
                        'expires': expires_match.group(1).strip() if expires_match else 'N/A',
                        'name_servers': ns_match.group(1).strip() if ns_match else 'N/A',
                        'status': status_match.group(1).strip() if status_match else 'N/A',
                        'source': 'who.is'
                    })
                    api_success = True
            except Exception as e:
                logger.error(f"who.is fallback error for {domain}: {str(e)}")

            if not api_success and python_whois:
                # Fallback 2: python-whois library
                try:
                    w = python_whois.whois(domain)
                    result.update({
                        'registrar': w.get('registrar', 'N/A'),
                        'registrant': w.get('name', 'Privacy Protected'),
                        'created': str(w.get('creation_date', 'N/A')),
                        'expires': str(w.get('expiration_date', 'N/A')),
                        'name_servers': ', '.join(w.get('name_servers', ['N/A'])),
                        'status': str(w.get('status', 'N/A')),
                        'source': 'python-whois'
                    })
                    api_success = True
                except Exception as e:
                    logger.error(f"python-whois fallback error for {domain}: {str(e)}")

        whois_cache[domain] = result
        return result
    except Exception as e:
        logger.error(f"Unexpected error in WHOIS for {domain}: {str(e)}")
        whois_cache[domain] = result
        return result

def get_dns_data(domain: str) -> list:
    """Fetch DNS records."""
    try:
        records = []
        for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, qtype, raise_on_no_answer=False, lifetime=15)
                for rdata in answers:
                    records.append({
                        'type': qtype,
                        'value': rdata.to_text()
                    })
            except Exception:
                records.append({
                    'type': qtype,
                    'value': 'No records found'
                })
        return records
    except Exception as e:
        logger.error(f"DNS lookup failed for {domain}: {str(e)}")
        return [{'type': 'ERROR', 'value': f"DNS lookup failed: {str(e)}"}]

def get_ssl_data(domain: str) -> dict:
    """Fetch SSL certificate details."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    'issuer': dict(x[0] for x in cert.get('issuer', [])).get('organizationName', 'N/A'),
                    'subject': dict(x[0] for x in cert.get('subject', [])).get('commonName', 'N/A'),
                    'expiry': cert.get('notAfter', 'N/A'),
                    'valid': True,
                    'serial_number': cert.get('serialNumber', 'N/A'),
                    'version': cert.get('version', 'N/A')
                }
    except Exception as e:
        logger.error(f"SSL data unavailable for {domain}: {str(e)}")
        return {
            'issuer': 'N/A',
            'subject': 'N/A',
            'expiry': 'N/A',
            'valid': False,
            'error': str(e)
        }

def get_virustotal_data(domain: str) -> dict:
    """Fetch VirusTotal threat intelligence."""
    if not VIRUSTOTAL_API_KEY:
        return {
            'reputation': 'N/A',
            'last_analysis': 'N/A',
            'categories': [],
            'malicious': 0,
            'suspicious': 0,
            'error': 'VirusTotal API key not set'
        }
    
    try:
        url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()['data']['attributes']
        
        return {
            'reputation': data.get('reputation', 0),
            'last_analysis': data.get('last_analysis_date', 'N/A'),
            'categories': list(data.get('categories', {}).values()),
            'malicious': data.get('last_analysis_stats', {}).get('malicious', 0),
            'suspicious': data.get('last_analysis_stats', {}).get('suspicious', 0)
        }
    except Exception as e:
        logger.error(f"Threat intelligence unavailable for {domain}: {str(e)}")
        return {
            'reputation': 'N/A',
            'last_analysis': 'N/A',
            'categories': [],
            'malicious': 0,
            'suspicious': 0,
            'error': str(e)
        }

def get_traceroute(domain: str) -> dict:
    """Perform traceroute using an external API."""
    ip = get_ip(domain)
    if not ip:
        return {'error': 'Unable to resolve IP', 'hops': []}
    
    try:
        # Use HackerTarget's traceroute API
        response = requests.get(f'https://api.hackertarget.com/traceroute/?q={ip}', timeout=30)
        response.raise_for_status()
        hops = response.text.splitlines()
        cleaned_hops = [hop.strip() for hop in hops if hop.strip() and not hop.startswith('Tracing')]
        
        return {
            'ip': ip,
            'hops': cleaned_hops[:10]  # Limit to first 10 hops
        }
    except Exception as e:
        logger.error(f"Traceroute unavailable for {domain}: {str(e)}")
        return {'error': f'Traceroute failed: {str(e)}', 'hops': []}

def get_domain_status(domain: str) -> dict:
    """Check if domain is active via HTTP/HTTPS."""
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{domain}"
            response = requests.get(url, timeout=15, allow_redirects=True)
            return {
                'active': True,
                'protocol': protocol,
                'status_code': response.status_code,
                'final_url': response.url,
                'title': extract_title(response.text)
            }
        except Exception as e:
            continue
    
    return {
        'active': False,
        'error': 'Domain inactive or unreachable'
    }

def extract_title(html_content: str) -> str:
    """Extract title from HTML content."""
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        title = soup.find('title')
        return title.get_text().strip() if title else 'No title found'
    except:
        return 'Unable to extract title'

def get_subdomains(domain: str) -> list:
    """Fetch subdomains using crt.sh."""
    if domain in subdomain_cache:
        return subdomain_cache[domain]
    
    try:
        response = requests.get(f'https://crt.sh/?q=%.{quote(domain)}&output=json', timeout=15)
        response.raise_for_status()
        subdomains = list(set(entry['name_value'].strip() for entry in response.json()))
        result = subdomains[:50]  # Limit to 50 subdomains
        subdomain_cache[domain] = result
        return result
    except Exception as e:
        logger.error(f"Subdomains unavailable for {domain}: {str(e)}")
        return []

def get_open_ports(domain: str) -> list:
    """Scan common ports."""
    ip = get_ip(domain)
    if not ip:
        return []
    
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
    open_ports = []
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append({
                    'port': port,
                    'service': get_service_name(port)
                })
            sock.close()
        except Exception:
            continue
    
    return open_ports

def get_service_name(port: int) -> str:
    """Get service name for port."""
    services = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        993: 'IMAPS', 995: 'POP3S', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
    }
    return services.get(port, 'Unknown')

def get_reverse_ip_lookup(domain: str) -> list:
    """Find other domains on the same IP with fallback."""
    ip = get_ip(domain)
    if not ip:
        return []
    
    try:
        # Primary: WhoisXMLAPI Reverse IP API (since key is available)
        if WHOISXMLAPI_KEY:
            url = f'https://reverse-ip.whoisxmlapi.com/api/v2?apiKey={WHOISXMLAPI_KEY}&ip={ip}'
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            data = response.json()
            domains = [result.get('name', '') for result in data.get('result', [])]
            if domains:
                return domains[:20]
        
        # Fallback: HackerTarget API
        response = requests.get(f'https://api.hackertarget.com/reverseiplookup/?q={ip}', timeout=15)
        response.raise_for_status()
        domains = response.text.splitlines()
        if domains and domains[0].lower() != 'error' and 'api count exceeded' not in domains[0].lower():
            return domains[:20]
        
        # Second Fallback: ViewDNS.info
        response = requests.get(f'https://api.viewdns.info/reverseip/?host={ip}&t=1', timeout=15)
        response.raise_for_status()
        data = response.json()
        domains = [domain['name'] for domain in data.get('response', {}).get('domains', [])]
        return domains[:20] if domains else []
    except Exception as e:
        logger.error(f"Reverse IP Lookup unavailable for {domain}: {str(e)}")
        return []

def get_geolocation(domain: str) -> dict:
    """Fetch geolocation data for the domain's IP."""
    ip = get_ip(domain)
    if not ip:
        return {'error': 'Unable to resolve IP'}
    
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=15)
        response.raise_for_status()
        data = response.json()
        
        return {
            'ip': ip,
            'country': data.get('country', 'N/A'),
            'country_code': data.get('countryCode', 'N/A'),
            'city': data.get('city', 'N/A'),
            'region': data.get('regionName', 'N/A'),
            'isp': data.get('isp', 'N/A'),
            'org': data.get('org', 'N/A'),
            'latitude': data.get('lat', 0),
            'longitude': data.get('lon', 0),
            'timezone': data.get('timezone', 'N/A')
        }
    except Exception as e:
        logger.error(f"Geolocation unavailable for {domain}: {str(e)}")
        return {'error': str(e)}

def get_associated_emails(domain: str) -> list:
    """Extract emails from WHOIS or website."""
    emails = set()
    
    try:
        # Check WHOIS data
        response = requests.get(f'https://who.is/whois/{domain}', timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text()
        found_emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
        emails.update(found_emails)
        
        # Check website content
        try:
            web_response = requests.get(f'https://{domain}', timeout=10)
            web_emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', web_response.text)
            emails.update(web_emails)
        except:
            pass
        
        return list(emails)[:10]  # Limit to 10 emails
    except Exception as e:
        logger.error(f"Associated Emails unavailable for {domain}: {str(e)}")
        return []

def get_technologies(domain: str) -> list:
    """Detect web technologies via headers and content."""
    try:
        response = requests.get(f'https://{domain}', timeout=15)
        response.raise_for_status()
        
        technologies = []
        headers = response.headers
        
        # Check headers
        if 'server' in headers:
            technologies.append(f"Server: {headers['server']}")
        if 'x-powered-by' in headers:
            technologies.append(f"Powered By: {headers['x-powered-by']}")
        if 'x-generator' in headers:
            technologies.append(f"Generator: {headers['x-generator']}")
        
        # Check content for common frameworks
        content = response.text.lower()
        if 'wordpress' in content:
            technologies.append('WordPress')
        if 'drupal' in content:
            technologies.append('Drupal')
        if 'joomla' in content:
            technologies.append('Joomla')
        if 'react' in content:
            technologies.append('React')
        if 'angular' in content:
            technologies.append('Angular')
        if 'vue' in content:
            technologies.append('Vue.js')
        
        return technologies
    except Exception as e:
        logger.error(f"Technologies unavailable for {domain}: {str(e)}")
        return []

def get_security_headers(domain: str) -> dict:
    """Check security headers."""
    try:
        response = requests.get(f'https://{domain}', timeout=15)
        response.raise_for_status()
        headers = response.headers
        
        security_headers = {
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not set'),
            'X-Frame-Options': headers.get('X-Frame-Options', 'Not set'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not set'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not set'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Not set'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Not set'),
            'Permissions-Policy': headers.get('Permissions-Policy', 'Not set')
        }
        
        return security_headers
    except Exception as e:
        logger.error(f"Security Headers unavailable for {domain}: {str(e)}")
        return {'error': str(e)}

def get_wayback_snapshots(domain: str) -> list:
    """Fetch Wayback Machine snapshots with retry logic."""
    try:
        for attempt in range(3):
            try:
                response = requests.get(
                    f'https://web.archive.org/cdx/search/cdx?url=*.{quote(domain)}&output=json&limit=10&fl=timestamp,original,statuscode&filter=statuscode:200',
                    timeout=30
                )
                response.raise_for_status()
                data = response.json()
                
                snapshots = []
                if len(data) > 1:  # Skip header
                    for entry in data[1:]:
                        if len(entry) >= 3:
                            snapshots.append({
                                'timestamp': entry[0],
                                'url': f"https://web.archive.org/web/{entry[0]}/{entry[1]}",
                                'status': entry[2]
                            })
                
                if snapshots:
                    return snapshots
                else:
                    logger.warning(f"No snapshots found for {domain} on attempt {attempt+1}")
                    time.sleep(5)
                    continue
            except Exception as e:
                logger.warning(f"Wayback Machine attempt {attempt+1} failed for {domain}: {str(e)}")
                time.sleep(5)
        
        return []
    except Exception as e:
        logger.error(f"Wayback Machine snapshots unavailable for {domain}: {str(e)}")
        return []

def get_owasp_checks(domain: str) -> list:
    """Perform passive checks for OWASP Top 10 2025 vulnerabilities."""
    checks = []
    
    # Get necessary data
    ssl_data = get_ssl_data(domain)
    security_headers = get_security_headers(domain)
    technologies = get_technologies(domain)
    domain_status = get_domain_status(domain)
    
    # OWASP Top 10 2025 checks based on provided table
    owasp_top10 = [
        {
            "name": "A01: Broken Access Control",
            "status": "Unknown",
            "details": "Cannot check passively"
        },
        {
            "name": "A02: Injection",
            "status": "Low Risk" if not any('php' in tech.lower() or 'sql' in tech.lower() for tech in technologies) else "Potential Risk",
            "details": "Look for vulnerable technologies"
        },
        {
            "name": "A03: Insecure Design",
            "status": "Unknown",
            "details": "Cannot check passively"
        },
        {
            "name": "A04: Identification and Authentication Failures",
            "status": "Low Risk" if domain_status.get('protocol') == 'https' else "High Risk",
            "details": "Check if HTTPS used"
        },
        {
            "name": "A05: Security Misconfiguration",
            "status": "High Risk" if any(val == 'Not set' for val in security_headers.values() if val != 'error') else "Low Risk",
            "details": "Missing security headers"
        },
        {
            "name": "A06: Vulnerable and Outdated Components",
            "status": "Low Risk" if not any('apache/2.2' in tech.lower() or 'nginx/1.14' in tech.lower() for tech in technologies) else "Potential Risk",
            "details": "Check server headers for old versions"
        },
        {
            "name": "A07: Cryptographic Failures",
            "status": "Low Risk" if ssl_data.get('valid', False) else "High Risk",
            "details": "Invalid or expired SSL"
        },
        {
            "name": "A08: Software and Data Integrity Failures",
            "status": "Unknown",
            "details": "Cannot check passively"
        },
        {
            "name": "A09: Server-Side Request Forgery",
            "status": "Unknown",
            "details": "Cannot check passively"
        },
        {
            "name": "A10: Security Logging and Monitoring Failures",
            "status": "Unknown",
            "details": "Cannot check passively"
        }
    ]
    
    for item in owasp_top10:
        checks.append({
            'name': item['name'],
            'status': item['status'],
            'details': item['details']
        })
    
    return checks

def get_recon_data(domain: str) -> dict:
    """Combine all reconnaissance data."""
    logger.info(f"Starting reconnaissance for {domain}")
    
    data = {
        'domain': domain,
        'whois': get_whois_data(domain),
        'dns': get_dns_data(domain),
        'ssl': get_ssl_data(domain),
        'virustotal': get_virustotal_data(domain),
        'traceroute': get_traceroute(domain),
        'domain_status': get_domain_status(domain),
        'subdomains': get_subdomains(domain),
        'open_ports': get_open_ports(domain),
        'reverse_ip': get_reverse_ip_lookup(domain),
        'geolocation': get_geolocation(domain),
        'emails': get_associated_emails(domain),
        'technologies': get_technologies(domain),
        'security_headers': get_security_headers(domain),
        'wayback_snapshots': get_wayback_snapshots(domain),
        'owasp_checks': get_owasp_checks(domain)
    }
    
    # Add a random pro-tip
    tips = [
        "🔒 Pro Tip: Always check SSL expiry to avoid security risks!",
        "🌐 Fun Fact: Over 1 billion domains exist worldwide!",
        "⚠️ Reminder: Use VPNs when scanning sensitive domains.",
        "🛡️ Security Tip: Check security headers for better protection!",
        "📊 Analysis Tip: Monitor subdomains for complete coverage!"
    ]
    data['pro_tip'] = random.choice(tips)
    
    logger.info(f"Reconnaissance completed for {domain}")
    return data