import os
import logging
import requests
import base64
import time
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')

def check_authenticity(url: str) -> dict:
    """Check website authenticity using VirusTotal and Google Safe Browsing with fallback."""
    vt_result = check_virustotal(url)
    gs_result = check_google_safe_browsing(url)
    
    is_genuine = vt_result['malicious'] == 0 and vt_result['suspicious'] == 0
    if gs_result and not gs_result['malicious']:
        is_genuine = True
    
    return {
        'is_genuine': is_genuine,
        'vt_result': vt_result,
        'gs_result': gs_result,
        'confidence_score': calculate_confidence_score(vt_result, gs_result)
    }

def calculate_confidence_score(vt_result: dict, gs_result: dict) -> int:
    """Calculate confidence score based on threat analysis."""
    score = 100
    
    # Deduct points for VirusTotal detections
    score -= vt_result['malicious'] * 20
    score -= vt_result['suspicious'] * 10
    
    # Deduct points for Google Safe Browsing threats
    if gs_result and gs_result['malicious']:
        score -= 30
    
    return max(0, score)

def check_virustotal(url: str) -> dict:
    """Scan URL with VirusTotal and get stats."""
    if not VIRUSTOTAL_API_KEY:
        return {
            'malicious': 0,
            'suspicious': 0,
            'clean': 0,
            'undetected': 0,
            'error': 'VirusTotal API key not set'
        }
    
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
    
    try:
        # First, try to get existing analysis
        response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()['data']['attributes']['last_analysis_stats']
            return {
                'malicious': data.get('malicious', 0),
                'suspicious': data.get('suspicious', 0),
                'clean': data.get('harmless', 0),
                'undetected': data.get('undetected', 0),
                'timeout': data.get('timeout', 0)
            }
        elif response.status_code == 404:
            # URL not found, submit for analysis
            scan_response = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers=headers,
                data={'url': url},
                timeout=15
            )
            scan_response.raise_for_status()
            analysis_id = scan_response.json()['data']['id']
            
            # Wait for analysis to complete (max 60 seconds)
            for _ in range(6):
                time.sleep(10)
                analysis_response = requests.get(
                    f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                    headers=headers,
                    timeout=15
                )
                
                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json()['data']['attributes']
                    if analysis_data['status'] == 'completed':
                        stats = analysis_data['stats']
                        return {
                            'malicious': stats.get('malicious', 0),
                            'suspicious': stats.get('suspicious', 0),
                            'clean': stats.get('harmless', 0),
                            'undetected': stats.get('undetected', 0),
                            'timeout': stats.get('timeout', 0)
                        }
            
            # Analysis timed out
            return {
                'malicious': 0,
                'suspicious': 0,
                'clean': 0,
                'undetected': 0,
                'error': 'Analysis timed out'
            }
        
        response.raise_for_status()
        
    except Exception as e:
        logger.error(f"VirusTotal error for {url}: {str(e)}")
        return {
            'malicious': 0,
            'suspicious': 0,
            'clean': 0,
            'undetected': 0,
            'error': str(e)
        }

def check_google_safe_browsing(url: str) -> dict:
    """Check URL with Google Safe Browsing API with detailed error handling."""
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {
            'malicious': False,
            'threat_type': 'Unknown',
            'error': 'Google Safe Browsing API key not set'
        }
    
    headers = {'Content-Type': 'application/json'}
    params = {
        'client': {
            'clientId': 'domain-recon-web',
            'clientVersion': '1.0'
        },
        'threatInfo': {
            'threatTypes': [
                'MALWARE',
                'SOCIAL_ENGINEERING',
                'UNWANTED_SOFTWARE',
                'POTENTIALLY_HARMFUL_APPLICATION'
            ],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }
    
    try:
        response = requests.post(
            f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}',
            json=params,
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        
        matches = data.get('matches', [])
        if matches:
            return {
                'malicious': True,
                'threat_type': matches[0].get('threatType', 'Unknown'),
                'platform_type': matches[0].get('platformType', 'Unknown'),
                'threat_entry_type': matches[0].get('threatEntryType', 'Unknown')
            }
        else:
            return {
                'malicious': False,
                'threat_type': 'Safe'
            }
            
    except requests.exceptions.HTTPError as e:
        if response.status_code == 403:
            logger.error(f"Google Safe Browsing error for {url}: 403 Forbidden - Check API key and permissions")
            return {
                'malicious': False,
                'threat_type': 'Unknown',
                'error': '403 Forbidden - Check API key'
            }
        else:
            logger.error(f"Google Safe Browsing HTTP error for {url}: {str(e)}")
            return {
                'malicious': False,
                'threat_type': 'Unknown',
                'error': f'HTTP {response.status_code}'
            }
    except requests.exceptions.RequestException as e:
        logger.error(f"Google Safe Browsing request error for {url}: {str(e)}")
        return {
            'malicious': False,
            'threat_type': 'Unknown',
            'error': str(e)
        }

def get_official_link(domain: str) -> str:
    """Return the official link based on domain (expand as needed)."""
    official_links = {
        'facebook.com': 'https://www.facebook.com',
        'google.com': 'https://www.google.com',
        'amazon.com': 'https://www.amazon.com',
        'microsoft.com': 'https://www.microsoft.com',
        'apple.com': 'https://www.apple.com',
        'twitter.com': 'https://www.twitter.com',
        'instagram.com': 'https://www.instagram.com',
        'linkedin.com': 'https://www.linkedin.com',
        'github.com': 'https://www.github.com',
        'stackoverflow.com': 'https://www.stackoverflow.com',
        'reddit.com': 'https://www.reddit.com',
        'youtube.com': 'https://www.youtube.com',
        'netflix.com': 'https://www.netflix.com',
        'paypal.com': 'https://www.paypal.com',
        'ebay.com': 'https://www.ebay.com'
    }
    
    domain_lower = domain.lower()
    for key, value in official_links.items():
        if key in domain_lower:
            return value
    
    return f'https://www.{domain}'