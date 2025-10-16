import requests
import logging
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import re
import json
from typing import Dict, List, Any
from datetime import datetime
import spacy
from urllib.parse import urljoin, urlparse
import time

logger = logging.getLogger(__name__)

class ComplianceAuditor:
    def __init__(self):
        self.gdpr_keywords = [
            'gdpr', 'data protection', 'privacy policy', 'cookie consent',
            'data processing', 'personal data', 'data subject rights',
            'data controller', 'data processor', 'consent', 'legitimate interest'
        ]
        
        self.ccpa_keywords = [
            'ccpa', 'california consumer privacy act', 'do not sell',
            'personal information', 'consumer rights', 'opt-out'
        ]
        
        self.cookie_categories = {
            'necessary': ['session', 'csrf', 'auth', 'security'],
            'analytics': ['google-analytics', 'ga', '_gid', '_gat', 'analytics'],
            'marketing': ['facebook', 'twitter', 'linkedin', 'marketing', 'ads'],
            'tracking': ['tracking', 'pixel', 'beacon', 'doubleclick']
        }
        
        # Load spaCy model for NLP
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            logger.warning("spaCy model not found. NLP features will be limited.")
            self.nlp = None
    
    def audit_compliance(self, domain: str) -> dict:
        """Perform comprehensive compliance audit."""
        try:
            url = f"https://{domain}" if not domain.startswith('http') else domain
            
            # Initialize results
            audit_results = {
                'domain': domain,
                'audit_timestamp': datetime.now().isoformat(),
                'gdpr_compliance': self._audit_gdpr_compliance(url),
                'ccpa_compliance': self._audit_ccpa_compliance(url),
                'cookie_analysis': self._analyze_cookies(url),
                'privacy_policy_analysis': self._analyze_privacy_policy(url),
                'security_headers': self._check_security_headers(url),
                'data_flow_analysis': self._analyze_data_flows(url),
                'consent_mechanisms': self._check_consent_mechanisms(url),
                'overall_score': 0,
                'recommendations': []
            }
            
            # Calculate overall compliance score
            audit_results['overall_score'] = self._calculate_compliance_score(audit_results)
            audit_results['recommendations'] = self._generate_compliance_recommendations(audit_results)
            
            return audit_results
            
        except Exception as e:
            logger.error(f"Error during compliance audit for {domain}: {str(e)}")
            return {
                'domain': domain,
                'error': str(e),
                'audit_timestamp': datetime.now().isoformat(),
                'overall_score': 0
            }
    
    def _audit_gdpr_compliance(self, url: str) -> dict:
        """Audit GDPR compliance."""
        try:
            response = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(response.text, 'html.parser')
            
            gdpr_score = 0
            findings = []
            
            # Check for privacy policy link
            privacy_links = soup.find_all('a', href=True)
            has_privacy_policy = any('privacy' in link.get('href', '').lower() or 
                                   'privacy' in link.text.lower() 
                                   for link in privacy_links)
            
            if has_privacy_policy:
                gdpr_score += 20
                findings.append("✅ Privacy policy link found")
            else:
                findings.append("❌ No privacy policy link detected")
            
            # Check for cookie consent banner
            cookie_elements = soup.find_all(text=re.compile(r'cookie|consent', re.I))
            has_cookie_consent = len(cookie_elements) > 0
            
            if has_cookie_consent:
                gdpr_score += 25
                findings.append("✅ Cookie consent mechanism detected")
            else:
                findings.append("❌ No cookie consent banner found")
            
            # Check for GDPR-specific text
            page_text = soup.get_text().lower()
            gdpr_mentions = sum(1 for keyword in self.gdpr_keywords if keyword in page_text)
            
            if gdpr_mentions >= 3:
                gdpr_score += 20
                findings.append(f"✅ GDPR-related content found ({gdpr_mentions} keywords)")
            else:
                findings.append("⚠️ Limited GDPR-specific content")
            
            # Check for data subject rights information
            rights_keywords = ['access', 'rectification', 'erasure', 'portability', 'object']
            rights_found = sum(1 for keyword in rights_keywords if keyword in page_text)
            
            if rights_found >= 3:
                gdpr_score += 15
                findings.append("✅ Data subject rights information present")
            else:
                findings.append("❌ Data subject rights not clearly outlined")
            
            # Check for contact information for data protection
            contact_keywords = ['data protection officer', 'dpo', 'privacy officer', 'contact']
            has_contact = any(keyword in page_text for keyword in contact_keywords)
            
            if has_contact:
                gdpr_score += 10
                findings.append("✅ Data protection contact information found")
            else:
                findings.append("❌ No data protection contact information")
            
            # Check for legal basis information
            legal_basis_keywords = ['legitimate interest', 'consent', 'contract', 'legal obligation']
            has_legal_basis = any(keyword in page_text for keyword in legal_basis_keywords)
            
            if has_legal_basis:
                gdpr_score += 10
                findings.append("✅ Legal basis for processing mentioned")
            else:
                findings.append("❌ Legal basis for processing not clear")
            
            return {
                'score': gdpr_score,
                'max_score': 100,
                'compliance_level': self._get_compliance_level(gdpr_score),
                'findings': findings,
                'has_privacy_policy': has_privacy_policy,
                'has_cookie_consent': has_cookie_consent,
                'gdpr_keywords_found': gdpr_mentions
            }
            
        except Exception as e:
            logger.error(f"Error auditing GDPR compliance: {str(e)}")
            return {'score': 0, 'error': str(e)}
    
    def _audit_ccpa_compliance(self, url: str) -> dict:
        """Audit CCPA compliance."""
        try:
            response = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(response.text, 'html.parser')
            
            ccpa_score = 0
            findings = []
            
            page_text = soup.get_text().lower()
            
            # Check for "Do Not Sell" link
            do_not_sell_links = soup.find_all('a', text=re.compile(r'do not sell', re.I))
            has_do_not_sell = len(do_not_sell_links) > 0
            
            if has_do_not_sell:
                ccpa_score += 30
                findings.append("✅ 'Do Not Sell' link found")
            else:
                findings.append("❌ No 'Do Not Sell' link detected")
            
            # Check for CCPA-specific content
            ccpa_mentions = sum(1 for keyword in self.ccpa_keywords if keyword in page_text)
            
            if ccpa_mentions >= 2:
                ccpa_score += 25
                findings.append(f"✅ CCPA-related content found ({ccpa_mentions} keywords)")
            else:
                findings.append("⚠️ Limited CCPA-specific content")
            
            # Check for consumer rights information
            consumer_rights = ['right to know', 'right to delete', 'right to opt-out', 'non-discrimination']
            rights_found = sum(1 for right in consumer_rights if right in page_text)
            
            if rights_found >= 2:
                ccpa_score += 25
                findings.append("✅ Consumer rights information present")
            else:
                findings.append("❌ Consumer rights not clearly outlined")
            
            # Check for California-specific notices
            california_keywords = ['california', 'ca resident', 'california consumer']
            has_ca_notice = any(keyword in page_text for keyword in california_keywords)
            
            if has_ca_notice:
                ccpa_score += 20
                findings.append("✅ California-specific notices found")
            else:
                findings.append("❌ No California-specific notices")
            
            return {
                'score': ccpa_score,
                'max_score': 100,
                'compliance_level': self._get_compliance_level(ccpa_score),
                'findings': findings,
                'has_do_not_sell': has_do_not_sell,
                'ccpa_keywords_found': ccpa_mentions
            }
            
        except Exception as e:
            logger.error(f"Error auditing CCPA compliance: {str(e)}")
            return {'score': 0, 'error': str(e)}
    
    def _analyze_cookies(self, url: str) -> dict:
        """Analyze cookies using headless browser."""
        try:
            # Set up headless Chrome
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            
            driver = webdriver.Chrome(options=chrome_options)
            driver.get(url)
            
            # Wait for page to load
            time.sleep(3)
            
            # Get all cookies
            cookies = driver.get_cookies()
            driver.quit()
            
            # Analyze cookies
            cookie_analysis = {
                'total_cookies': len(cookies),
                'categories': {category: [] for category in self.cookie_categories.keys()},
                'security_analysis': {
                    'secure_cookies': 0,
                    'httponly_cookies': 0,
                    'samesite_cookies': 0
                },
                'third_party_cookies': [],
                'findings': []
            }
            
            for cookie in cookies:
                # Categorize cookie
                cookie_name = cookie['name'].lower()
                categorized = False
                
                for category, keywords in self.cookie_categories.items():
                    if any(keyword in cookie_name for keyword in keywords):
                        cookie_analysis['categories'][category].append({
                            'name': cookie['name'],
                            'domain': cookie['domain'],
                            'secure': cookie.get('secure', False),
                            'httpOnly': cookie.get('httpOnly', False)
                        })
                        categorized = True
                        break
                
                if not categorized:
                    cookie_analysis['categories']['necessary'].append({
                        'name': cookie['name'],
                        'domain': cookie['domain'],
                        'secure': cookie.get('secure', False),
                        'httpOnly': cookie.get('httpOnly', False)
                    })
                
                # Security analysis
                if cookie.get('secure'):
                    cookie_analysis['security_analysis']['secure_cookies'] += 1
                if cookie.get('httpOnly'):
                    cookie_analysis['security_analysis']['httponly_cookies'] += 1
                if cookie.get('sameSite'):
                    cookie_analysis['security_analysis']['samesite_cookies'] += 1
                
                # Check for third-party cookies
                parsed_url = urlparse(url)
                if cookie['domain'] != parsed_url.netloc and not cookie['domain'].endswith(parsed_url.netloc):
                    cookie_analysis['third_party_cookies'].append(cookie['name'])
            
            # Generate findings
            if cookie_analysis['total_cookies'] == 0:
                cookie_analysis['findings'].append("✅ No cookies detected")
            else:
                cookie_analysis['findings'].append(f"ℹ️ {cookie_analysis['total_cookies']} cookies found")
                
                if len(cookie_analysis['third_party_cookies']) > 0:
                    cookie_analysis['findings'].append(f"⚠️ {len(cookie_analysis['third_party_cookies'])} third-party cookies detected")
                
                secure_ratio = cookie_analysis['security_analysis']['secure_cookies'] / cookie_analysis['total_cookies']
                if secure_ratio < 0.5:
                    cookie_analysis['findings'].append("❌ Less than 50% of cookies are secure")
                else:
                    cookie_analysis['findings'].append("✅ Majority of cookies are secure")
            
            return cookie_analysis
            
        except Exception as e:
            logger.error(f"Error analyzing cookies: {str(e)}")
            return {
                'total_cookies': 0,
                'error': str(e),
                'findings': ['❌ Cookie analysis failed']
            }
    
    def _analyze_privacy_policy(self, url: str) -> dict:
        """Analyze privacy policy content."""
        try:
            response = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find privacy policy links
            privacy_links = []
            for link in soup.find_all('a', href=True):
                if 'privacy' in link.get('href', '').lower() or 'privacy' in link.text.lower():
                    privacy_links.append(urljoin(url, link['href']))
            
            if not privacy_links:
                return {
                    'found': False,
                    'analysis': 'No privacy policy link found',
                    'score': 0
                }
            
            # Analyze the first privacy policy found
            policy_url = privacy_links[0]
            policy_response = requests.get(policy_url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            policy_soup = BeautifulSoup(policy_response.text, 'html.parser')
            policy_text = policy_soup.get_text().lower()
            
            analysis = {
                'found': True,
                'url': policy_url,
                'word_count': len(policy_text.split()),
                'sections_found': [],
                'missing_sections': [],
                'score': 0,
                'readability': 'Unknown'
            }
            
            # Check for required sections
            required_sections = {
                'data collection': ['data we collect', 'information we collect', 'personal data'],
                'data usage': ['how we use', 'purpose of processing', 'data usage'],
                'data sharing': ['sharing', 'third parties', 'disclosure'],
                'data retention': ['retention', 'how long', 'storage period'],
                'user rights': ['your rights', 'data subject rights', 'access rights'],
                'contact information': ['contact us', 'data protection officer', 'privacy officer'],
                'cookies': ['cookies', 'tracking technologies', 'analytics'],
                'updates': ['changes to policy', 'updates', 'modifications']
            }
            
            for section, keywords in required_sections.items():
                if any(keyword in policy_text for keyword in keywords):
                    analysis['sections_found'].append(section)
                    analysis['score'] += 12.5  # 100/8 sections
                else:
                    analysis['missing_sections'].append(section)
            
            # Basic readability assessment
            sentences = policy_text.count('.') + policy_text.count('!') + policy_text.count('?')
            if sentences > 0:
                avg_sentence_length = len(policy_text.split()) / sentences
                if avg_sentence_length < 15:
                    analysis['readability'] = 'Good'
                elif avg_sentence_length < 25:
                    analysis['readability'] = 'Fair'
                else:
                    analysis['readability'] = 'Poor'
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing privacy policy: {str(e)}")
            return {
                'found': False,
                'error': str(e),
                'score': 0
            }
    
    def _check_security_headers(self, url: str) -> dict:
        """Check security headers for compliance."""
        try:
            response = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            headers = response.headers
            
            security_headers = {
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Referrer-Policy': headers.get('Referrer-Policy'),
                'Permissions-Policy': headers.get('Permissions-Policy'),
                'X-XSS-Protection': headers.get('X-XSS-Protection')
            }
            
            score = 0
            findings = []
            
            for header, value in security_headers.items():
                if value:
                    score += 14.3  # 100/7 headers
                    findings.append(f"✅ {header} present")
                else:
                    findings.append(f"❌ {header} missing")
            
            return {
                'score': round(score, 1),
                'headers': security_headers,
                'findings': findings
            }
            
        except Exception as e:
            logger.error(f"Error checking security headers: {str(e)}")
            return {'score': 0, 'error': str(e)}
    
    def _analyze_data_flows(self, url: str) -> dict:
        """Analyze potential data flows and third-party connections."""
        try:
            response = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find external scripts and resources
            external_resources = []
            
            # Check scripts
            for script in soup.find_all('script', src=True):
                src = script['src']
                if src.startswith('http') and not any(domain in src for domain in [urlparse(url).netloc]):
                    external_resources.append({
                        'type': 'script',
                        'url': src,
                        'domain': urlparse(src).netloc
                    })
            
            # Check iframes
            for iframe in soup.find_all('iframe', src=True):
                src = iframe['src']
                if src.startswith('http') and not any(domain in src for domain in [urlparse(url).netloc]):
                    external_resources.append({
                        'type': 'iframe',
                        'url': src,
                        'domain': urlparse(src).netloc
                    })
            
            # Check images
            for img in soup.find_all('img', src=True):
                src = img['src']
                if src.startswith('http') and not any(domain in src for domain in [urlparse(url).netloc]):
                    external_resources.append({
                        'type': 'image',
                        'url': src,
                        'domain': urlparse(src).netloc
                    })
            
            # Categorize by known services
            known_services = {
                'google-analytics.com': 'Analytics',
                'googletagmanager.com': 'Analytics',
                'facebook.com': 'Social Media',
                'twitter.com': 'Social Media',
                'linkedin.com': 'Social Media',
                'doubleclick.net': 'Advertising',
                'googlesyndication.com': 'Advertising'
            }
            
            service_analysis = {}
            for resource in external_resources:
                domain = resource['domain']
                service_type = 'Unknown'
                
                for known_domain, service in known_services.items():
                    if known_domain in domain:
                        service_type = service
                        break
                
                if service_type not in service_analysis:
                    service_analysis[service_type] = []
                service_analysis[service_type].append(domain)
            
            return {
                'total_external_resources': len(external_resources),
                'external_domains': list(set(r['domain'] for r in external_resources)),
                'service_analysis': service_analysis,
                'potential_data_flows': len(set(r['domain'] for r in external_resources))
            }
            
        except Exception as e:
            logger.error(f"Error analyzing data flows: {str(e)}")
            return {'error': str(e)}
    
    def _check_consent_mechanisms(self, url: str) -> dict:
        """Check for consent mechanisms and banners."""
        try:
            # Set up headless browser for dynamic content
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            
            driver = webdriver.Chrome(options=chrome_options)
            driver.get(url)
            
            # Wait for page to load
            time.sleep(3)
            
            consent_analysis = {
                'cookie_banner_found': False,
                'consent_buttons': [],
                'privacy_links': [],
                'opt_out_mechanisms': [],
                'findings': []
            }
            
            # Look for cookie banners
            cookie_banner_selectors = [
                '[class*="cookie"]',
                '[id*="cookie"]',
                '[class*="consent"]',
                '[id*="consent"]',
                '[class*="gdpr"]',
                '[id*="gdpr"]'
            ]
            
            for selector in cookie_banner_selectors:
                try:
                    elements = driver.find_elements(By.CSS_SELECTOR, selector)
                    if elements:
                        consent_analysis['cookie_banner_found'] = True
                        consent_analysis['findings'].append("✅ Cookie consent banner detected")
                        break
                except:
                    continue
            
            if not consent_analysis['cookie_banner_found']:
                consent_analysis['findings'].append("❌ No cookie consent banner found")
            
            # Look for consent buttons
            button_texts = ['accept', 'consent', 'agree', 'allow', 'reject', 'decline']
            buttons = driver.find_elements(By.TAG_NAME, 'button')
            
            for button in buttons:
                button_text = button.text.lower()
                if any(text in button_text for text in button_texts):
                    consent_analysis['consent_buttons'].append(button.text)
            
            if consent_analysis['consent_buttons']:
                consent_analysis['findings'].append(f"✅ Consent buttons found: {', '.join(consent_analysis['consent_buttons'])}")
            else:
                consent_analysis['findings'].append("❌ No consent buttons detected")
            
            driver.quit()
            return consent_analysis
            
        except Exception as e:
            logger.error(f"Error checking consent mechanisms: {str(e)}")
            return {
                'cookie_banner_found': False,
                'error': str(e),
                'findings': ['❌ Consent mechanism analysis failed']
            }
    
    def _calculate_compliance_score(self, audit_results: dict) -> int:
        """Calculate overall compliance score."""
        try:
            scores = []
            
            # GDPR score (weight: 30%)
            if 'gdpr_compliance' in audit_results and 'score' in audit_results['gdpr_compliance']:
                scores.append(audit_results['gdpr_compliance']['score'] * 0.3)
            
            # CCPA score (weight: 20%)
            if 'ccpa_compliance' in audit_results and 'score' in audit_results['ccpa_compliance']:
                scores.append(audit_results['ccpa_compliance']['score'] * 0.2)
            
            # Privacy policy score (weight: 20%)
            if 'privacy_policy_analysis' in audit_results and 'score' in audit_results['privacy_policy_analysis']:
                scores.append(audit_results['privacy_policy_analysis']['score'] * 0.2)
            
            # Security headers score (weight: 15%)
            if 'security_headers' in audit_results and 'score' in audit_results['security_headers']:
                scores.append(audit_results['security_headers']['score'] * 0.15)
            
            # Cookie compliance (weight: 15%)
            cookie_score = 0
            if 'cookie_analysis' in audit_results:
                cookie_data = audit_results['cookie_analysis']
                if cookie_data.get('total_cookies', 0) == 0:
                    cookie_score = 100  # No cookies = perfect score
                else:
                    # Score based on security features
                    total = cookie_data.get('total_cookies', 1)
                    secure_ratio = cookie_data.get('security_analysis', {}).get('secure_cookies', 0) / total
                    cookie_score = secure_ratio * 100
                
                scores.append(cookie_score * 0.15)
            
            return int(sum(scores)) if scores else 0
            
        except Exception as e:
            logger.error(f"Error calculating compliance score: {str(e)}")
            return 0
    
    def _generate_compliance_recommendations(self, audit_results: dict) -> List[str]:
        """Generate compliance recommendations."""
        recommendations = []
        
        try:
            overall_score = audit_results.get('overall_score', 0)
            
            if overall_score < 50:
                recommendations.append("🚨 CRITICAL: Major compliance issues detected - immediate action required")
            elif overall_score < 70:
                recommendations.append("⚠️ WARNING: Significant compliance gaps need attention")
            else:
                recommendations.append("✅ Good compliance posture - minor improvements recommended")
            
            # GDPR recommendations
            gdpr = audit_results.get('gdpr_compliance', {})
            if gdpr.get('score', 0) < 70:
                if not gdpr.get('has_privacy_policy'):
                    recommendations.append("📋 Implement comprehensive privacy policy")
                if not gdpr.get('has_cookie_consent'):
                    recommendations.append("🍪 Add GDPR-compliant cookie consent banner")
                recommendations.append("🔒 Ensure data subject rights are clearly outlined")
            
            # CCPA recommendations
            ccpa = audit_results.get('ccpa_compliance', {})
            if ccpa.get('score', 0) < 70:
                if not ccpa.get('has_do_not_sell'):
                    recommendations.append("🚫 Add 'Do Not Sell My Personal Information' link")
                recommendations.append("📍 Include California-specific privacy notices")
            
            # Security headers
            security = audit_results.get('security_headers', {})
            if security.get('score', 0) < 80:
                recommendations.append("🛡️ Implement missing security headers (CSP, HSTS, etc.)")
            
            # Cookie recommendations
            cookies = audit_results.get('cookie_analysis', {})
            if cookies.get('total_cookies', 0) > 0:
                secure_cookies = cookies.get('security_analysis', {}).get('secure_cookies', 0)
                total_cookies = cookies.get('total_cookies', 1)
                if secure_cookies / total_cookies < 0.8:
                    recommendations.append("🔐 Ensure all cookies use Secure and HttpOnly flags")
            
            # Privacy policy recommendations
            policy = audit_results.get('privacy_policy_analysis', {})
            if policy.get('found') and policy.get('score', 0) < 80:
                recommendations.append("📝 Update privacy policy to include all required sections")
                if policy.get('readability') == 'Poor':
                    recommendations.append("📖 Improve privacy policy readability and clarity")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {str(e)}")
            return ["❌ Unable to generate recommendations"]
    
    def _get_compliance_level(self, score: int) -> str:
        """Convert score to compliance level."""
        if score >= 90:
            return 'Excellent'
        elif score >= 80:
            return 'Good'
        elif score >= 70:
            return 'Fair'
        elif score >= 50:
            return 'Poor'
        else:
            return 'Critical'

# Initialize global compliance auditor
compliance_auditor = ComplianceAuditor()