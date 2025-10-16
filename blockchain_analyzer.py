import requests
import logging
from typing import Dict, List, Any, Optional
import json
from datetime import datetime
import hashlib
import re
from web3 import Web3
from eth_utils import is_address, to_checksum_address

logger = logging.getLogger(__name__)

class BlockchainDomainAnalyzer:
    def __init__(self):
        self.ens_resolver_address = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
        self.unstoppable_api_base = "https://resolve.unstoppabledomains.com"
        
        # Blockchain RPC endpoints (use public endpoints or configure your own)
        self.rpc_endpoints = {
            'ethereum': 'https://eth-mainnet.alchemyapi.io/v2/demo',
            'polygon': 'https://polygon-rpc.com',
            'bsc': 'https://bsc-dataseed.binance.org'
        }
        
        # Known scam patterns and addresses
        self.scam_patterns = {
            'fake_exchanges': [
                'binance-security', 'coinbase-support', 'kraken-verify',
                'bitfinex-update', 'huobi-security', 'okex-verify'
            ],
            'fake_wallets': [
                'metamask-support', 'trustwallet-verify', 'ledger-update',
                'trezor-security', 'exodus-support'
            ],
            'fake_defi': [
                'uniswap-airdrop', 'sushiswap-claim', 'pancakeswap-bonus',
                'compound-rewards', 'aave-claim'
            ],
            'fake_nft': [
                'opensea-mint', 'rarible-drop', 'superrare-claim',
                'foundation-mint', 'async-drop'
            ]
        }
        
        # Known blacklisted addresses (example addresses)
        self.blacklisted_addresses = {
            'ethereum': [
                '0x0000000000000000000000000000000000000000',  # Null address
                # Add more known scam addresses
            ],
            'bitcoin': [
                # Add known Bitcoin scam addresses
            ]
        }
        
        # Initialize Web3 connections
        self.w3_connections = {}
        self.init_web3_connections()
    
    def init_web3_connections(self):
        """Initialize Web3 connections to different networks."""
        try:
            for network, endpoint in self.rpc_endpoints.items():
                try:
                    w3 = Web3(Web3.HTTPProvider(endpoint))
                    if w3.isConnected():
                        self.w3_connections[network] = w3
                        logger.info(f"Connected to {network} network")
                    else:
                        logger.warning(f"Failed to connect to {network} network")
                except Exception as e:
                    logger.error(f"Error connecting to {network}: {str(e)}")
        except Exception as e:
            logger.error(f"Error initializing Web3 connections: {str(e)}")
    
    def analyze_blockchain_domain(self, domain: str) -> dict:
        """Comprehensive blockchain domain analysis."""
        try:
            analysis_result = {
                'domain': domain,
                'analysis_timestamp': datetime.now().isoformat(),
                'blockchain_type': self.detect_blockchain_type(domain),
                'ens_analysis': {},
                'unstoppable_analysis': {},
                'wallet_analysis': {},
                'transaction_analysis': {},
                'scam_indicators': [],
                'risk_assessment': {},
                'recommendations': []
            }
            
            # Determine blockchain type and perform specific analysis
            blockchain_type = analysis_result['blockchain_type']
            
            if blockchain_type == 'ens':
                analysis_result['ens_analysis'] = self.analyze_ens_domain(domain)
                if analysis_result['ens_analysis'].get('address'):
                    analysis_result['wallet_analysis'] = self.analyze_ethereum_wallet(
                        analysis_result['ens_analysis']['address']
                    )
            
            elif blockchain_type == 'unstoppable':
                analysis_result['unstoppable_analysis'] = self.analyze_unstoppable_domain(domain)
                if analysis_result['unstoppable_analysis'].get('crypto_addresses'):
                    for crypto, address in analysis_result['unstoppable_analysis']['crypto_addresses'].items():
                        if address and crypto == 'eth':
                            analysis_result['wallet_analysis'] = self.analyze_ethereum_wallet(address)
            
            elif blockchain_type == 'traditional':
                # Analyze traditional domain for crypto-related content
                analysis_result['crypto_content_analysis'] = self.analyze_crypto_content(domain)
                analysis_result['scam_indicators'] = self.detect_crypto_scam_patterns(domain)
            
            # Perform cross-chain analysis if wallet addresses found
            if analysis_result.get('wallet_analysis'):
                analysis_result['transaction_analysis'] = self.analyze_transactions(
                    analysis_result['wallet_analysis']
                )
            
            # Risk assessment
            analysis_result['risk_assessment'] = self.assess_blockchain_risk(analysis_result)
            analysis_result['recommendations'] = self.generate_blockchain_recommendations(analysis_result)
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error analyzing blockchain domain {domain}: {str(e)}")
            return {
                'domain': domain,
                'error': str(e),
                'analysis_timestamp': datetime.now().isoformat()
            }
    
    def detect_blockchain_type(self, domain: str) -> str:
        """Detect the type of blockchain domain."""
        domain_lower = domain.lower()
        
        # ENS domains
        if domain_lower.endswith('.eth'):
            return 'ens'
        
        # Unstoppable Domains
        unstoppable_tlds = ['.crypto', '.nft', '.blockchain', '.bitcoin', '.wallet', '.x', '.888', '.dao', '.zil']
        if any(domain_lower.endswith(tld) for tld in unstoppable_tlds):
            return 'unstoppable'
        
        # Traditional domains with crypto content
        return 'traditional'
    
    def analyze_ens_domain(self, domain: str) -> dict:
        """Analyze ENS domain."""
        try:
            if 'ethereum' not in self.w3_connections:
                return {'error': 'Ethereum connection not available'}
            
            w3 = self.w3_connections['ethereum']
            
            # Resolve ENS domain
            try:
                address = w3.ens.address(domain)
                if not address:
                    return {'error': 'ENS domain not found or not resolved'}
                
                # Get ENS record details
                resolver = w3.ens.resolver(domain)
                
                ens_data = {
                    'domain': domain,
                    'address': address,
                    'resolver': str(resolver.address) if resolver else None,
                    'records': {},
                    'registration_info': {},
                    'is_valid': True
                }
                
                # Get additional records
                try:
                    # Text records
                    text_keys = ['email', 'url', 'avatar', 'description', 'notice', 'keywords']
                    for key in text_keys:
                        try:
                            value = w3.ens.get_text(domain, key)
                            if value:
                                ens_data['records'][key] = value
                        except:
                            pass
                    
                    # Content hash
                    try:
                        content_hash = w3.ens.get_text(domain, 'contenthash')
                        if content_hash:
                            ens_data['records']['contenthash'] = content_hash
                    except:
                        pass
                
                except Exception as e:
                    logger.warning(f"Error getting ENS records: {str(e)}")
                
                return ens_data
                
            except Exception as e:
                return {'error': f'ENS resolution failed: {str(e)}', 'is_valid': False}
            
        except Exception as e:
            logger.error(f"Error analyzing ENS domain: {str(e)}")
            return {'error': str(e)}
    
    def analyze_unstoppable_domain(self, domain: str) -> dict:
        """Analyze Unstoppable Domains."""
        try:
            # Use Unstoppable Domains API
            response = requests.get(f'{self.unstoppable_api_base}/domains/{domain}', timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                unstoppable_data = {
                    'domain': domain,
                    'owner': data.get('meta', {}).get('owner'),
                    'resolver': data.get('meta', {}).get('resolver'),
                    'records': data.get('records', {}),
                    'crypto_addresses': {},
                    'ipfs_hash': data.get('records', {}).get('dweb.ipfs.hash'),
                    'is_valid': True
                }
                
                # Extract crypto addresses
                records = data.get('records', {})
                crypto_currencies = ['BTC', 'ETH', 'LTC', 'BCH', 'XRP', 'ADA', 'DOT', 'MATIC']
                
                for currency in crypto_currencies:
                    address_key = f'crypto.{currency}.address'
                    if address_key in records:
                        unstoppable_data['crypto_addresses'][currency.lower()] = records[address_key]
                
                # Additional metadata
                unstoppable_data['website'] = records.get('dweb.ipfs.hash')
                unstoppable_data['email'] = records.get('whois.email.value')
                
                return unstoppable_data
            
            elif response.status_code == 404:
                return {'error': 'Unstoppable domain not found', 'is_valid': False}
            else:
                return {'error': f'API error: {response.status_code}', 'is_valid': False}
            
        except Exception as e:
            logger.error(f"Error analyzing Unstoppable domain: {str(e)}")
            return {'error': str(e)}
    
    def analyze_ethereum_wallet(self, address: str) -> dict:
        """Analyze Ethereum wallet address."""
        try:
            if 'ethereum' not in self.w3_connections:
                return {'error': 'Ethereum connection not available'}
            
            w3 = self.w3_connections['ethereum']
            
            if not is_address(address):
                return {'error': 'Invalid Ethereum address'}
            
            address = to_checksum_address(address)
            
            wallet_data = {
                'address': address,
                'balance': 0,
                'transaction_count': 0,
                'is_contract': False,
                'first_seen': None,
                'last_activity': None,
                'risk_indicators': [],
                'associated_tokens': []
            }
            
            try:
                # Get balance
                balance_wei = w3.eth.get_balance(address)
                wallet_data['balance'] = w3.fromWei(balance_wei, 'ether')
                
                # Get transaction count
                wallet_data['transaction_count'] = w3.eth.get_transaction_count(address)
                
                # Check if it's a contract
                code = w3.eth.get_code(address)
                wallet_data['is_contract'] = len(code) > 0
                
                # Risk indicators
                if address.lower() in [addr.lower() for addr in self.blacklisted_addresses.get('ethereum', [])]:
                    wallet_data['risk_indicators'].append('Address on blacklist')
                
                if wallet_data['balance'] == 0 and wallet_data['transaction_count'] == 0:
                    wallet_data['risk_indicators'].append('Inactive address')
                
                if wallet_data['transaction_count'] > 10000:
                    wallet_data['risk_indicators'].append('High transaction volume (possible exchange/mixer)')
                
            except Exception as e:
                logger.warning(f"Error getting wallet details: {str(e)}")
            
            return wallet_data
            
        except Exception as e:
            logger.error(f"Error analyzing Ethereum wallet: {str(e)}")
            return {'error': str(e)}
    
    def analyze_crypto_content(self, domain: str) -> dict:
        """Analyze traditional domain for crypto-related content."""
        try:
            url = f"https://{domain}" if not domain.startswith('http') else domain
            response = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            
            content = response.text.lower()
            
            crypto_analysis = {
                'has_crypto_content': False,
                'crypto_keywords': [],
                'wallet_addresses': [],
                'crypto_services': [],
                'suspicious_patterns': []
            }
            
            # Crypto keywords
            crypto_keywords = [
                'bitcoin', 'ethereum', 'crypto', 'blockchain', 'defi', 'nft',
                'wallet', 'exchange', 'trading', 'mining', 'staking', 'yield',
                'token', 'coin', 'altcoin', 'hodl', 'dapp', 'smart contract'
            ]
            
            found_keywords = [keyword for keyword in crypto_keywords if keyword in content]
            crypto_analysis['crypto_keywords'] = found_keywords
            crypto_analysis['has_crypto_content'] = len(found_keywords) > 0
            
            # Look for wallet addresses
            # Bitcoin addresses
            btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
            btc_addresses = re.findall(btc_pattern, response.text)
            
            # Ethereum addresses
            eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
            eth_addresses = re.findall(eth_pattern, response.text)
            
            crypto_analysis['wallet_addresses'] = {
                'bitcoin': btc_addresses[:5],  # Limit to 5
                'ethereum': eth_addresses[:5]
            }
            
            # Detect crypto services
            service_patterns = {
                'exchange': ['buy crypto', 'sell crypto', 'trade', 'exchange'],
                'wallet': ['store crypto', 'secure wallet', 'private keys'],
                'mining': ['mining pool', 'hash rate', 'mining rewards'],
                'defi': ['liquidity pool', 'yield farming', 'lending protocol']
            }
            
            for service, patterns in service_patterns.items():
                if any(pattern in content for pattern in patterns):
                    crypto_analysis['crypto_services'].append(service)
            
            return crypto_analysis
            
        except Exception as e:
            logger.error(f"Error analyzing crypto content: {str(e)}")
            return {'error': str(e)}
    
    def detect_crypto_scam_patterns(self, domain: str) -> List[dict]:
        """Detect crypto scam patterns in domain."""
        scam_indicators = []
        domain_lower = domain.lower()
        
        try:
            # Check against known scam patterns
            for category, patterns in self.scam_patterns.items():
                for pattern in patterns:
                    if pattern in domain_lower:
                        scam_indicators.append({
                            'type': 'domain_pattern',
                            'category': category,
                            'pattern': pattern,
                            'severity': 'high',
                            'description': f'Domain contains suspicious pattern: {pattern}'
                        })
            
            # Check for typosquatting of popular crypto sites
            popular_crypto_sites = [
                'binance', 'coinbase', 'kraken', 'bitfinex', 'huobi',
                'metamask', 'uniswap', 'opensea', 'ethereum', 'bitcoin'
            ]
            
            for site in popular_crypto_sites:
                if site in domain_lower and domain_lower != f"{site}.com":
                    # Calculate similarity
                    similarity = self.calculate_domain_similarity(domain_lower, f"{site}.com")
                    if similarity > 0.7:
                        scam_indicators.append({
                            'type': 'typosquatting',
                            'target_site': site,
                            'similarity': similarity,
                            'severity': 'critical',
                            'description': f'Possible typosquatting of {site}.com'
                        })
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
            for tld in suspicious_tlds:
                if domain_lower.endswith(tld):
                    scam_indicators.append({
                        'type': 'suspicious_tld',
                        'tld': tld,
                        'severity': 'medium',
                        'description': f'Domain uses suspicious TLD: {tld}'
                    })
            
            # Check for excessive hyphens or numbers
            if domain_lower.count('-') > 3:
                scam_indicators.append({
                    'type': 'suspicious_structure',
                    'severity': 'medium',
                    'description': 'Domain contains excessive hyphens'
                })
            
            if len(re.findall(r'\d', domain_lower)) > 5:
                scam_indicators.append({
                    'type': 'suspicious_structure',
                    'severity': 'medium',
                    'description': 'Domain contains excessive numbers'
                })
            
            return scam_indicators
            
        except Exception as e:
            logger.error(f"Error detecting scam patterns: {str(e)}")
            return []
    
    def analyze_transactions(self, wallet_data: dict) -> dict:
        """Analyze wallet transactions for suspicious patterns."""
        try:
            if 'ethereum' not in self.w3_connections:
                return {'error': 'Ethereum connection not available'}
            
            address = wallet_data.get('address')
            if not address:
                return {'error': 'No wallet address provided'}
            
            transaction_analysis = {
                'total_transactions': wallet_data.get('transaction_count', 0),
                'suspicious_patterns': [],
                'interaction_analysis': {},
                'risk_score': 0
            }
            
            # Analyze transaction patterns (simplified due to API limitations)
            tx_count = wallet_data.get('transaction_count', 0)
            
            if tx_count > 1000:
                transaction_analysis['suspicious_patterns'].append('High transaction volume')
                transaction_analysis['risk_score'] += 20
            
            if tx_count == 0:
                transaction_analysis['suspicious_patterns'].append('No transaction history')
                transaction_analysis['risk_score'] += 10
            
            # Check balance vs transaction count ratio
            balance = wallet_data.get('balance', 0)
            if tx_count > 100 and balance == 0:
                transaction_analysis['suspicious_patterns'].append('High activity but zero balance')
                transaction_analysis['risk_score'] += 30
            
            return transaction_analysis
            
        except Exception as e:
            logger.error(f"Error analyzing transactions: {str(e)}")
            return {'error': str(e)}
    
    def assess_blockchain_risk(self, analysis_result: dict) -> dict:
        """Assess overall blockchain-related risk."""
        try:
            risk_assessment = {
                'overall_risk_score': 0,
                'risk_level': 'low',
                'risk_factors': [],
                'confidence': 'medium'
            }
            
            risk_score = 0
            
            # Scam indicators
            scam_indicators = analysis_result.get('scam_indicators', [])
            for indicator in scam_indicators:
                if indicator.get('severity') == 'critical':
                    risk_score += 40
                elif indicator.get('severity') == 'high':
                    risk_score += 25
                elif indicator.get('severity') == 'medium':
                    risk_score += 15
                
                risk_assessment['risk_factors'].append(indicator.get('description', ''))
            
            # Wallet analysis risks
            wallet_analysis = analysis_result.get('wallet_analysis', {})
            wallet_risks = wallet_analysis.get('risk_indicators', [])
            risk_score += len(wallet_risks) * 10
            risk_assessment['risk_factors'].extend(wallet_risks)
            
            # Transaction analysis risks
            transaction_analysis = analysis_result.get('transaction_analysis', {})
            tx_risk_score = transaction_analysis.get('risk_score', 0)
            risk_score += tx_risk_score
            
            # Domain type risks
            blockchain_type = analysis_result.get('blockchain_type', 'traditional')
            if blockchain_type == 'traditional' and analysis_result.get('crypto_content_analysis', {}).get('has_crypto_content'):
                risk_score += 10  # Traditional domains with crypto content need scrutiny
            
            # Determine risk level
            risk_assessment['overall_risk_score'] = min(100, risk_score)
            
            if risk_score >= 70:
                risk_assessment['risk_level'] = 'critical'
            elif risk_score >= 50:
                risk_assessment['risk_level'] = 'high'
            elif risk_score >= 30:
                risk_assessment['risk_level'] = 'medium'
            else:
                risk_assessment['risk_level'] = 'low'
            
            return risk_assessment
            
        except Exception as e:
            logger.error(f"Error assessing blockchain risk: {str(e)}")
            return {'overall_risk_score': 0, 'risk_level': 'unknown'}
    
    def generate_blockchain_recommendations(self, analysis_result: dict) -> List[str]:
        """Generate blockchain-specific recommendations."""
        recommendations = []
        
        try:
            risk_level = analysis_result.get('risk_assessment', {}).get('risk_level', 'low')
            blockchain_type = analysis_result.get('blockchain_type', 'traditional')
            
            # Risk-based recommendations
            if risk_level == 'critical':
                recommendations.append("🚨 CRITICAL: Do not interact with this domain - high scam risk detected")
                recommendations.append("🔒 Report domain to relevant authorities and security communities")
                recommendations.append("⚠️ Warn others about potential scam indicators")
            
            elif risk_level == 'high':
                recommendations.append("⚠️ HIGH RISK: Exercise extreme caution when interacting")
                recommendations.append("🔍 Verify domain authenticity through official channels")
                recommendations.append("💰 Never send cryptocurrency or connect wallets")
            
            elif risk_level == 'medium':
                recommendations.append("⚡ MEDIUM RISK: Proceed with caution")
                recommendations.append("🔐 Use hardware wallet if interaction is necessary")
                recommendations.append("📱 Enable all available security features")
            
            # Blockchain type specific recommendations
            if blockchain_type == 'ens':
                recommendations.append("🌐 Verify ENS domain resolution through multiple sources")
                recommendations.append("🔍 Check ENS domain history and ownership changes")
            
            elif blockchain_type == 'unstoppable':
                recommendations.append("🔗 Verify Unstoppable Domain through official resolver")
                recommendations.append("📋 Check domain records for suspicious content")
            
            # Wallet-specific recommendations
            wallet_analysis = analysis_result.get('wallet_analysis', {})
            if wallet_analysis.get('risk_indicators'):
                recommendations.append("💳 Associated wallet shows suspicious activity")
                recommendations.append("🚫 Avoid sending funds to associated addresses")
            
            # Scam-specific recommendations
            scam_indicators = analysis_result.get('scam_indicators', [])
            if scam_indicators:
                recommendations.append("🎯 Domain shows patterns consistent with crypto scams")
                recommendations.append("📚 Educate yourself about common crypto scam tactics")
            
            # General security recommendations
            recommendations.append("🔒 Always verify URLs before entering sensitive information")
            recommendations.append("🛡️ Use reputable antivirus and anti-phishing tools")
            recommendations.append("📖 Stay informed about latest crypto security threats")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating blockchain recommendations: {str(e)}")
            return ["❌ Unable to generate recommendations"]
    
    def calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between two domains using Levenshtein distance."""
        try:
            def levenshtein_distance(s1, s2):
                if len(s1) < len(s2):
                    return levenshtein_distance(s2, s1)
                
                if len(s2) == 0:
                    return len(s1)
                
                previous_row = list(range(len(s2) + 1))
                for i, c1 in enumerate(s1):
                    current_row = [i + 1]
                    for j, c2 in enumerate(s2):
                        insertions = previous_row[j + 1] + 1
                        deletions = current_row[j] + 1
                        substitutions = previous_row[j] + (c1 != c2)
                        current_row.append(min(insertions, deletions, substitutions))
                    previous_row = current_row
                
                return previous_row[-1]
            
            distance = levenshtein_distance(domain1, domain2)
            max_len = max(len(domain1), len(domain2))
            similarity = 1 - (distance / max_len)
            
            return similarity
            
        except Exception as e:
            logger.error(f"Error calculating domain similarity: {str(e)}")
            return 0.0

# Initialize global blockchain analyzer
blockchain_analyzer = BlockchainDomainAnalyzer()