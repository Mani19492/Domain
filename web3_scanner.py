import requests
import logging
from typing import Dict, List
from web3 import Web3
import json

logger = logging.getLogger(__name__)

class Web3DomainScanner:
    def __init__(self):
        self.ens_resolver_address = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
        self.unstoppable_api_base = "https://resolve.unstoppabledomains.com"
        
    def scan_web3_domain(self, domain: str) -> dict:
        """Comprehensive Web3 domain scanning."""
        results = {
            'domain': domain,
            'ens_data': self._scan_ens_domain(domain),
            'unstoppable_data': self._scan_unstoppable_domain(domain),
            'blockchain_analysis': self._analyze_blockchain_presence(domain),
            'crypto_threats': self._check_crypto_threats(domain),
            'nft_analysis': self._analyze_nft_connections(domain)
        }
        
        return results
    
    def _scan_ens_domain(self, domain: str) -> dict:
        """Scan Ethereum Name Service domains."""
        try:
            # Check if domain ends with .eth
            if not domain.endswith('.eth'):
                return {'error': 'Not an ENS domain', 'is_ens': False}
            
            # Use public ENS API
            response = requests.get(f'https://api.ensideas.com/ens/resolve/{domain}', timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'is_ens': True,
                    'address': data.get('address'),
                    'resolver': data.get('resolver'),
                    'owner': data.get('owner'),
                    'registration_date': data.get('registration_date'),
                    'expiry_date': data.get('expiry_date'),
                    'records': data.get('records', {}),
                    'reverse_record': data.get('reverse_record')
                }
            else:
                return {'error': 'ENS domain not found', 'is_ens': True}
                
        except Exception as e:
            logger.error(f"ENS scanning error for {domain}: {str(e)}")
            return {'error': str(e), 'is_ens': domain.endswith('.eth')}
    
    def _scan_unstoppable_domain(self, domain: str) -> dict:
        """Scan Unstoppable Domains (.crypto, .nft, .blockchain, etc.)."""
        try:
            unstoppable_tlds = ['.crypto', '.nft', '.blockchain', '.bitcoin', '.wallet', '.x', '.888', '.dao', '.zil']
            
            if not any(domain.endswith(tld) for tld in unstoppable_tlds):
                return {'error': 'Not an Unstoppable domain', 'is_unstoppable': False}
            
            # Use Unstoppable Domains API
            response = requests.get(f'{self.unstoppable_api_base}/domains/{domain}', timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'is_unstoppable': True,
                    'owner': data.get('meta', {}).get('owner'),
                    'resolver': data.get('meta', {}).get('resolver'),
                    'records': data.get('records', {}),
                    'ipfs_hash': data.get('records', {}).get('dweb.ipfs.hash'),
                    'crypto_addresses': {
                        'btc': data.get('records', {}).get('crypto.BTC.address'),
                        'eth': data.get('records', {}).get('crypto.ETH.address'),
                        'ltc': data.get('records', {}).get('crypto.LTC.address')
                    }
                }
            else:
                return {'error': 'Unstoppable domain not found', 'is_unstoppable': True}
                
        except Exception as e:
            logger.error(f"Unstoppable Domains scanning error for {domain}: {str(e)}")
            return {'error': str(e), 'is_unstoppable': any(domain.endswith(tld) for tld in ['.crypto', '.nft', '.blockchain'])}
    
    def _analyze_blockchain_presence(self, domain: str) -> dict:
        """Analyze blockchain-related presence of traditional domains."""
        try:
            analysis = {
                'has_crypto_keywords': self._check_crypto_keywords(domain),
                'defi_protocols': self._check_defi_protocols(domain),
                'exchange_similarity': self._check_exchange_similarity(domain),
                'wallet_similarity': self._check_wallet_similarity(domain)
            }
            
            return analysis
            
        except Exception as e:
            logger.error(f"Blockchain analysis error for {domain}: {str(e)}")
            return {'error': str(e)}
    
    def _check_crypto_keywords(self, domain: str) -> dict:
        """Check for cryptocurrency-related keywords in domain."""
        crypto_keywords = [
            'bitcoin', 'btc', 'ethereum', 'eth', 'crypto', 'blockchain', 'defi',
            'nft', 'token', 'coin', 'wallet', 'exchange', 'trading', 'mining',
            'staking', 'yield', 'swap', 'dex', 'dao', 'web3', 'metaverse'
        ]
        
        found_keywords = [keyword for keyword in crypto_keywords if keyword in domain.lower()]
        
        return {
            'found_keywords': found_keywords,
            'keyword_count': len(found_keywords),
            'crypto_related': len(found_keywords) > 0
        }
    
    def _check_defi_protocols(self, domain: str) -> dict:
        """Check similarity to known DeFi protocols."""
        defi_protocols = [
            'uniswap', 'sushiswap', 'pancakeswap', 'compound', 'aave', 'makerdao',
            'yearn', 'curve', 'balancer', '1inch', 'synthetix', 'chainlink'
        ]
        
        similar_protocols = []
        for protocol in defi_protocols:
            if protocol in domain.lower() or self._calculate_similarity(domain.lower(), protocol) > 0.8:
                similar_protocols.append(protocol)
        
        return {
            'similar_protocols': similar_protocols,
            'potential_impersonation': len(similar_protocols) > 0
        }
    
    def _check_exchange_similarity(self, domain: str) -> dict:
        """Check similarity to cryptocurrency exchanges."""
        exchanges = [
            'binance', 'coinbase', 'kraken', 'bitfinex', 'huobi', 'okex',
            'kucoin', 'gemini', 'bitstamp', 'coincheck', 'bittrex'
        ]
        
        similar_exchanges = []
        for exchange in exchanges:
            if exchange in domain.lower() or self._calculate_similarity(domain.lower(), exchange) > 0.8:
                similar_exchanges.append(exchange)
        
        return {
            'similar_exchanges': similar_exchanges,
            'potential_phishing': len(similar_exchanges) > 0
        }
    
    def _check_wallet_similarity(self, domain: str) -> dict:
        """Check similarity to cryptocurrency wallets."""
        wallets = [
            'metamask', 'trustwallet', 'coinbase', 'exodus', 'electrum',
            'myetherwallet', 'ledger', 'trezor', 'phantom', 'solflare'
        ]
        
        similar_wallets = []
        for wallet in wallets:
            if wallet in domain.lower() or self._calculate_similarity(domain.lower(), wallet) > 0.8:
                similar_wallets.append(wallet)
        
        return {
            'similar_wallets': similar_wallets,
            'potential_phishing': len(similar_wallets) > 0
        }
    
    def _check_crypto_threats(self, domain: str) -> dict:
        """Check for known crypto-related threats."""
        try:
            # Check against known crypto scam databases
            threats = {
                'scam_database_hits': [],
                'phishing_indicators': [],
                'rugpull_indicators': [],
                'fake_ico_indicators': []
            }
            
            # Scam indicators
            scam_indicators = ['free', 'giveaway', 'double', 'airdrop', 'bonus', 'promo']
            for indicator in scam_indicators:
                if indicator in domain.lower():
                    threats['phishing_indicators'].append(f"Contains '{indicator}' - common in crypto scams")
            
            # Fake ICO indicators
            ico_indicators = ['ico', 'presale', 'tokensale', 'crowdsale']
            for indicator in ico_indicators:
                if indicator in domain.lower():
                    threats['fake_ico_indicators'].append(f"Contains '{indicator}' - potential fake ICO")
            
            return threats
            
        except Exception as e:
            logger.error(f"Crypto threat analysis error for {domain}: {str(e)}")
            return {'error': str(e)}
    
    def _analyze_nft_connections(self, domain: str) -> dict:
        """Analyze NFT-related connections."""
        try:
            nft_keywords = ['nft', 'opensea', 'rarible', 'superrare', 'foundation', 'async', 'makersplace']
            nft_indicators = []
            
            for keyword in nft_keywords:
                if keyword in domain.lower():
                    nft_indicators.append(keyword)
            
            return {
                'nft_related': len(nft_indicators) > 0,
                'nft_keywords': nft_indicators,
                'marketplace_similarity': self._check_nft_marketplace_similarity(domain)
            }
            
        except Exception as e:
            logger.error(f"NFT analysis error for {domain}: {str(e)}")
            return {'error': str(e)}
    
    def _check_nft_marketplace_similarity(self, domain: str) -> dict:
        """Check similarity to NFT marketplaces."""
        marketplaces = ['opensea', 'rarible', 'superrare', 'foundation', 'asyncart', 'makersplace']
        similar_marketplaces = []
        
        for marketplace in marketplaces:
            if marketplace in domain.lower() or self._calculate_similarity(domain.lower(), marketplace) > 0.8:
                similar_marketplaces.append(marketplace)
        
        return {
            'similar_marketplaces': similar_marketplaces,
            'potential_phishing': len(similar_marketplaces) > 0
        }
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate string similarity using Levenshtein distance."""
        if len(str1) < len(str2):
            return self._calculate_similarity(str2, str1)
        
        if len(str2) == 0:
            return 0.0
        
        previous_row = list(range(len(str2) + 1))
        for i, c1 in enumerate(str1):
            current_row = [i + 1]
            for j, c2 in enumerate(str2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return 1.0 - (previous_row[-1] / len(str1))

# Initialize global Web3 scanner
web3_scanner = Web3DomainScanner()