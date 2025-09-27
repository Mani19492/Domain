import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import logging
from datetime import datetime, timedelta
import re
import hashlib
from typing import Dict, List, Tuple
import os

logger = logging.getLogger(__name__)

class ThreatPredictor:
    def __init__(self):
        self.phishing_model = None
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self.is_trained = False
        
    def extract_domain_features(self, domain_data: dict) -> np.array:
        """Extract ML features from domain reconnaissance data."""
        features = []
        
        # Domain characteristics
        domain = domain_data.get('domain', '')
        features.append(len(domain))  # Domain length
        features.append(domain.count('.'))  # Subdomain count
        features.append(len(re.findall(r'\d', domain)))  # Number count
        features.append(1 if '-' in domain else 0)  # Has hyphen
        features.append(1 if any(char.isdigit() for char in domain) else 0)  # Has numbers
        
        # WHOIS features
        whois = domain_data.get('whois', {})
        created_date = whois.get('created', 'N/A')
        if created_date != 'N/A' and created_date and str(created_date).strip():
            try:
                # Handle various date formats
                date_str = str(created_date).split('T')[0].strip()
                if len(date_str) >= 10:
                    created = datetime.strptime(date_str[:10], '%Y-%m-%d')
                else:
                    # Try alternative format
                    created = datetime.strptime(date_str, '%Y-%m-%d')
                days_old = (datetime.now() - created).days
                features.append(days_old)
            except (ValueError, TypeError, AttributeError):
                features.append(0)
        else:
            features.append(0)
        
        # SSL features
        ssl = domain_data.get('ssl', {})
        features.append(1 if ssl.get('valid', False) else 0)
        
        # DNS features
        dns_records = domain_data.get('dns', [])
        features.append(len(dns_records))
        features.append(len([r for r in dns_records if r.get('type') == 'A']))
        features.append(len([r for r in dns_records if r.get('type') == 'MX']))
        
        # Threat intelligence features
        vt = domain_data.get('virustotal', {})
        features.append(int(vt.get('malicious', 0)) if str(vt.get('malicious', 0)).isdigit() else 0)
        features.append(int(vt.get('suspicious', 0)) if str(vt.get('suspicious', 0)).isdigit() else 0)
        features.append(int(vt.get('reputation', 0)) if str(vt.get('reputation', 0)).replace('-', '').isdigit() else 0)
        
        # Subdomain features
        subdomains = domain_data.get('subdomains', [])
        features.append(len(subdomains))
        
        # Port features
        open_ports = domain_data.get('open_ports', [])
        features.append(len(open_ports))
        features.append(1 if any(p.get('port') == 22 for p in open_ports) else 0)  # SSH
        features.append(1 if any(p.get('port') == 21 for p in open_ports) else 0)  # FTP
        
        # Security headers
        sec_headers = domain_data.get('security_headers', {})
        missing_headers = sum(1 for v in sec_headers.values() if str(v) == 'Not set')
        features.append(missing_headers)
        
        return np.array(features).reshape(1, -1)
    
    def generate_synthetic_training_data(self) -> Tuple[np.array, np.array]:
        """Generate synthetic training data for the ML model."""
        np.random.seed(42)
        n_samples = 1000
        
        # Generate features for legitimate domains
        legit_features = []
        for _ in range(n_samples // 2):
            features = [
                np.random.randint(5, 20),  # Domain length
                np.random.randint(1, 3),   # Subdomain count
                np.random.randint(0, 3),   # Number count
                np.random.choice([0, 1], p=[0.7, 0.3]),  # Has hyphen
                np.random.choice([0, 1], p=[0.6, 0.4]),  # Has numbers
                np.random.randint(30, 3650),  # Days old
                1,  # SSL valid
                np.random.randint(5, 15),  # DNS records
                np.random.randint(1, 5),   # A records
                np.random.randint(1, 3),   # MX records
                0,  # Malicious
                0,  # Suspicious
                np.random.randint(0, 100), # Reputation
                np.random.randint(0, 50),  # Subdomains
                np.random.randint(2, 8),   # Open ports
                np.random.choice([0, 1], p=[0.8, 0.2]),  # SSH
                np.random.choice([0, 1], p=[0.9, 0.1]),  # FTP
                np.random.randint(0, 3),   # Missing headers
            ]
            legit_features.append(features)
        
        # Generate features for malicious domains
        malicious_features = []
        for _ in range(n_samples // 2):
            features = [
                np.random.randint(8, 30),  # Domain length (longer)
                np.random.randint(2, 5),   # Subdomain count (more)
                np.random.randint(2, 8),   # Number count (more)
                np.random.choice([0, 1], p=[0.3, 0.7]),  # Has hyphen (more likely)
                np.random.choice([0, 1], p=[0.2, 0.8]),  # Has numbers (more likely)
                np.random.randint(0, 90),  # Days old (newer)
                np.random.choice([0, 1], p=[0.6, 0.4]),  # SSL valid (less likely)
                np.random.randint(1, 8),   # DNS records (fewer)
                np.random.randint(0, 3),   # A records
                np.random.randint(0, 2),   # MX records
                np.random.randint(1, 10),  # Malicious (higher)
                np.random.randint(0, 5),   # Suspicious
                np.random.randint(-100, 0), # Reputation (negative)
                np.random.randint(0, 20),  # Subdomains
                np.random.randint(1, 15),  # Open ports
                np.random.choice([0, 1], p=[0.7, 0.3]),  # SSH
                np.random.choice([0, 1], p=[0.8, 0.2]),  # FTP
                np.random.randint(3, 7),   # Missing headers (more)
            ]
            malicious_features.append(features)
        
        X = np.array(legit_features + malicious_features)
        y = np.array([0] * (n_samples // 2) + [1] * (n_samples // 2))
        
        return X, y
    
    def train_models(self):
        """Train the threat prediction models."""
        try:
            # Generate training data
            X, y = self.generate_synthetic_training_data()
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train phishing classifier
            self.phishing_model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.phishing_model.fit(X_train_scaled, y_train)
            
            # Train anomaly detector
            self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
            self.anomaly_detector.fit(X_train_scaled)
            
            # Evaluate
            y_pred = self.phishing_model.predict(X_test_scaled)
            logger.info(f"Model trained successfully. Accuracy: {np.mean(y_pred == y_test):.3f}")
            
            self.is_trained = True
            
            # Save models
            joblib.dump(self.phishing_model, 'models/phishing_model.pkl')
            joblib.dump(self.anomaly_detector, 'models/anomaly_model.pkl')
            joblib.dump(self.scaler, 'models/scaler.pkl')
            
        except Exception as e:
            logger.error(f"Error training models: {str(e)}")
    
    def load_models(self):
        """Load pre-trained models."""
        try:
            if os.path.exists('models/phishing_model.pkl'):
                self.phishing_model = joblib.load('models/phishing_model.pkl')
                self.anomaly_detector = joblib.load('models/anomaly_model.pkl')
                self.scaler = joblib.load('models/scaler.pkl')
                self.is_trained = True
                logger.info("Models loaded successfully")
            else:
                logger.info("No pre-trained models found, training new models...")
                os.makedirs('models', exist_ok=True)
                self.train_models()
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
            self.train_models()
    
    def predict_threat_level(self, domain_data: dict) -> dict:
        """Predict threat level for a domain."""
        if not self.is_trained:
            self.load_models()
        
        try:
            features = self.extract_domain_features(domain_data)
            features_scaled = self.scaler.transform(features)
            
            # Phishing prediction
            phishing_prob = self.phishing_model.predict_proba(features_scaled)[0][1]
            phishing_risk = "High" if phishing_prob > 0.7 else "Medium" if phishing_prob > 0.4 else "Low"
            
            # Anomaly detection
            anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
            is_anomaly = self.anomaly_detector.predict(features_scaled)[0] == -1
            
            # Rule-based checks
            rule_based_flags = self._rule_based_analysis(domain_data)
            
            # Overall risk score
            risk_score = int(phishing_prob * 100)
            if is_anomaly:
                risk_score = min(100, risk_score + 20)
            if rule_based_flags:
                risk_score = min(100, risk_score + len(rule_based_flags) * 10)
            
            return {
                'risk_score': risk_score,
                'phishing_probability': round(phishing_prob * 100, 2),
                'phishing_risk': phishing_risk,
                'is_anomaly': is_anomaly,
                'anomaly_score': round(anomaly_score, 3),
                'rule_based_flags': rule_based_flags,
                'recommendations': self._generate_recommendations(domain_data, risk_score)
            }
            
        except Exception as e:
            logger.error(f"Error predicting threat level: {str(e)}")
            return {
                'risk_score': 0,
                'phishing_probability': 0,
                'phishing_risk': 'Unknown',
                'is_anomaly': False,
                'anomaly_score': 0,
                'rule_based_flags': [],
                'recommendations': ['Unable to analyze threat level']
            }
    
    def _rule_based_analysis(self, domain_data: dict) -> List[str]:
        """Perform rule-based threat analysis."""
        flags = []
        
        domain = domain_data.get('domain', '')
        whois = domain_data.get('whois', {})
        ssl = domain_data.get('ssl', {})
        vt = domain_data.get('virustotal', {})
        
        # Domain age check
        created_date = whois.get('created', 'N/A')
        if created_date != 'N/A':
            try:
                created = datetime.strptime(created_date.split('T')[0], '%Y-%m-%d')
                if (datetime.now() - created).days < 30:
                    flags.append("Domain registered less than 30 days ago")
            except:
                pass
        
        # SSL check
        if not ssl.get('valid', False):
            flags.append("Invalid or missing SSL certificate")
        
        # VirusTotal check
        if vt.get('malicious', 0) > 0:
            flags.append(f"Flagged as malicious by {vt.get('malicious')} security vendors")
        
        # Suspicious domain patterns
        if len(re.findall(r'\d', domain)) > 3:
            flags.append("Domain contains many numbers (potential typosquatting)")
        
        if domain.count('-') > 2:
            flags.append("Domain contains many hyphens (suspicious pattern)")
        
        # Security headers
        sec_headers = domain_data.get('security_headers', {})
        missing_critical = sum(1 for header in ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security'] 
                              if sec_headers.get(header) == 'Not set')
        if missing_critical >= 2:
            flags.append("Missing critical security headers")
        
        return flags
    
    def _generate_recommendations(self, domain_data: dict, risk_score: int) -> List[str]:
        """Generate actionable security recommendations."""
        recommendations = []
        
        ssl = domain_data.get('ssl', {})
        sec_headers = domain_data.get('security_headers', {})
        open_ports = domain_data.get('open_ports', [])
        
        if risk_score > 70:
            recommendations.append("⚠️ HIGH RISK: Avoid interacting with this domain")
            recommendations.append("🔍 Investigate further using additional threat intelligence sources")
        elif risk_score > 40:
            recommendations.append("⚡ MEDIUM RISK: Exercise caution when accessing this domain")
        
        if not ssl.get('valid', False):
            recommendations.append("🔒 Implement valid SSL/TLS certificate")
        
        if sec_headers.get('Content-Security-Policy') == 'Not set':
            recommendations.append("🛡️ Add Content-Security-Policy header to prevent XSS attacks")
        
        if sec_headers.get('Strict-Transport-Security') == 'Not set':
            recommendations.append("🔐 Enable HSTS (HTTP Strict Transport Security)")
        
        # Port-specific recommendations
        risky_ports = [21, 23, 135, 139, 445]
        for port_info in open_ports:
            if port_info.get('port') in risky_ports:
                recommendations.append(f"🚪 Consider closing port {port_info.get('port')} ({port_info.get('service')}) if not needed")
        
        if not recommendations:
            recommendations.append("✅ No immediate security concerns detected")
        
        return recommendations

# Initialize global predictor
threat_predictor = ThreatPredictor()