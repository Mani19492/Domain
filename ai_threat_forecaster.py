import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, classification_report
import joblib
import logging
from datetime import datetime, timedelta
import re
import hashlib
from typing import Dict, List, Tuple, Optional
import os
import shap
import warnings
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

class ThreatForecaster:
    def __init__(self):
        self.forecasting_model = None
        self.evolution_model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.is_trained = False
        self.explainer = None
        
    def extract_temporal_features(self, domain_data: dict, historical_data: List[dict] = None) -> np.array:
        """Extract time-series features for threat forecasting."""
        features = []
        
        # Current domain characteristics
        domain = domain_data.get('domain', '')
        features.extend([
            len(domain),  # Domain length
            domain.count('.'),  # Subdomain levels
            len(re.findall(r'\d', domain)),  # Number count
            1 if '-' in domain else 0,  # Has hyphen
            len(re.findall(r'[aeiou]', domain.lower())),  # Vowel count
        ])
        
        # DNS change frequency (if historical data available)
        if historical_data:
            dns_changes = sum(1 for h in historical_data if h.get('dns_changed', False))
            features.append(dns_changes / max(len(historical_data), 1))
        else:
            features.append(0)
        
        # Threat score volatility
        if historical_data:
            scores = [h.get('threat_score', 0) for h in historical_data]
            volatility = np.std(scores) if scores else 0
            features.append(volatility)
        else:
            features.append(0)
        
        # SSL certificate age and expiry prediction
        ssl = domain_data.get('ssl', {})
        if ssl.get('expiry') and ssl.get('expiry') != 'N/A':
            try:
                expiry_date = datetime.strptime(ssl['expiry'].split()[0], '%b')
                days_to_expiry = (expiry_date - datetime.now()).days
                features.append(max(0, days_to_expiry))
            except:
                features.append(365)  # Default
        else:
            features.append(365)
        
        # Subdomain growth rate
        current_subdomains = len(domain_data.get('subdomains', []))
        if historical_data:
            past_subdomains = [len(h.get('subdomains', [])) for h in historical_data]
            growth_rate = (current_subdomains - np.mean(past_subdomains)) / max(np.mean(past_subdomains), 1)
            features.append(growth_rate)
        else:
            features.append(0)
        
        # Threat intelligence trends
        vt = domain_data.get('virustotal', {})
        features.extend([
            int(vt.get('malicious', 0)),
            int(vt.get('suspicious', 0)),
            int(vt.get('reputation', 0)) if str(vt.get('reputation', 0)).replace('-', '').isdigit() else 0
        ])
        
        # Port exposure risk
        open_ports = domain_data.get('open_ports', [])
        risky_ports = [21, 22, 23, 135, 139, 445, 1433, 3389]
        risky_port_count = sum(1 for port in open_ports if port.get('port') in risky_ports)
        features.append(risky_port_count)
        
        # Security posture degradation indicators
        sec_headers = domain_data.get('security_headers', {})
        missing_headers = sum(1 for v in sec_headers.values() if str(v) == 'Not set')
        features.append(missing_headers)
        
        # Web3/Crypto indicators
        web3_keywords = ['crypto', 'bitcoin', 'ethereum', 'nft', 'defi', 'wallet']
        crypto_score = sum(1 for keyword in web3_keywords if keyword in domain.lower())
        features.append(crypto_score)
        
        return np.array(features).reshape(1, -1)
    
    def generate_forecasting_training_data(self) -> Tuple[np.array, np.array]:
        """Generate synthetic training data for threat forecasting."""
        np.random.seed(42)
        n_samples = 2000
        
        X = []
        y = []
        
        for _ in range(n_samples):
            # Generate features
            domain_length = np.random.randint(5, 30)
            subdomain_levels = np.random.randint(1, 5)
            number_count = np.random.randint(0, 8)
            has_hyphen = np.random.choice([0, 1])
            vowel_count = np.random.randint(2, 10)
            dns_change_freq = np.random.exponential(0.1)
            threat_volatility = np.random.exponential(5)
            days_to_ssl_expiry = np.random.randint(0, 730)
            subdomain_growth = np.random.normal(0, 0.5)
            malicious_count = np.random.poisson(0.5)
            suspicious_count = np.random.poisson(0.3)
            reputation = np.random.normal(0, 50)
            risky_ports = np.random.poisson(0.2)
            missing_headers = np.random.randint(0, 7)
            crypto_score = np.random.poisson(0.1)
            
            features = [
                domain_length, subdomain_levels, number_count, has_hyphen, vowel_count,
                dns_change_freq, threat_volatility, days_to_ssl_expiry, subdomain_growth,
                malicious_count, suspicious_count, reputation, risky_ports, missing_headers, crypto_score
            ]
            
            # Generate target (future threat probability)
            threat_prob = (
                0.1 * (domain_length > 20) +
                0.15 * (dns_change_freq > 0.2) +
                0.2 * (threat_volatility > 10) +
                0.15 * (days_to_ssl_expiry < 30) +
                0.1 * (subdomain_growth > 1) +
                0.2 * (malicious_count > 0) +
                0.1 * (risky_ports > 0) +
                0.05 * missing_headers +
                0.1 * (crypto_score > 2)
            )
            
            # Add noise
            threat_prob += np.random.normal(0, 0.1)
            threat_prob = np.clip(threat_prob, 0, 1)
            
            X.append(features)
            y.append(threat_prob)
        
        return np.array(X), np.array(y)
    
    def train_forecasting_models(self):
        """Train threat forecasting models."""
        try:
            # Generate training data
            X, y = self.generate_forecasting_training_data()
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train forecasting model
            self.forecasting_model = GradientBoostingClassifier(n_estimators=100, random_state=42)
            y_train_binary = (y_train > 0.5).astype(int)
            self.forecasting_model.fit(X_train_scaled, y_train_binary)
            
            # Train evolution model for threat pattern evolution
            self.evolution_model = RandomForestRegressor(n_estimators=100, random_state=42)
            self.evolution_model.fit(X_train_scaled, y_train)
            
            # Create SHAP explainer for interpretability
            self.explainer = shap.TreeExplainer(self.forecasting_model)
            
            # Evaluate
            y_pred = self.forecasting_model.predict(X_test_scaled)
            y_test_binary = (y_test > 0.5).astype(int)
            accuracy = np.mean(y_pred == y_test_binary)
            logger.info(f"Forecasting model trained successfully. Accuracy: {accuracy:.3f}")
            
            self.is_trained = True
            
            # Save models
            os.makedirs('models', exist_ok=True)
            joblib.dump(self.forecasting_model, 'models/forecasting_model.pkl')
            joblib.dump(self.evolution_model, 'models/evolution_model.pkl')
            joblib.dump(self.scaler, 'models/forecasting_scaler.pkl')
            joblib.dump(self.explainer, 'models/shap_explainer.pkl')
            
        except Exception as e:
            logger.error(f"Error training forecasting models: {str(e)}")
    
    def load_forecasting_models(self):
        """Load pre-trained forecasting models."""
        try:
            if os.path.exists('models/forecasting_model.pkl'):
                self.forecasting_model = joblib.load('models/forecasting_model.pkl')
                self.evolution_model = joblib.load('models/evolution_model.pkl')
                self.scaler = joblib.load('models/forecasting_scaler.pkl')
                self.explainer = joblib.load('models/shap_explainer.pkl')
                self.is_trained = True
                logger.info("Forecasting models loaded successfully")
            else:
                logger.info("No pre-trained forecasting models found, training new models...")
                self.train_forecasting_models()
        except Exception as e:
            logger.error(f"Error loading forecasting models: {str(e)}")
            self.train_forecasting_models()
    
    def forecast_threats(self, domain_data: dict, historical_data: List[dict] = None) -> dict:
        """Generate threat forecasts for a domain."""
        if not self.is_trained:
            self.load_forecasting_models()
        
        try:
            features = self.extract_temporal_features(domain_data, historical_data)
            features_scaled = self.scaler.transform(features)
            
            # Threat probability forecast
            threat_prob = self.forecasting_model.predict_proba(features_scaled)[0][1]
            evolution_score = self.evolution_model.predict(features_scaled)[0]
            
            # Generate time-based predictions
            forecasts = {}
            time_horizons = [7, 30, 90, 180, 365]  # days
            
            for days in time_horizons:
                # Adjust prediction based on time horizon
                time_factor = 1 + (days / 365) * 0.3  # Increase uncertainty over time
                adjusted_prob = min(1.0, threat_prob * time_factor)
                
                forecasts[f"{days}_days"] = {
                    'probability': round(adjusted_prob * 100, 2),
                    'confidence': max(0.5, 1 - (days / 365) * 0.4),
                    'risk_level': self._get_risk_level(adjusted_prob)
                }
            
            # SHAP explanations for interpretability
            shap_values = self.explainer.shap_values(features_scaled)
            feature_names = [
                'domain_length', 'subdomain_levels', 'number_count', 'has_hyphen', 'vowel_count',
                'dns_change_freq', 'threat_volatility', 'ssl_expiry_days', 'subdomain_growth',
                'malicious_count', 'suspicious_count', 'reputation', 'risky_ports', 'missing_headers', 'crypto_score'
            ]
            
            explanations = []
            if len(shap_values) > 0:
                for i, (feature, value) in enumerate(zip(feature_names, shap_values[0])):
                    if abs(value) > 0.01:  # Only include significant features
                        explanations.append({
                            'feature': feature.replace('_', ' ').title(),
                            'impact': round(value, 3),
                            'direction': 'increases' if value > 0 else 'decreases'
                        })
            
            # Generate specific predictions
            predictions = self._generate_specific_predictions(domain_data, threat_prob, evolution_score)
            
            return {
                'overall_threat_probability': round(threat_prob * 100, 2),
                'evolution_score': round(evolution_score * 100, 2),
                'forecasts': forecasts,
                'predictions': predictions,
                'explanations': sorted(explanations, key=lambda x: abs(x['impact']), reverse=True)[:5],
                'recommendations': self._generate_forecasting_recommendations(domain_data, threat_prob)
            }
            
        except Exception as e:
            logger.error(f"Error generating threat forecast: {str(e)}")
            return {
                'overall_threat_probability': 0,
                'evolution_score': 0,
                'forecasts': {},
                'predictions': [],
                'explanations': [],
                'recommendations': ['Unable to generate threat forecast']
            }
    
    def _get_risk_level(self, probability: float) -> str:
        """Convert probability to risk level."""
        if probability > 0.7:
            return 'Critical'
        elif probability > 0.5:
            return 'High'
        elif probability > 0.3:
            return 'Medium'
        else:
            return 'Low'
    
    def _generate_specific_predictions(self, domain_data: dict, threat_prob: float, evolution_score: float) -> List[dict]:
        """Generate specific threat predictions."""
        predictions = []
        
        # SSL expiry prediction
        ssl = domain_data.get('ssl', {})
        if ssl.get('expiry') and ssl.get('expiry') != 'N/A':
            predictions.append({
                'type': 'SSL Certificate',
                'prediction': 'SSL certificate may expire soon, increasing vulnerability risk',
                'timeline': '30-90 days',
                'probability': min(100, threat_prob * 80 + 20)
            })
        
        # Phishing evolution prediction
        if threat_prob > 0.4:
            predictions.append({
                'type': 'Phishing Evolution',
                'prediction': 'Domain characteristics suggest potential for phishing campaign development',
                'timeline': '7-30 days',
                'probability': threat_prob * 100
            })
        
        # Subdomain abuse prediction
        subdomains = domain_data.get('subdomains', [])
        if len(subdomains) > 10:
            predictions.append({
                'type': 'Subdomain Abuse',
                'prediction': 'High subdomain count increases risk of subdomain takeover attacks',
                'timeline': '30-180 days',
                'probability': min(100, len(subdomains) * 2 + threat_prob * 50)
            })
        
        # DNS hijacking prediction
        if evolution_score > 0.6:
            predictions.append({
                'type': 'DNS Manipulation',
                'prediction': 'Domain shows patterns consistent with future DNS manipulation attempts',
                'timeline': '90-365 days',
                'probability': evolution_score * 100
            })
        
        return predictions
    
    def _generate_forecasting_recommendations(self, domain_data: dict, threat_prob: float) -> List[str]:
        """Generate actionable recommendations based on forecast."""
        recommendations = []
        
        if threat_prob > 0.7:
            recommendations.append("🚨 CRITICAL: Implement immediate monitoring and security controls")
            recommendations.append("🔒 Consider domain parking or takedown procedures")
        elif threat_prob > 0.5:
            recommendations.append("⚠️ HIGH RISK: Increase monitoring frequency to daily")
            recommendations.append("🛡️ Implement additional security headers and controls")
        
        # SSL-specific recommendations
        ssl = domain_data.get('ssl', {})
        if not ssl.get('valid', False):
            recommendations.append("🔐 Implement valid SSL certificate immediately")
        
        # DNS monitoring
        recommendations.append("📡 Set up DNS change monitoring and alerting")
        
        # Subdomain security
        subdomains = domain_data.get('subdomains', [])
        if len(subdomains) > 5:
            recommendations.append("🌐 Audit and secure all discovered subdomains")
        
        if not recommendations:
            recommendations.append("✅ Continue regular monitoring and maintain current security posture")
        
        return recommendations

# Initialize global forecaster
threat_forecaster = ThreatForecaster()