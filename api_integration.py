import json
import logging
from typing import Dict, List, Any, Optional
from flask import Flask, request, jsonify, Response
from flask_restful import Api, Resource
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta
import hashlib
import hmac
import requests
from functools import wraps
import sqlite3
import threading
import time

logger = logging.getLogger(__name__)

class APIIntegrationManager:
    def __init__(self, app: Flask):
        self.app = app
        self.api = Api(app)
        
        # Enable CORS for all domains
        CORS(app, resources={r"/api/*": {"origins": "*"}})
        
        # Rate limiting
        self.limiter = Limiter(
            app,
            key_func=get_remote_address,
            default_limits=["200 per day", "50 per hour"]
        )
        
        # API configuration
        self.api_config = {
            'version': '2.0',
            'base_url': '/api/v2',
            'authentication_required': True,
            'rate_limiting': True,
            'webhook_support': True,
            'real_time_updates': True
        }
        
        # External integrations
        self.external_integrations = {
            'splunk': {
                'enabled': False,
                'endpoint': None,
                'token': None,
                'index': 'security'
            },
            'elasticsearch': {
                'enabled': False,
                'endpoint': None,
                'index': 'domain-recon'
            },
            'slack': {
                'enabled': False,
                'webhook_url': None,
                'channel': '#security'
            },
            'teams': {
                'enabled': False,
                'webhook_url': None
            },
            'jira': {
                'enabled': False,
                'endpoint': None,
                'username': None,
                'token': None,
                'project_key': None
            },
            'servicenow': {
                'enabled': False,
                'endpoint': None,
                'username': None,
                'password': None,
                'table': 'incident'
            }
        }
        
        # Initialize database for API management
        self.init_api_database()
        
        # Register API endpoints
        self.register_endpoints()
        
        # Start background services
        self.start_background_services()
    
    def init_api_database(self):
        """Initialize API management database."""
        try:
            conn = sqlite3.connect('api_management.db')
            cursor = conn.cursor()
            
            # API keys table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT UNIQUE NOT NULL,
                    key_hash TEXT NOT NULL,
                    name TEXT NOT NULL,
                    permissions TEXT NOT NULL,
                    rate_limit INTEGER DEFAULT 1000,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    last_used TEXT,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # API usage logs
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_usage_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT,
                    endpoint TEXT NOT NULL,
                    method TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    response_code INTEGER,
                    response_time REAL,
                    timestamp TEXT NOT NULL
                )
            ''')
            
            # Webhook subscriptions
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS webhook_subscriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT NOT NULL,
                    endpoint_url TEXT NOT NULL,
                    events TEXT NOT NULL,
                    secret TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_triggered TEXT
                )
            ''')
            
            # Integration configurations
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS integration_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    integration_name TEXT UNIQUE NOT NULL,
                    config_data TEXT NOT NULL,
                    is_enabled BOOLEAN DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error initializing API database: {str(e)}")
    
    def register_endpoints(self):
        """Register all API endpoints."""
        # Domain analysis endpoints
        self.api.add_resource(DomainAnalysisAPI, f"{self.api_config['base_url']}/analyze")
        self.api.add_resource(BulkAnalysisAPI, f"{self.api_config['base_url']}/analyze/bulk")
        self.api.add_resource(ScanStatusAPI, f"{self.api_config['base_url']}/scan/<string:scan_id>/status")
        
        # Monitoring endpoints
        self.api.add_resource(MonitoringAPI, f"{self.api_config['base_url']}/monitor")
        self.api.add_resource(AlertsAPI, f"{self.api_config['base_url']}/alerts")
        
        # Reports endpoints
        self.api.add_resource(ReportsAPI, f"{self.api_config['base_url']}/reports")
        self.api.add_resource(ReportExportAPI, f"{self.api_config['base_url']}/reports/<string:report_id>/export")
        
        # Threat intelligence endpoints
        self.api.add_resource(ThreatIntelAPI, f"{self.api_config['base_url']}/threat-intel")
        self.api.add_resource(IOCFeedAPI, f"{self.api_config['base_url']}/ioc-feed")
        
        # Integration endpoints
        self.api.add_resource(IntegrationsAPI, f"{self.api_config['base_url']}/integrations")
        self.api.add_resource(WebhooksAPI, f"{self.api_config['base_url']}/webhooks")
        
        # API management endpoints
        self.api.add_resource(APIKeysAPI, f"{self.api_config['base_url']}/keys")
        self.api.add_resource(APIUsageAPI, f"{self.api_config['base_url']}/usage")
        
        logger.info("API endpoints registered successfully")
    
    def authenticate_api_key(self, f):
        """Decorator for API key authentication."""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not self.api_config['authentication_required']:
                return f(*args, **kwargs)
            
            api_key = request.headers.get('X-API-Key')
            if not api_key:
                return {'error': 'API key required'}, 401
            
            # Validate API key
            key_info = self.validate_api_key(api_key)
            if not key_info:
                return {'error': 'Invalid API key'}, 401
            
            # Check rate limits
            if not self.check_rate_limit(key_info['key_id']):
                return {'error': 'Rate limit exceeded'}, 429
            
            # Log API usage
            self.log_api_usage(key_info['key_id'], request)
            
            # Add key info to request context
            request.api_key_info = key_info
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    def validate_api_key(self, api_key: str) -> Optional[dict]:
        """Validate API key and return key information."""
        try:
            # Hash the provided key
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            conn = sqlite3.connect('api_management.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT key_id, name, permissions, rate_limit, expires_at, is_active
                FROM api_keys 
                WHERE key_hash = ? AND is_active = 1
            ''', (key_hash,))
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return None
            
            # Check expiration
            if row[4]:  # expires_at
                expires_at = datetime.fromisoformat(row[4])
                if datetime.now() > expires_at:
                    return None
            
            return {
                'key_id': row[0],
                'name': row[1],
                'permissions': json.loads(row[2]),
                'rate_limit': row[3],
                'is_active': bool(row[5])
            }
            
        except Exception as e:
            logger.error(f"Error validating API key: {str(e)}")
            return None
    
    def check_rate_limit(self, key_id: str) -> bool:
        """Check if API key is within rate limits."""
        try:
            # This is a simplified rate limiting implementation
            # In production, you'd use Redis or similar for distributed rate limiting
            
            conn = sqlite3.connect('api_management.db')
            cursor = conn.cursor()
            
            # Count requests in the last hour
            one_hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
            cursor.execute('''
                SELECT COUNT(*) FROM api_usage_logs 
                WHERE key_id = ? AND timestamp > ?
            ''', (key_id, one_hour_ago))
            
            request_count = cursor.fetchone()[0]
            
            # Get rate limit for this key
            cursor.execute('SELECT rate_limit FROM api_keys WHERE key_id = ?', (key_id,))
            rate_limit = cursor.fetchone()[0]
            
            conn.close()
            
            return request_count < rate_limit
            
        except Exception as e:
            logger.error(f"Error checking rate limit: {str(e)}")
            return True  # Allow request if check fails
    
    def log_api_usage(self, key_id: str, request_obj):
        """Log API usage for analytics and monitoring."""
        try:
            conn = sqlite3.connect('api_management.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO api_usage_logs 
                (key_id, endpoint, method, ip_address, user_agent, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                key_id,
                request_obj.endpoint,
                request_obj.method,
                request_obj.remote_addr,
                request_obj.user_agent.string if request_obj.user_agent else None,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error logging API usage: {str(e)}")
    
    def send_webhook(self, event_type: str, data: dict):
        """Send webhook notifications to subscribed endpoints."""
        try:
            conn = sqlite3.connect('api_management.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT endpoint_url, secret FROM webhook_subscriptions 
                WHERE events LIKE ? AND is_active = 1
            ''', (f'%{event_type}%',))
            
            subscriptions = cursor.fetchall()
            conn.close()
            
            for endpoint_url, secret in subscriptions:
                self.send_webhook_request(endpoint_url, event_type, data, secret)
                
        except Exception as e:
            logger.error(f"Error sending webhooks: {str(e)}")
    
    def send_webhook_request(self, url: str, event_type: str, data: dict, secret: str = None):
        """Send individual webhook request."""
        try:
            payload = {
                'event_type': event_type,
                'timestamp': datetime.now().isoformat(),
                'data': data
            }
            
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'DomainRecon-Webhook/2.0'
            }
            
            # Add signature if secret is provided
            if secret:
                signature = hmac.new(
                    secret.encode(),
                    json.dumps(payload).encode(),
                    hashlib.sha256
                ).hexdigest()
                headers['X-Signature-SHA256'] = f'sha256={signature}'
            
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Webhook sent successfully to {url}")
            else:
                logger.warning(f"Webhook failed for {url}: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error sending webhook to {url}: {str(e)}")
    
    def integrate_with_splunk(self, data: dict):
        """Send data to Splunk."""
        try:
            if not self.external_integrations['splunk']['enabled']:
                return
            
            splunk_config = self.external_integrations['splunk']
            
            headers = {
                'Authorization': f"Splunk {splunk_config['token']}",
                'Content-Type': 'application/json'
            }
            
            splunk_event = {
                'index': splunk_config['index'],
                'sourcetype': 'domain_recon',
                'event': data
            }
            
            response = requests.post(
                f"{splunk_config['endpoint']}/services/collector/event",
                json=splunk_event,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Data sent to Splunk successfully")
            else:
                logger.warning(f"Splunk integration failed: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error integrating with Splunk: {str(e)}")
    
    def integrate_with_elasticsearch(self, data: dict):
        """Send data to Elasticsearch."""
        try:
            if not self.external_integrations['elasticsearch']['enabled']:
                return
            
            es_config = self.external_integrations['elasticsearch']
            
            headers = {'Content-Type': 'application/json'}
            
            # Create document with timestamp
            doc = {
                '@timestamp': datetime.now().isoformat(),
                **data
            }
            
            response = requests.post(
                f"{es_config['endpoint']}/{es_config['index']}/_doc",
                json=doc,
                headers=headers,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                logger.info("Data sent to Elasticsearch successfully")
            else:
                logger.warning(f"Elasticsearch integration failed: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error integrating with Elasticsearch: {str(e)}")
    
    def send_slack_notification(self, message: str, channel: str = None):
        """Send notification to Slack."""
        try:
            if not self.external_integrations['slack']['enabled']:
                return
            
            slack_config = self.external_integrations['slack']
            webhook_url = slack_config['webhook_url']
            
            payload = {
                'text': message,
                'channel': channel or slack_config['channel'],
                'username': 'Domain Recon Bot',
                'icon_emoji': ':shield:'
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                logger.info("Slack notification sent successfully")
            else:
                logger.warning(f"Slack notification failed: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error sending Slack notification: {str(e)}")
    
    def create_jira_ticket(self, summary: str, description: str, issue_type: str = 'Bug'):
        """Create JIRA ticket for security issues."""
        try:
            if not self.external_integrations['jira']['enabled']:
                return
            
            jira_config = self.external_integrations['jira']
            
            auth = (jira_config['username'], jira_config['token'])
            headers = {'Content-Type': 'application/json'}
            
            issue_data = {
                'fields': {
                    'project': {'key': jira_config['project_key']},
                    'summary': summary,
                    'description': description,
                    'issuetype': {'name': issue_type},
                    'priority': {'name': 'High'},
                    'labels': ['security', 'domain-recon']
                }
            }
            
            response = requests.post(
                f"{jira_config['endpoint']}/rest/api/2/issue",
                json=issue_data,
                headers=headers,
                auth=auth,
                timeout=10
            )
            
            if response.status_code == 201:
                issue_key = response.json()['key']
                logger.info(f"JIRA ticket created: {issue_key}")
                return issue_key
            else:
                logger.warning(f"JIRA ticket creation failed: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error creating JIRA ticket: {str(e)}")
        
        return None
    
    def start_background_services(self):
        """Start background services for API management."""
        def cleanup_expired_keys():
            """Clean up expired API keys."""
            while True:
                try:
                    conn = sqlite3.connect('api_management.db')
                    cursor = conn.cursor()
                    
                    # Deactivate expired keys
                    cursor.execute('''
                        UPDATE api_keys 
                        SET is_active = 0 
                        WHERE expires_at < ? AND expires_at IS NOT NULL
                    ''', (datetime.now().isoformat(),))
                    
                    # Clean up old usage logs (keep last 30 days)
                    thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
                    cursor.execute('''
                        DELETE FROM api_usage_logs 
                        WHERE timestamp < ?
                    ''', (thirty_days_ago,))
                    
                    conn.commit()
                    conn.close()
                    
                    time.sleep(3600)  # Run every hour
                    
                except Exception as e:
                    logger.error(f"Error in cleanup service: {str(e)}")
                    time.sleep(3600)
        
        # Start cleanup service in background thread
        cleanup_thread = threading.Thread(target=cleanup_expired_keys, daemon=True)
        cleanup_thread.start()
        
        logger.info("Background services started")

# API Resource Classes
class DomainAnalysisAPI(Resource):
    def __init__(self):
        self.api_manager = api_integration_manager

    def post(self):
        """Analyze a single domain."""
        try:
            data = request.get_json()
            domain = data.get('domain')
            
            if not domain:
                return {'error': 'Domain parameter required'}, 400
            
            # Import here to avoid circular imports
            from recon import get_recon_data
            from ai_threat_predictor import threat_predictor
            
            # Perform analysis
            recon_data = get_recon_data(domain)
            threat_analysis = threat_predictor.predict_threat_level(recon_data)
            
            result = {
                'domain': domain,
                'timestamp': datetime.now().isoformat(),
                'reconnaissance': recon_data,
                'threat_analysis': threat_analysis
            }
            
            # Send webhook notification
            self.api_manager.send_webhook('domain_analyzed', result)
            
            # Integrate with external systems
            self.api_manager.integrate_with_splunk(result)
            self.api_manager.integrate_with_elasticsearch(result)
            
            return result, 200
            
        except Exception as e:
            logger.error(f"Error in domain analysis API: {str(e)}")
            return {'error': 'Internal server error'}, 500

class BulkAnalysisAPI(Resource):
    def __init__(self):
        self.api_manager = api_integration_manager

    def post(self):
        """Analyze multiple domains."""
        try:
            data = request.get_json()
            domains = data.get('domains', [])
            
            if not domains or len(domains) > 100:  # Limit bulk requests
                return {'error': 'Provide 1-100 domains'}, 400
            
            results = []
            for domain in domains:
                try:
                    # Import here to avoid circular imports
                    from recon import get_recon_data
                    from ai_threat_predictor import threat_predictor
                    
                    recon_data = get_recon_data(domain)
                    threat_analysis = threat_predictor.predict_threat_level(recon_data)
                    
                    result = {
                        'domain': domain,
                        'timestamp': datetime.now().isoformat(),
                        'reconnaissance': recon_data,
                        'threat_analysis': threat_analysis
                    }
                    
                    results.append(result)
                    
                except Exception as e:
                    results.append({
                        'domain': domain,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
            
            # Send webhook notification
            self.api_manager.send_webhook('bulk_analysis_complete', {
                'total_domains': len(domains),
                'successful': len([r for r in results if 'error' not in r]),
                'failed': len([r for r in results if 'error' in r])
            })
            
            return {'results': results}, 200
            
        except Exception as e:
            logger.error(f"Error in bulk analysis API: {str(e)}")
            return {'error': 'Internal server error'}, 500

class MonitoringAPI(Resource):
    def __init__(self):
        self.api_manager = api_integration_manager

    def post(self):
        """Add domain to monitoring."""
        try:
            data = request.get_json()
            domain = data.get('domain')
            frequency = data.get('frequency', 3600)  # Default 1 hour
            
            if not domain:
                return {'error': 'Domain parameter required'}, 400
            
            # Import here to avoid circular imports
            from real_time_monitor import real_time_monitor
            
            job_id = real_time_monitor.add_domain_monitor(
                domain=domain,
                user_id=request.api_key_info['key_id'],
                frequency=frequency
            )
            
            return {
                'job_id': job_id,
                'domain': domain,
                'frequency': frequency,
                'status': 'monitoring_started'
            }, 201
            
        except Exception as e:
            logger.error(f"Error in monitoring API: {str(e)}")
            return {'error': 'Internal server error'}, 500
    
    def get(self):
        """Get monitored domains."""
        try:
            # Import here to avoid circular imports
            from real_time_monitor import real_time_monitor
            
            monitored_domains = real_time_monitor.get_monitored_domains()
            
            return {'monitored_domains': monitored_domains}, 200
            
        except Exception as e:
            logger.error(f"Error getting monitored domains: {str(e)}")
            return {'error': 'Internal server error'}, 500

class ThreatIntelAPI(Resource):
    def __init__(self):
        self.api_manager = api_integration_manager

    def get(self):
        """Get threat intelligence data."""
        try:
            domain = request.args.get('domain')
            
            if not domain:
                return {'error': 'Domain parameter required'}, 400
            
            # Import here to avoid circular imports
            from ai_threat_predictor import threat_predictor
            from recon import get_recon_data
            
            recon_data = get_recon_data(domain)
            threat_intel = threat_predictor.predict_threat_level(recon_data)
            
            return {
                'domain': domain,
                'threat_intelligence': threat_intel,
                'timestamp': datetime.now().isoformat()
            }, 200
            
        except Exception as e:
            logger.error(f"Error in threat intel API: {str(e)}")
            return {'error': 'Internal server error'}, 500

class IntegrationsAPI(Resource):
    def __init__(self):
        self.api_manager = api_integration_manager

    def get(self):
        """Get available integrations."""
        try:
            integrations = {}
            for name, config in self.api_manager.external_integrations.items():
                integrations[name] = {
                    'enabled': config['enabled'],
                    'description': f'{name.title()} integration for security data export'
                }
            
            return {'integrations': integrations}, 200
            
        except Exception as e:
            logger.error(f"Error getting integrations: {str(e)}")
            return {'error': 'Internal server error'}, 500
    
    def post(self):
        """Configure integration."""
        try:
            data = request.get_json()
            integration_name = data.get('integration')
            config = data.get('config', {})
            
            if integration_name not in self.api_manager.external_integrations:
                return {'error': 'Invalid integration name'}, 400
            
            # Update integration configuration
            self.api_manager.external_integrations[integration_name].update(config)
            
            # Save to database
            conn = sqlite3.connect('api_management.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO integration_configs 
                (integration_name, config_data, is_enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                integration_name,
                json.dumps(config),
                config.get('enabled', False),
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            return {
                'integration': integration_name,
                'status': 'configured',
                'enabled': config.get('enabled', False)
            }, 200
            
        except Exception as e:
            logger.error(f"Error configuring integration: {str(e)}")
            return {'error': 'Internal server error'}, 500

class WebhooksAPI(Resource):
    def __init__(self):
        self.api_manager = api_integration_manager

    def post(self):
        """Subscribe to webhook events."""
        try:
            data = request.get_json()
            endpoint_url = data.get('endpoint_url')
            events = data.get('events', [])
            secret = data.get('secret')
            
            if not endpoint_url or not events:
                return {'error': 'endpoint_url and events required'}, 400
            
            conn = sqlite3.connect('api_management.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO webhook_subscriptions 
                (key_id, endpoint_url, events, secret, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                request.api_key_info['key_id'],
                endpoint_url,
                json.dumps(events),
                secret,
                datetime.now().isoformat()
            ))
            
            subscription_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return {
                'subscription_id': subscription_id,
                'endpoint_url': endpoint_url,
                'events': events,
                'status': 'subscribed'
            }, 201
            
        except Exception as e:
            logger.error(f"Error creating webhook subscription: {str(e)}")
            return {'error': 'Internal server error'}, 500

class APIKeysAPI(Resource):
    def __init__(self):
        self.api_manager = api_integration_manager
    
    def post(self):
        """Create new API key."""
        try:
            data = request.get_json()
            name = data.get('name')
            permissions = data.get('permissions', ['read'])
            rate_limit = data.get('rate_limit', 1000)
            expires_days = data.get('expires_days')
            
            if not name:
                return {'error': 'Name required'}, 400
            
            # Generate API key
            import secrets
            api_key = secrets.token_urlsafe(32)
            key_id = hashlib.md5(api_key.encode()).hexdigest()[:16]
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            # Calculate expiration
            expires_at = None
            if expires_days:
                expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat()
            
            conn = sqlite3.connect('api_management.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO api_keys 
                (key_id, key_hash, name, permissions, rate_limit, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                key_id,
                key_hash,
                name,
                json.dumps(permissions),
                rate_limit,
                datetime.now().isoformat(),
                expires_at
            ))
            
            conn.commit()
            conn.close()
            
            return {
                'api_key': api_key,
                'key_id': key_id,
                'name': name,
                'permissions': permissions,
                'rate_limit': rate_limit,
                'expires_at': expires_at
            }, 201
            
        except Exception as e:
            logger.error(f"Error creating API key: {str(e)}")
            return {'error': 'Internal server error'}, 500

class APIUsageAPI(Resource):
    def __init__(self):
        self.api_manager = api_integration_manager

    def get(self):
        """Get API usage statistics."""
        try:
            key_id = request.api_key_info['key_id']
            
            conn = sqlite3.connect('api_management.db')
            cursor = conn.cursor()
            
            # Get usage stats for last 30 days
            thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
            
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_requests,
                    COUNT(DISTINCT DATE(timestamp)) as active_days,
                    AVG(response_time) as avg_response_time
                FROM api_usage_logs 
                WHERE key_id = ? AND timestamp > ?
            ''', (key_id, thirty_days_ago))
            
            stats = cursor.fetchone()
            
            # Get requests by endpoint
            cursor.execute('''
                SELECT endpoint, COUNT(*) as count
                FROM api_usage_logs 
                WHERE key_id = ? AND timestamp > ?
                GROUP BY endpoint
                ORDER BY count DESC
            ''', (key_id, thirty_days_ago))
            
            endpoints = [{'endpoint': row[0], 'count': row[1]} for row in cursor.fetchall()]
            
            conn.close()
            
            return {
                'key_id': key_id,
                'period': '30_days',
                'total_requests': stats[0],
                'active_days': stats[1],
                'avg_response_time': round(stats[2] or 0, 3),
                'endpoints': endpoints
            }, 200
            
        except Exception as e:
            logger.error(f"Error getting API usage: {str(e)}")
            return {'error': 'Internal server error'}, 500

class ScanStatusAPI(Resource):
    def __init__(self):
        self.api_manager = api_integration_manager

    def get(self, scan_id):
        """Get scan status."""
        try:
            # This would integrate with your scan tracking system
            # For now, return a mock response
            return {
                'scan_id': scan_id,
                'status': 'completed',
                'progress': 100,
                'started_at': datetime.now().isoformat(),
                'completed_at': datetime.now().isoformat()
            }, 200
            
        except Exception as e:
            logger.error(f"Error getting scan status: {str(e)}")
            return {'error': 'Internal server error'}, 500

class ReportsAPI(Resource):
    def __init__(self):
        self.api_manager = api_integration_manager

    def get(self):
        """Get available reports."""
        try:
            # This would integrate with your report storage system
            return {'reports': []}, 200
            
        except Exception as e:
            logger.error(f"Error getting reports: {str(e)}")
            return {'error': 'Internal server error'}, 500

class ReportExportAPI(Resource):
    def __init__(self):
        self.api_manager = api_integration_manager

    def get(self, report_id):
        """Export report in specified format."""
        try:
            format_type = request.args.get('format', 'json')
            
            # This would integrate with your report generation system
            return {
                'report_id': report_id,
                'format': format_type,
                'download_url': f'/api/v2/reports/{report_id}/download'
            }, 200
            
        except Exception as e:
            logger.error(f"Error exporting report: {str(e)}")
            return {'error': 'Internal server error'}, 500

class AlertsAPI(Resource):
    def __init__(self):
        self.api_manager = api_integration_manager

    def get(self):
        """Get alerts."""
        try:
            # Import here to avoid circular imports
            from real_time_monitor import real_time_monitor
            
            dashboard_data = real_time_monitor.get_dashboard_data()
            alerts = dashboard_data.get('recent_alerts', [])
            
            return {'alerts': alerts}, 200
            
        except Exception as e:
            logger.error(f"Error getting alerts: {str(e)}")
            return {'error': 'Internal server error'}, 500

class IOCFeedAPI(Resource):
    def __init__(self):
        self.api_manager = api_integration_manager

    def get(self):
        """Get Indicators of Compromise feed."""
        try:
            # This would integrate with threat intelligence sources
            iocs = {
                'domains': [],
                'ips': [],
                'urls': [],
                'hashes': [],
                'last_updated': datetime.now().isoformat()
            }
            
            return iocs, 200
            
        except Exception as e:
            logger.error(f"Error getting IOC feed: {str(e)}")
            return {'error': 'Internal server error'}, 500

# Initialize global API integration manager
api_integration_manager = None

def initialize_api_integration(app: Flask):
    """Initialize API integration manager."""
    global api_integration_manager
    api_integration_manager = APIIntegrationManager(app)
    return api_integration_manager