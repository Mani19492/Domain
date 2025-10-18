import asyncio
import websockets
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import sqlite3
import threading
import time
import hashlib
from dataclasses import dataclass, asdict
import requests
from recon import get_recon_data
from ai_threat_predictor import threat_predictor
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

@dataclass
class MonitoringAlert:
    id: str
    domain: str
    alert_type: str
    severity: str
    message: str
    timestamp: str
    resolved: bool = False

class RealTimeMonitor:
    def __init__(self, db_path: str = 'monitoring.db'):
        self.db_path = db_path
        self.active_monitors = {}
        self.websocket_clients = set()
        self.alert_queue = []
        self.running = False
        
        # Initialize database
        self.init_database()
        
        # Start background monitoring
        self.start_monitoring_thread()
    
    def init_database(self):
        """Initialize monitoring database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Monitoring jobs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS monitoring_jobs (
                    id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    user_id TEXT,
                    frequency INTEGER DEFAULT 3600,
                    last_check TEXT,
                    next_check TEXT,
                    baseline_data TEXT,
                    alert_channels TEXT,
                    active BOOLEAN DEFAULT 1,
                    created_at TEXT NOT NULL
                )
            ''')
            
            # Monitoring alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS monitoring_alerts (
                    id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    resolved BOOLEAN DEFAULT 0,
                    resolved_at TEXT
                )
            ''')
            
            # Domain changes history
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domain_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT,
                    timestamp TEXT NOT NULL,
                    severity TEXT DEFAULT 'info'
                )
            ''')
            
            # Real-time dashboard data
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dashboard_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT NOT NULL,
                    metric_value TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
    
    def add_domain_monitor(self, domain: str, user_id: str = None, frequency: int = 3600, alert_channels: List[str] = None) -> str:
        """Add a domain to real-time monitoring."""
        try:
            # Generate monitoring job ID
            job_id = hashlib.md5(f"{domain}_{datetime.now().isoformat()}".encode()).hexdigest()
            
            # Get baseline data
            baseline_data = get_recon_data(domain)
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO monitoring_jobs 
                (id, domain, user_id, frequency, last_check, next_check, baseline_data, alert_channels, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                job_id,
                domain,
                user_id,
                frequency,
                datetime.now().isoformat(),
                (datetime.now() + timedelta(seconds=frequency)).isoformat(),
                json.dumps(baseline_data),
                json.dumps(alert_channels or ['websocket']),
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            # Add to active monitors
            self.active_monitors[job_id] = {
                'domain': domain,
                'frequency': frequency,
                'last_check': datetime.now(),
                'next_check': datetime.now() + timedelta(seconds=frequency),
                'baseline_data': baseline_data,
                'alert_channels': alert_channels or ['websocket']
            }
            
            logger.info(f"Added domain {domain} to monitoring with job ID {job_id}")
            
            # Send initial status to dashboard
            self.broadcast_dashboard_update({
                'type': 'monitor_added',
                'domain': domain,
                'job_id': job_id,
                'timestamp': datetime.now().isoformat()
            })
            
            return job_id
            
        except Exception as e:
            logger.error(f"Error adding domain monitor: {str(e)}")
            raise
    
    def start_monitoring_thread(self):
        """Start background monitoring thread."""
        def monitoring_loop():
            self.running = True
            while self.running:
                try:
                    self.check_all_monitors()
                    self.process_alert_queue()
                    time.sleep(30)  # Check every 30 seconds
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {str(e)}")
                    time.sleep(60)  # Wait longer on error
        
        monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitoring_thread.start()
        logger.info("Real-time monitoring thread started")
    
    def check_all_monitors(self):
        """Check all active monitors for changes."""
        current_time = datetime.now()
        
        for job_id, monitor in list(self.active_monitors.items()):
            try:
                if current_time >= monitor['next_check']:
                    self.check_domain_changes(job_id, monitor)
                    
                    # Update next check time
                    monitor['next_check'] = current_time + timedelta(seconds=monitor['frequency'])
                    monitor['last_check'] = current_time
                    
            except Exception as e:
                logger.error(f"Error checking monitor {job_id}: {str(e)}")
    
    def check_domain_changes(self, job_id: str, monitor: dict):
        """Check for changes in a specific domain."""
        try:
            domain = monitor['domain']
            baseline_data = monitor['baseline_data']
            
            # Get current data
            current_data = get_recon_data(domain)
            
            # Compare with baseline
            changes = self.detect_changes(baseline_data, current_data)
            
            if changes:
                # Log changes to database
                self.log_domain_changes(domain, changes)
                
                # Generate alerts
                for change in changes:
                    alert = self.create_alert(domain, change)
                    self.alert_queue.append(alert)
                
                # Update baseline if significant changes
                if any(change['severity'] in ['high', 'critical'] for change in changes):
                    monitor['baseline_data'] = current_data
                    self.update_baseline_in_db(job_id, current_data)
                
                # Broadcast changes to dashboard
                self.broadcast_dashboard_update({
                    'type': 'domain_changes',
                    'domain': domain,
                    'changes': changes,
                    'timestamp': datetime.now().isoformat()
                })
            
            # Update last check time in database
            self.update_last_check(job_id)
            
        except Exception as e:
            logger.error(f"Error checking domain changes for {monitor['domain']}: {str(e)}")
    
    def detect_changes(self, baseline: dict, current: dict) -> List[dict]:
        """Detect changes between baseline and current data."""
        changes = []
        
        try:
            # DNS changes
            baseline_dns = set(str(record) for record in baseline.get('dns', []))
            current_dns = set(str(record) for record in current.get('dns', []))
            
            if baseline_dns != current_dns:
                new_records = current_dns - baseline_dns
                removed_records = baseline_dns - current_dns
                
                if new_records:
                    changes.append({
                        'type': 'dns_added',
                        'severity': 'medium',
                        'message': f"New DNS records detected: {', '.join(list(new_records)[:3])}",
                        'details': list(new_records)
                    })
                
                if removed_records:
                    changes.append({
                        'type': 'dns_removed',
                        'severity': 'high',
                        'message': f"DNS records removed: {', '.join(list(removed_records)[:3])}",
                        'details': list(removed_records)
                    })
            
            # IP address changes
            baseline_ip = baseline.get('geolocation', {}).get('ip')
            current_ip = current.get('geolocation', {}).get('ip')
            
            if baseline_ip and current_ip and baseline_ip != current_ip:
                changes.append({
                    'type': 'ip_change',
                    'severity': 'critical',
                    'message': f"IP address changed from {baseline_ip} to {current_ip}",
                    'details': {'old_ip': baseline_ip, 'new_ip': current_ip}
                })
            
            # SSL certificate changes
            baseline_ssl = baseline.get('ssl', {})
            current_ssl = current.get('ssl', {})
            
            if baseline_ssl.get('expiry') != current_ssl.get('expiry'):
                changes.append({
                    'type': 'ssl_change',
                    'severity': 'medium',
                    'message': "SSL certificate changed",
                    'details': {
                        'old_expiry': baseline_ssl.get('expiry'),
                        'new_expiry': current_ssl.get('expiry')
                    }
                })
            
            # Subdomain changes
            baseline_subdomains = set(baseline.get('subdomains', []))
            current_subdomains = set(current.get('subdomains', []))
            
            new_subdomains = current_subdomains - baseline_subdomains
            if new_subdomains:
                changes.append({
                    'type': 'subdomain_added',
                    'severity': 'medium',
                    'message': f"New subdomains discovered: {', '.join(list(new_subdomains)[:5])}",
                    'details': list(new_subdomains)
                })
            
            # Threat score changes
            baseline_threat = threat_predictor.predict_threat_level(baseline)
            current_threat = threat_predictor.predict_threat_level(current)
            
            baseline_score = baseline_threat.get('risk_score', 0)
            current_score = current_threat.get('risk_score', 0)
            
            score_diff = current_score - baseline_score
            if abs(score_diff) >= 20:  # Significant change
                severity = 'critical' if score_diff > 0 else 'info'
                direction = 'increased' if score_diff > 0 else 'decreased'
                
                changes.append({
                    'type': 'threat_score_change',
                    'severity': severity,
                    'message': f"Threat score {direction} by {abs(score_diff)} points (now {current_score})",
                    'details': {
                        'old_score': baseline_score,
                        'new_score': current_score,
                        'change': score_diff
                    }
                })
            
            # Open ports changes
            baseline_ports = set(port.get('port') for port in baseline.get('open_ports', []))
            current_ports = set(port.get('port') for port in current.get('open_ports', []))
            
            new_ports = current_ports - baseline_ports
            closed_ports = baseline_ports - current_ports
            
            if new_ports:
                changes.append({
                    'type': 'ports_opened',
                    'severity': 'high',
                    'message': f"New open ports detected: {', '.join(map(str, new_ports))}",
                    'details': list(new_ports)
                })
            
            if closed_ports:
                changes.append({
                    'type': 'ports_closed',
                    'severity': 'info',
                    'message': f"Ports closed: {', '.join(map(str, closed_ports))}",
                    'details': list(closed_ports)
                })
            
            return changes
            
        except Exception as e:
            logger.error(f"Error detecting changes: {str(e)}")
            return []
    
    def create_alert(self, domain: str, change: dict) -> MonitoringAlert:
        """Create a monitoring alert."""
        alert_id = hashlib.md5(f"{domain}_{change['type']}_{datetime.now().isoformat()}".encode()).hexdigest()
        
        return MonitoringAlert(
            id=alert_id,
            domain=domain,
            alert_type=change['type'],
            severity=change['severity'],
            message=change['message'],
            timestamp=datetime.now().isoformat()
        )
    
    def process_alert_queue(self):
        """Process pending alerts."""
        while self.alert_queue:
            try:
                alert = self.alert_queue.pop(0)
                
                # Save alert to database
                self.save_alert_to_db(alert)
                
                # Send alert through configured channels
                self.send_alert(alert)
                
                # Broadcast to dashboard
                self.broadcast_dashboard_update({
                    'type': 'new_alert',
                    'alert': asdict(alert)
                })
                
            except Exception as e:
                logger.error(f"Error processing alert: {str(e)}")
    
    def send_alert(self, alert: MonitoringAlert):
        """Send alert through configured channels."""
        try:
            # WebSocket broadcast (always enabled)
            self.broadcast_to_websockets({
                'type': 'alert',
                'data': asdict(alert)
            })
            
            # Email alerts (if configured)
            # This would integrate with your email service
            logger.info(f"Alert sent for {alert.domain}: {alert.message}")
            
        except Exception as e:
            logger.error(f"Error sending alert: {str(e)}")
    
    def get_dashboard_data(self) -> dict:
        """Get real-time dashboard data."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get active monitors count
            cursor.execute('SELECT COUNT(*) FROM monitoring_jobs WHERE active = 1')
            active_monitors = cursor.fetchone()[0]
            
            # Get recent alerts
            cursor.execute('''
                SELECT * FROM monitoring_alerts 
                WHERE timestamp > datetime('now', '-24 hours')
                ORDER BY timestamp DESC LIMIT 10
            ''')
            recent_alerts = [
                {
                    'id': row[0],
                    'domain': row[1],
                    'alert_type': row[2],
                    'severity': row[3],
                    'message': row[4],
                    'timestamp': row[5],
                    'resolved': bool(row[6])
                }
                for row in cursor.fetchall()
            ]
            
            # Get domain changes in last 24 hours
            cursor.execute('''
                SELECT domain, COUNT(*) as change_count
                FROM domain_changes 
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY domain
                ORDER BY change_count DESC
                LIMIT 5
            ''')
            top_changing_domains = [
                {'domain': row[0], 'changes': row[1]}
                for row in cursor.fetchall()
            ]
            
            # Get severity distribution
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM monitoring_alerts 
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY severity
            ''')
            severity_distribution = {row[0]: row[1] for row in cursor.fetchall()}
            
            conn.close()
            
            return {
                'active_monitors': active_monitors,
                'recent_alerts': recent_alerts,
                'top_changing_domains': top_changing_domains,
                'severity_distribution': severity_distribution,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting dashboard data: {str(e)}")
            return {}
    
    def log_domain_changes(self, domain: str, changes: List[dict]):
        """Log domain changes to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for change in changes:
                cursor.execute('''
                    INSERT INTO domain_changes (domain, change_type, old_value, new_value, timestamp, severity)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    domain,
                    change['type'],
                    json.dumps(change.get('details', {}).get('old_value')),
                    json.dumps(change.get('details', {}).get('new_value')),
                    datetime.now().isoformat(),
                    change['severity']
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error logging domain changes: {str(e)}")
    
    def save_alert_to_db(self, alert: MonitoringAlert):
        """Save alert to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO monitoring_alerts (id, domain, alert_type, severity, message, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                alert.id,
                alert.domain,
                alert.alert_type,
                alert.severity,
                alert.message,
                alert.timestamp
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error saving alert to database: {str(e)}")
    
    def update_baseline_in_db(self, job_id: str, new_baseline: dict):
        """Update baseline data in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE monitoring_jobs 
                SET baseline_data = ? 
                WHERE id = ?
            ''', (json.dumps(new_baseline), job_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error updating baseline: {str(e)}")
    
    def update_last_check(self, job_id: str):
        """Update last check time in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE monitoring_jobs 
                SET last_check = ? 
                WHERE id = ?
            ''', (datetime.now().isoformat(), job_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error updating last check: {str(e)}")
    
    def broadcast_dashboard_update(self, data: dict):
        """Broadcast update to dashboard clients."""
        try:
            message = json.dumps(data)
            self.broadcast_to_websockets(message)
        except Exception as e:
            logger.error(f"Error broadcasting dashboard update: {str(e)}")
    
    def broadcast_to_websockets(self, message):
        """Broadcast message to all WebSocket clients."""
        if self.websocket_clients:
            # This would integrate with your WebSocket implementation
            logger.info(f"Broadcasting to {len(self.websocket_clients)} clients")
    
    def get_monitored_domains(self) -> List[dict]:
        """Get list of all monitored domains."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, domain, last_check, created_at, active
                FROM monitoring_jobs
                ORDER BY created_at DESC
            ''')
            
            domains = [
                {
                    'id': row[0],
                    'domain': row[1],
                    'last_check': row[2],
                    'created_at': row[3],
                    'active': bool(row[4])
                }
                for row in cursor.fetchall()
            ]
            
            conn.close()
            return domains
            
        except Exception as e:
            logger.error(f"Error getting monitored domains: {str(e)}")
            return []
    
    def stop_monitoring(self, job_id: str):
        """Stop monitoring a domain."""
        try:
            # Remove from active monitors
            if job_id in self.active_monitors:
                del self.active_monitors[job_id]
            
            # Update database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE monitoring_jobs 
                SET active = 0 
                WHERE id = ?
            ''', (job_id,))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Stopped monitoring job {job_id}")
            
        except Exception as e:
            logger.error(f"Error stopping monitoring: {str(e)}")

# Initialize global real-time monitor
real_time_monitor = RealTimeMonitor()