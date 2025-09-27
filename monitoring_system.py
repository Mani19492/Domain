import schedule
import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
import threading
from dataclasses import dataclass, asdict
import sqlite3
import hashlib

logger = logging.getLogger(__name__)

@dataclass
class MonitoringJob:
    id: str
    domain: str
    frequency: str  # 'hourly', 'daily', 'weekly'
    alert_channels: List[str]
    baseline_data: dict
    last_scan: str
    next_scan: str
    active: bool
    created_at: str

class DomainMonitoringSystem:
    def __init__(self, db_path: str = 'monitoring.db'):
        self.db_path = db_path
        self.monitoring_jobs = {}
        self.public_monitoring = {}
        self.alert_thresholds = {
            'dns_changes': True,
            'ssl_changes': True,
            'subdomain_changes': True,
            'ip_changes': True,
            'whois_changes': True,
            'threat_score_increase': 20  # Alert if threat score increases by 20+
        }
        self.init_database()
        self.load_monitoring_jobs()
        self.start_scheduler()
    
    def init_database(self):
        """Initialize SQLite database for monitoring jobs."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS monitoring_jobs (
                    id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    frequency TEXT NOT NULL,
                    alert_channels TEXT NOT NULL,
                    baseline_data TEXT NOT NULL,
                    last_scan TEXT,
                    next_scan TEXT,
                    active BOOLEAN DEFAULT 1,
                    created_at TEXT NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS public_monitoring (
                    id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL UNIQUE,
                    baseline_data TEXT NOT NULL,
                    last_scan TEXT,
                    last_change TEXT,
                    change_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'monitoring',
                    created_at TEXT NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    scan_time TEXT NOT NULL,
                    changes_detected TEXT,
                    threat_score INTEGER,
                    alert_sent BOOLEAN DEFAULT 0,
                    FOREIGN KEY (job_id) REFERENCES monitoring_jobs (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
    
    def create_monitoring_job(self, domain: str, frequency: str, alert_channels: List[str]) -> str:
        """Create a new monitoring job."""
        try:
            from recon import get_recon_data
            from ai_threat_predictor import threat_predictor
            
            # Get baseline data
            baseline_recon = get_recon_data(domain)
            baseline_threat = threat_predictor.predict_threat_level(baseline_recon)
            
            baseline_data = {
                'recon': baseline_recon,
                'threat_analysis': baseline_threat,
                'created_at': datetime.now().isoformat()
            }
            
            job_id = hashlib.md5(f"{domain}_{datetime.now().isoformat()}".encode()).hexdigest()
            
            job = MonitoringJob(
                id=job_id,
                domain=domain,
                frequency=frequency,
                alert_channels=alert_channels,
                baseline_data=baseline_data,
                last_scan='',
                next_scan=self._calculate_next_scan(frequency),
                active=True,
                created_at=datetime.now().isoformat()
            )
            
            self.monitoring_jobs[job_id] = job
            self._save_job_to_db(job)
            
            logger.info(f"Created monitoring job {job_id} for domain {domain}")
            return job_id
            
        except Exception as e:
            logger.error(f"Error creating monitoring job: {str(e)}")
            raise
    
    def _calculate_next_scan(self, frequency: str) -> str:
        """Calculate next scan time based on frequency."""
        now = datetime.now()
        
        if frequency == 'hourly':
            next_scan = now + timedelta(hours=1)
        elif frequency == 'daily':
            next_scan = now + timedelta(days=1)
        elif frequency == 'weekly':
            next_scan = now + timedelta(weeks=1)
        else:
            next_scan = now + timedelta(days=1)  # Default to daily
        
        return next_scan.isoformat()
    
    def _save_job_to_db(self, job: MonitoringJob):
        """Save monitoring job to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO monitoring_jobs 
                (id, domain, frequency, alert_channels, baseline_data, last_scan, next_scan, active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                job.id,
                job.domain,
                job.frequency,
                json.dumps(job.alert_channels),
                json.dumps(job.baseline_data),
                job.last_scan,
                job.next_scan,
                job.active,
                job.created_at
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error saving job to database: {str(e)}")
    
    def load_monitoring_jobs(self):
        """Load monitoring jobs from database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM monitoring_jobs WHERE active = 1')
            rows = cursor.fetchall()
            
            for row in rows:
                job = MonitoringJob(
                    id=row[0],
                    domain=row[1],
                    frequency=row[2],
                    alert_channels=json.loads(row[3]),
                    baseline_data=json.loads(row[4]),
                    last_scan=row[5] or '',
                    next_scan=row[6],
                    active=bool(row[7]),
                    created_at=row[8]
                )
                self.monitoring_jobs[job.id] = job
            
            conn.close()
            logger.info(f"Loaded {len(self.monitoring_jobs)} monitoring jobs")
            
        except Exception as e:
            logger.error(f"Error loading monitoring jobs: {str(e)}")
    
    def start_scheduler(self):
        """Start the monitoring scheduler."""
        def run_scheduler():
            schedule.every().minute.do(self.check_scheduled_scans)
            
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
        logger.info("Monitoring scheduler started")
    
    def check_scheduled_scans(self):
        """Check for scheduled scans and execute them."""
        now = datetime.now()
        
        for job_id, job in self.monitoring_jobs.items():
            if not job.active:
                continue
            
            try:
                next_scan_time = datetime.fromisoformat(job.next_scan)
                if now >= next_scan_time:
                    self.execute_monitoring_scan(job_id)
            except Exception as e:
                logger.error(f"Error checking scheduled scan for job {job_id}: {str(e)}")
    
    def execute_monitoring_scan(self, job_id: str):
        """Execute a monitoring scan for a specific job."""
        try:
            job = self.monitoring_jobs.get(job_id)
            if not job:
                logger.error(f"Job {job_id} not found")
                return
            
            from recon import get_recon_data
            from ai_threat_predictor import threat_predictor
            
            # Perform new scan
            current_recon = get_recon_data(job.domain)
            current_threat = threat_predictor.predict_threat_level(current_recon)
            
            # Compare with baseline
            changes = self._detect_changes(job.baseline_data, {
                'recon': current_recon,
                'threat_analysis': current_threat
            })
            
            # Update job
            job.last_scan = datetime.now().isoformat()
            job.next_scan = self._calculate_next_scan(job.frequency)
            self._save_job_to_db(job)
            
            # Save scan history
            self._save_scan_history(job_id, changes, current_threat.get('risk_score', 0))
            
            # Send alerts if changes detected
            if changes['has_changes']:
                self._send_monitoring_alerts(job, changes)
            
            logger.info(f"Completed monitoring scan for {job.domain}")
            
        except Exception as e:
            logger.error(f"Error executing monitoring scan for job {job_id}: {str(e)}")
    
    def _detect_changes(self, baseline: dict, current: dict) -> dict:
        """Detect changes between baseline and current scan."""
        changes = {
            'has_changes': False,
            'dns_changes': [],
            'ssl_changes': [],
            'subdomain_changes': [],
            'ip_changes': [],
            'whois_changes': [],
            'threat_score_change': 0,
            'new_threats': []
        }
        
        try:
            baseline_recon = baseline.get('recon', {})
            current_recon = current.get('recon', {})
            
            # Check DNS changes
            baseline_dns = set(str(r) for r in baseline_recon.get('dns', []))
            current_dns = set(str(r) for r in current_recon.get('dns', []))
            
            if baseline_dns != current_dns:
                changes['has_changes'] = True
                changes['dns_changes'] = list(current_dns - baseline_dns)
            
            # Check SSL changes
            baseline_ssl = baseline_recon.get('ssl', {})
            current_ssl = current_recon.get('ssl', {})
            
            if baseline_ssl.get('expiry') != current_ssl.get('expiry'):
                changes['has_changes'] = True
                changes['ssl_changes'].append('SSL certificate changed')
            
            # Check subdomain changes
            baseline_subdomains = set(baseline_recon.get('subdomains', []))
            current_subdomains = set(current_recon.get('subdomains', []))
            
            new_subdomains = current_subdomains - baseline_subdomains
            if new_subdomains:
                changes['has_changes'] = True
                changes['subdomain_changes'] = list(new_subdomains)
            
            # Check IP changes
            baseline_ip = baseline_recon.get('geolocation', {}).get('ip')
            current_ip = current_recon.get('geolocation', {}).get('ip')
            
            if baseline_ip != current_ip:
                changes['has_changes'] = True
                changes['ip_changes'].append(f'IP changed from {baseline_ip} to {current_ip}')
            
            # Check threat score changes
            baseline_score = baseline.get('threat_analysis', {}).get('risk_score', 0)
            current_score = current.get('threat_analysis', {}).get('risk_score', 0)
            
            score_change = current_score - baseline_score
            if abs(score_change) >= self.alert_thresholds['threat_score_increase']:
                changes['has_changes'] = True
                changes['threat_score_change'] = score_change
            
            return changes
            
        except Exception as e:
            logger.error(f"Error detecting changes: {str(e)}")
            return changes
    
    def _save_scan_history(self, job_id: str, changes: dict, threat_score: int):
        """Save scan history to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO scan_history (job_id, scan_time, changes_detected, threat_score, alert_sent)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                job_id,
                datetime.now().isoformat(),
                json.dumps(changes),
                threat_score,
                changes['has_changes']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error saving scan history: {str(e)}")
    
    def _send_monitoring_alerts(self, job: MonitoringJob, changes: dict):
        """Send monitoring alerts through configured channels."""
        try:
            alert_message = self._create_alert_message(job.domain, changes)
            
            for channel in job.alert_channels:
                if channel == 'email':
                    self._send_email_alert(job.domain, alert_message)
                elif channel == 'sms':
                    self._send_sms_alert(job.domain, alert_message)
                elif channel == 'slack':
                    self._send_slack_alert(job.domain, alert_message)
                elif channel == 'webhook':
                    self._send_webhook_alert(job.domain, changes)
            
        except Exception as e:
            logger.error(f"Error sending monitoring alerts: {str(e)}")
    
    def _create_alert_message(self, domain: str, changes: dict) -> str:
        """Create alert message from detected changes."""
        message = f"🚨 Domain Monitoring Alert: {domain}\n\n"
        
        if changes.get('dns_changes'):
            message += f"📡 DNS Changes: {len(changes['dns_changes'])} new records\n"
        
        if changes.get('ssl_changes'):
            message += f"🔒 SSL Changes: {', '.join(changes['ssl_changes'])}\n"
        
        if changes.get('subdomain_changes'):
            message += f"🌐 New Subdomains: {len(changes['subdomain_changes'])} discovered\n"
        
        if changes.get('ip_changes'):
            message += f"🌍 IP Changes: {', '.join(changes['ip_changes'])}\n"
        
        if changes.get('threat_score_change'):
            change = changes['threat_score_change']
            direction = "increased" if change > 0 else "decreased"
            message += f"⚠️ Threat Score {direction} by {abs(change)} points\n"
        
        message += f"\nScan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        return message
    
    def _send_email_alert(self, domain: str, message: str):
        """Send email alert (placeholder - implement with your email service)."""
        logger.info(f"Email alert sent for {domain}")
        # Implement actual email sending here
    
    def _send_sms_alert(self, domain: str, message: str):
        """Send SMS alert (placeholder - implement with Twilio or similar)."""
        logger.info(f"SMS alert sent for {domain}")
        # Implement actual SMS sending here
    
    def _send_slack_alert(self, domain: str, message: str):
        """Send Slack alert (placeholder - implement with Slack webhook)."""
        logger.info(f"Slack alert sent for {domain}")
        # Implement actual Slack webhook here
    
    def _send_webhook_alert(self, domain: str, changes: dict):
        """Send webhook alert (placeholder)."""
        logger.info(f"Webhook alert sent for {domain}")
        # Implement actual webhook sending here
    
    def get_monitoring_jobs(self) -> List[dict]:
        """Get all monitoring jobs."""
        return [asdict(job) for job in self.monitoring_jobs.values()]
    
    def get_job_history(self, job_id: str, limit: int = 50) -> List[dict]:
        """Get scan history for a specific job."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT scan_time, changes_detected, threat_score, alert_sent
                FROM scan_history
                WHERE job_id = ?
                ORDER BY scan_time DESC
                LIMIT ?
            ''', (job_id, limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            history = []
            for row in rows:
                history.append({
                    'scan_time': row[0],
                    'changes_detected': json.loads(row[1]),
                    'threat_score': row[2],
                    'alert_sent': bool(row[3])
                })
            
            return history
            
        except Exception as e:
            logger.error(f"Error getting job history: {str(e)}")
            return []
    
    def stop_monitoring_job(self, job_id: str):
        """Stop a monitoring job."""
        if job_id in self.monitoring_jobs:
            self.monitoring_jobs[job_id].active = False
            self._save_job_to_db(self.monitoring_jobs[job_id])
            logger.info(f"Stopped monitoring job {job_id}")

    def add_public_monitoring(self, domain: str) -> str:
        """Add domain to public monitoring."""
        try:
            from recon import get_recon_data
            from ai_threat_predictor import threat_predictor
            
            # Check if already exists
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM public_monitoring WHERE domain = ?', (domain,))
            existing = cursor.fetchone()
            
            if existing:
                conn.close()
                return existing[0]
            
            # Get baseline data
            baseline_recon = get_recon_data(domain)
            baseline_threat = threat_predictor.predict_threat_level(baseline_recon)
            
            baseline_data = {
                'recon': baseline_recon,
                'threat_analysis': baseline_threat,
                'created_at': datetime.now().isoformat()
            }
            
            job_id = hashlib.md5(f"public_{domain}_{datetime.now().isoformat()}".encode()).hexdigest()
            
            cursor.execute('''
                INSERT INTO public_monitoring 
                (id, domain, baseline_data, last_scan, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                job_id,
                domain,
                json.dumps(baseline_data),
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            self.public_monitoring[job_id] = {
                'id': job_id,
                'domain': domain,
                'baseline_data': baseline_data,
                'last_scan': datetime.now().isoformat(),
                'status': 'monitoring',
                'change_count': 0
            }
            
            logger.info(f"Added {domain} to public monitoring")
            return job_id
            
        except Exception as e:
            logger.error(f"Error adding public monitoring: {str(e)}")
            raise
    
    def get_public_monitoring_jobs(self) -> List[dict]:
        """Get all public monitoring jobs."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, domain, last_scan, last_change, change_count, status, created_at
                FROM public_monitoring
                ORDER BY created_at DESC
            ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            jobs = []
            for row in rows:
                jobs.append({
                    'id': row[0],
                    'domain': row[1],
                    'last_scan': row[2],
                    'last_change': row[3],
                    'change_count': row[4],
                    'status': row[5],
                    'created_at': row[6],
                    'has_updates': row[4] > 0
                })
            
            return jobs
            
        except Exception as e:
            logger.error(f"Error getting public monitoring jobs: {str(e)}")
            return []
# Initialize global monitoring system
monitoring_system = DomainMonitoringSystem()