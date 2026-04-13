"""
Uptime Monitoring Service
Real-time uptime checking with response time tracking
"""
import requests
import logging
import sqlite3
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import threading
import time
import hashlib
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class UptimeCheck:
    timestamp: str
    url: str
    status_code: int
    response_time_ms: float
    is_up: bool
    error: Optional[str] = None


class UptimeMonitor:
    """Real-time uptime monitoring service."""

    def __init__(self, db_path: str = 'monitoring.db'):
        self.db_path = db_path
        self.monitored_urls = {}
        self.running = False
        self.check_interval = 60  # 60 seconds
        self.init_database()
        self.load_monitored_urls()
        self.start_monitoring_thread()

    def init_database(self):
        """Initialize uptime monitoring database tables."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Uptime monitoring jobs
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS uptime_monitors (
                    id TEXT PRIMARY KEY,
                    url TEXT NOT NULL UNIQUE,
                    check_interval INTEGER DEFAULT 60,
                    alert_threshold INTEGER DEFAULT 3,
                    active BOOLEAN DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_check TEXT
                )
            ''')

            # Uptime check history
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS uptime_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    monitor_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    status_code INTEGER,
                    response_time_ms REAL,
                    is_up BOOLEAN,
                    error TEXT,
                    FOREIGN KEY (monitor_id) REFERENCES uptime_monitors (id)
                )
            ''')

            # Uptime incidents
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS uptime_incidents (
                    id TEXT PRIMARY KEY,
                    monitor_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    duration_seconds INTEGER,
                    incident_type TEXT,
                    resolved BOOLEAN DEFAULT 0,
                    FOREIGN KEY (monitor_id) REFERENCES uptime_monitors (id)
                )
            ''')

            conn.commit()
            conn.close()
            logger.info("Uptime monitor database initialized")

        except Exception as e:
            logger.error(f"Error initializing uptime database: {str(e)}")

    def add_url_monitor(self, url: str, check_interval: int = 60) -> str:
        """Add a URL to uptime monitoring."""
        try:
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'

            monitor_id = hashlib.md5(f"{url}_{datetime.now().isoformat()}".encode()).hexdigest()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO uptime_monitors 
                (id, url, check_interval, created_at, last_check)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                monitor_id,
                url,
                check_interval,
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))

            conn.commit()
            conn.close()

            # Add to active monitors
            self.monitored_urls[monitor_id] = {
                'url': url,
                'check_interval': check_interval,
                'last_check': datetime.now(),
                'consecutive_failures': 0,
                'last_status': 'unknown'
            }

            logger.info(f"Added URL to uptime monitoring: {url}")
            return monitor_id

        except Exception as e:
            logger.error(f"Error adding URL monitor: {str(e)}")
            raise

    def load_monitored_urls(self):
        """Load monitored URLs from database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT id, url, check_interval, last_check FROM uptime_monitors WHERE active = 1')
            rows = cursor.fetchall()

            for row in rows:
                monitor_id, url, check_interval, last_check = row
                self.monitored_urls[monitor_id] = {
                    'url': url,
                    'check_interval': check_interval,
                    'last_check': datetime.fromisoformat(last_check) if last_check else datetime.now(),
                    'consecutive_failures': 0,
                    'last_status': 'unknown'
                }

            conn.close()
            logger.info(f"Loaded {len(self.monitored_urls)} monitored URLs")

        except Exception as e:
            logger.error(f"Error loading monitored URLs: {str(e)}")

    def start_monitoring_thread(self):
        """Start background monitoring thread."""
        def monitoring_loop():
            self.running = True
            while self.running:
                try:
                    self.check_all_urls()
                    time.sleep(10)  # Check every 10 seconds if any URL is due
                except Exception as e:
                    logger.error(f"Error in uptime monitoring loop: {str(e)}")
                    time.sleep(30)

        monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitor_thread.start()
        logger.info("Uptime monitoring thread started")

    def check_all_urls(self):
        """Check all monitored URLs that are due for checking."""
        current_time = datetime.now()

        for monitor_id, monitor_data in list(self.monitored_urls.items()):
            try:
                time_since_check = (current_time - monitor_data['last_check']).seconds
                
                if time_since_check >= monitor_data['check_interval']:
                    self.perform_uptime_check(monitor_id, monitor_data)
                    monitor_data['last_check'] = current_time

            except Exception as e:
                logger.error(f"Error checking URL {monitor_data['url']}: {str(e)}")

    def perform_uptime_check(self, monitor_id: str, monitor_data: dict):
        """Perform uptime check for a specific URL."""
        url = monitor_data['url']
        start_time = time.time()
        
        check = UptimeCheck(
            timestamp=datetime.now().isoformat(),
            url=url,
            status_code=0,
            response_time_ms=0,
            is_up=False,
            error=None
        )

        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                headers={'User-Agent': 'UptimeMonitor/1.0'}
            )
            
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            check.status_code = response.status_code
            check.response_time_ms = round(response_time, 2)
            check.is_up = response.status_code < 500
            
            # Update consecutive failures
            if check.is_up:
                if monitor_data['consecutive_failures'] > 0:
                    # Recovery from downtime
                    self.resolve_incident(monitor_id)
                monitor_data['consecutive_failures'] = 0
                monitor_data['last_status'] = 'up'
            else:
                monitor_data['consecutive_failures'] += 1
                monitor_data['last_status'] = 'down'
                
                # Create incident if threshold reached
                if monitor_data['consecutive_failures'] >= 3:
                    self.create_incident(monitor_id, url)

        except requests.exceptions.RequestException as e:
            check.error = str(e)
            check.is_up = False
            monitor_data['consecutive_failures'] += 1
            monitor_data['last_status'] = 'down'
            
            if monitor_data['consecutive_failures'] >= 3:
                self.create_incident(monitor_id, url)

        # Save check to database
        self.save_uptime_check(monitor_id, check)

    def save_uptime_check(self, monitor_id: str, check: UptimeCheck):
        """Save uptime check to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO uptime_checks 
                (monitor_id, url, timestamp, status_code, response_time_ms, is_up, error)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                monitor_id,
                check.url,
                check.timestamp,
                check.status_code,
                check.response_time_ms,
                check.is_up,
                check.error
            ))

            # Update last check time
            cursor.execute('''
                UPDATE uptime_monitors 
                SET last_check = ? 
                WHERE id = ?
            ''', (check.timestamp, monitor_id))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Error saving uptime check: {str(e)}")

    def create_incident(self, monitor_id: str, url: str):
        """Create uptime incident."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Check if there's already an active incident
            cursor.execute('''
                SELECT id FROM uptime_incidents 
                WHERE monitor_id = ? AND resolved = 0
            ''', (monitor_id,))
            
            if cursor.fetchone():
                conn.close()
                return  # Incident already exists

            incident_id = hashlib.md5(f"{monitor_id}_{datetime.now().isoformat()}".encode()).hexdigest()

            cursor.execute('''
                INSERT INTO uptime_incidents 
                (id, monitor_id, url, start_time, incident_type)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                incident_id,
                monitor_id,
                url,
                datetime.now().isoformat(),
                'downtime'
            ))

            conn.commit()
            conn.close()

            logger.warning(f"Uptime incident created for {url}")

        except Exception as e:
            logger.error(f"Error creating incident: {str(e)}")

    def resolve_incident(self, monitor_id: str):
        """Resolve active incident."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get active incident
            cursor.execute('''
                SELECT id, start_time FROM uptime_incidents 
                WHERE monitor_id = ? AND resolved = 0
            ''', (monitor_id,))
            
            incident = cursor.fetchone()
            if not incident:
                conn.close()
                return

            incident_id, start_time = incident
            start = datetime.fromisoformat(start_time)
            duration = (datetime.now() - start).seconds

            cursor.execute('''
                UPDATE uptime_incidents 
                SET resolved = 1, end_time = ?, duration_seconds = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), duration, incident_id))

            conn.commit()
            conn.close()

            logger.info(f"Incident resolved for monitor {monitor_id}, duration: {duration}s")

        except Exception as e:
            logger.error(f"Error resolving incident: {str(e)}")

    def get_uptime_stats(self, monitor_id: str, hours: int = 24) -> Dict[str, Any]:
        """Get uptime statistics for a monitor."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()

            # Get all checks in time period
            cursor.execute('''
                SELECT status_code, response_time_ms, is_up, timestamp
                FROM uptime_checks
                WHERE monitor_id = ? AND timestamp > ?
                ORDER BY timestamp ASC
            ''', (monitor_id, cutoff_time))

            checks = cursor.fetchall()
            
            if not checks:
                conn.close()
                return {
                    'uptime_percentage': 0,
                    'total_checks': 0,
                    'successful_checks': 0,
                    'failed_checks': 0,
                    'avg_response_time': 0,
                    'incidents': []
                }

            total_checks = len(checks)
            successful_checks = sum(1 for check in checks if check[2])  # is_up
            failed_checks = total_checks - successful_checks
            uptime_percentage = (successful_checks / total_checks) * 100

            # Calculate average response time (only for successful checks)
            response_times = [check[1] for check in checks if check[2] and check[1] > 0]
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0

            # Get incidents in time period
            cursor.execute('''
                SELECT id, start_time, end_time, duration_seconds, resolved
                FROM uptime_incidents
                WHERE monitor_id = ? AND start_time > ?
                ORDER BY start_time DESC
            ''', (monitor_id, cutoff_time))

            incidents = [
                {
                    'id': row[0],
                    'start_time': row[1],
                    'end_time': row[2],
                    'duration_seconds': row[3],
                    'resolved': bool(row[4])
                }
                for row in cursor.fetchall()
            ]

            # Get response time data for graphing
            cursor.execute('''
                SELECT timestamp, response_time_ms, is_up
                FROM uptime_checks
                WHERE monitor_id = ? AND timestamp > ?
                ORDER BY timestamp ASC
            ''', (monitor_id, cutoff_time))

            response_time_data = [
                {
                    'timestamp': row[0],
                    'response_time': row[1],
                    'is_up': bool(row[2])
                }
                for row in cursor.fetchall()
            ]

            conn.close()

            return {
                'uptime_percentage': round(uptime_percentage, 2),
                'total_checks': total_checks,
                'successful_checks': successful_checks,
                'failed_checks': failed_checks,
                'avg_response_time': round(avg_response_time, 2),
                'incidents': incidents,
                'response_time_data': response_time_data
            }

        except Exception as e:
            logger.error(f"Error getting uptime stats: {str(e)}")
            return {}

    def get_all_monitors(self) -> List[Dict[str, Any]]:
        """Get all active monitors with current status."""
        try:
            monitors = []
            for monitor_id, data in self.monitored_urls.items():
                stats = self.get_uptime_stats(monitor_id, hours=24)
                monitors.append({
                    'id': monitor_id,
                    'url': data['url'],
                    'last_status': data['last_status'],
                    'consecutive_failures': data['consecutive_failures'],
                    'uptime_percentage': stats.get('uptime_percentage', 0),
                    'avg_response_time': stats.get('avg_response_time', 0)
                })
            
            return monitors

        except Exception as e:
            logger.error(f"Error getting all monitors: {str(e)}")
            return []

    def remove_monitor(self, monitor_id: str):
        """Remove a URL from monitoring."""
        try:
            if monitor_id in self.monitored_urls:
                del self.monitored_urls[monitor_id]

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('UPDATE uptime_monitors SET active = 0 WHERE id = ?', (monitor_id,))

            conn.commit()
            conn.close()

            logger.info(f"Removed monitor {monitor_id}")

        except Exception as e:
            logger.error(f"Error removing monitor: {str(e)}")


uptime_monitor = UptimeMonitor()
