"""
Visitor/Access IP Tracking Service
Real-time visitor logging with geolocation
"""
import logging
import sqlite3
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import hashlib
from ip_geolocation import ip_geolocation

logger = logging.getLogger(__name__)


@dataclass
class VisitorLog:
    id: str
    ip_address: str
    user_agent: str
    path: str
    timestamp: str
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    referrer: Optional[str] = None
    method: str = 'GET'


class VisitorTracker:
    """Real-time visitor tracking with IP logging and geolocation."""

    def __init__(self, db_path: str = 'monitoring.db'):
        self.db_path = db_path
        self.ip_cache = {}  # Cache geolocation data
        self.init_database()

    def init_database(self):
        """Initialize visitor tracking database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Visitor logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS visitor_logs (
                    id TEXT PRIMARY KEY,
                    ip_address TEXT NOT NULL,
                    user_agent TEXT,
                    path TEXT NOT NULL,
                    method TEXT DEFAULT 'GET',
                    referrer TEXT,
                    timestamp TEXT NOT NULL,
                    country TEXT,
                    country_code TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL,
                    isp TEXT
                )
            ''')

            # Create indices for faster queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_visitor_logs_timestamp 
                ON visitor_logs(timestamp)
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_visitor_logs_ip 
                ON visitor_logs(ip_address)
            ''')

            # Visitor statistics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS visitor_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL UNIQUE,
                    total_visits INTEGER DEFAULT 0,
                    unique_visitors INTEGER DEFAULT 0,
                    top_countries TEXT,
                    top_paths TEXT
                )
            ''')

            conn.commit()
            conn.close()
            logger.info("Visitor tracker database initialized")

        except Exception as e:
            logger.error(f"Error initializing visitor tracker database: {str(e)}")

    def log_visitor(self, ip_address: str, user_agent: str, path: str, 
                   method: str = 'GET', referrer: Optional[str] = None) -> str:
        """Log a visitor access."""
        try:
            visit_id = hashlib.md5(
                f"{ip_address}_{path}_{datetime.now().isoformat()}".encode()
            ).hexdigest()

            # Get geolocation data
            geo_data = self.get_ip_geolocation(ip_address)

            # Create visitor log
            visitor_log = VisitorLog(
                id=visit_id,
                ip_address=ip_address,
                user_agent=user_agent,
                path=path,
                method=method,
                referrer=referrer,
                timestamp=datetime.now().isoformat(),
                country=geo_data.get('country'),
                city=geo_data.get('city'),
                latitude=geo_data.get('latitude'),
                longitude=geo_data.get('longitude')
            )

            # Save to database
            self.save_visitor_log(visitor_log, geo_data)

            # Update statistics
            self.update_daily_stats()

            logger.info(f"Visitor logged: {ip_address} -> {path}")
            return visit_id

        except Exception as e:
            logger.error(f"Error logging visitor: {str(e)}")
            raise

    def get_ip_geolocation(self, ip_address: str) -> Dict[str, Any]:
        """Get geolocation data for an IP address with caching."""
        try:
            # Check cache first
            if ip_address in self.ip_cache:
                return self.ip_cache[ip_address]

            # Skip private/local IPs
            if ip_address.startswith(('127.', '192.168.', '10.', '172.')) or ip_address == 'localhost':
                return {
                    'country': 'Local',
                    'city': 'Local',
                    'latitude': 0,
                    'longitude': 0
                }

            # Fetch geolocation data
            # Using a simple IP API
            import requests
            response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    geo_data = {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'isp': data.get('isp')
                    }
                    # Cache the result
                    self.ip_cache[ip_address] = geo_data
                    return geo_data

        except Exception as e:
            logger.error(f"Error getting IP geolocation: {str(e)}")

        return {}

    def save_visitor_log(self, visitor_log: VisitorLog, geo_data: Dict[str, Any]):
        """Save visitor log to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO visitor_logs 
                (id, ip_address, user_agent, path, method, referrer, timestamp,
                 country, country_code, city, latitude, longitude, isp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                visitor_log.id,
                visitor_log.ip_address,
                visitor_log.user_agent,
                visitor_log.path,
                visitor_log.method,
                visitor_log.referrer,
                visitor_log.timestamp,
                geo_data.get('country'),
                geo_data.get('country_code'),
                geo_data.get('city'),
                geo_data.get('latitude'),
                geo_data.get('longitude'),
                geo_data.get('isp')
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Error saving visitor log: {str(e)}")

    def update_daily_stats(self):
        """Update daily visitor statistics."""
        try:
            today = datetime.now().date().isoformat()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get today's stats
            cursor.execute('''
                SELECT COUNT(*) as total_visits,
                       COUNT(DISTINCT ip_address) as unique_visitors
                FROM visitor_logs
                WHERE DATE(timestamp) = ?
            ''', (today,))

            total_visits, unique_visitors = cursor.fetchone()

            # Get top countries
            cursor.execute('''
                SELECT country, COUNT(*) as count
                FROM visitor_logs
                WHERE DATE(timestamp) = ? AND country IS NOT NULL
                GROUP BY country
                ORDER BY count DESC
                LIMIT 5
            ''', (today,))

            top_countries = [{'country': row[0], 'count': row[1]} for row in cursor.fetchall()]

            # Get top paths
            cursor.execute('''
                SELECT path, COUNT(*) as count
                FROM visitor_logs
                WHERE DATE(timestamp) = ?
                GROUP BY path
                ORDER BY count DESC
                LIMIT 5
            ''', (today,))

            top_paths = [{'path': row[0], 'count': row[1]} for row in cursor.fetchall()]

            # Update or insert stats
            cursor.execute('''
                INSERT OR REPLACE INTO visitor_stats 
                (date, total_visits, unique_visitors, top_countries, top_paths)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                today,
                total_visits,
                unique_visitors,
                json.dumps(top_countries),
                json.dumps(top_paths)
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Error updating daily stats: {str(e)}")

    def get_recent_visitors(self, limit: int = 100, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent visitor logs."""
        try:
            cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, ip_address, user_agent, path, method, referrer, timestamp,
                       country, city, latitude, longitude
                FROM visitor_logs
                WHERE timestamp > ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (cutoff_time, limit))

            visitors = [
                {
                    'id': row[0],
                    'ip_address': row[1],
                    'user_agent': row[2],
                    'path': row[3],
                    'method': row[4],
                    'referrer': row[5],
                    'timestamp': row[6],
                    'country': row[7],
                    'city': row[8],
                    'latitude': row[9],
                    'longitude': row[10]
                }
                for row in cursor.fetchall()
            ]

            conn.close()
            return visitors

        except Exception as e:
            logger.error(f"Error getting recent visitors: {str(e)}")
            return []

    def get_visitor_statistics(self, days: int = 7) -> Dict[str, Any]:
        """Get visitor statistics for the specified period."""
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).date().isoformat()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Total visits and unique visitors
            cursor.execute('''
                SELECT COUNT(*) as total_visits,
                       COUNT(DISTINCT ip_address) as unique_visitors
                FROM visitor_logs
                WHERE DATE(timestamp) >= ?
            ''', (cutoff_date,))

            total_visits, unique_visitors = cursor.fetchone()

            # Top countries
            cursor.execute('''
                SELECT country, COUNT(*) as count
                FROM visitor_logs
                WHERE DATE(timestamp) >= ? AND country IS NOT NULL
                GROUP BY country
                ORDER BY count DESC
                LIMIT 10
            ''', (cutoff_date,))

            top_countries = [{'country': row[0], 'visits': row[1]} for row in cursor.fetchall()]

            # Top paths
            cursor.execute('''
                SELECT path, COUNT(*) as count
                FROM visitor_logs
                WHERE DATE(timestamp) >= ?
                GROUP BY path
                ORDER BY count DESC
                LIMIT 10
            ''', (cutoff_date,))

            top_paths = [{'path': row[0], 'visits': row[1]} for row in cursor.fetchall()]

            # Visits by day
            cursor.execute('''
                SELECT DATE(timestamp) as date, 
                       COUNT(*) as visits,
                       COUNT(DISTINCT ip_address) as unique
                FROM visitor_logs
                WHERE DATE(timestamp) >= ?
                GROUP BY DATE(timestamp)
                ORDER BY date ASC
            ''', (cutoff_date,))

            visits_by_day = [
                {'date': row[0], 'visits': row[1], 'unique': row[2]}
                for row in cursor.fetchall()
            ]

            # Get map data (locations with visitor counts)
            cursor.execute('''
                SELECT country, city, latitude, longitude, COUNT(*) as visits
                FROM visitor_logs
                WHERE DATE(timestamp) >= ? 
                  AND latitude IS NOT NULL 
                  AND longitude IS NOT NULL
                GROUP BY country, city, latitude, longitude
                ORDER BY visits DESC
            ''', (cutoff_date,))

            map_data = [
                {
                    'country': row[0],
                    'city': row[1],
                    'latitude': row[2],
                    'longitude': row[3],
                    'visits': row[4]
                }
                for row in cursor.fetchall()
            ]

            conn.close()

            return {
                'period_days': days,
                'total_visits': total_visits,
                'unique_visitors': unique_visitors,
                'top_countries': top_countries,
                'top_paths': top_paths,
                'visits_by_day': visits_by_day,
                'map_data': map_data
            }

        except Exception as e:
            logger.error(f"Error getting visitor statistics: {str(e)}")
            return {}

    def get_live_visitor_count(self, minutes: int = 5) -> int:
        """Get count of visitors in the last N minutes."""
        try:
            cutoff_time = (datetime.now() - timedelta(minutes=minutes)).isoformat()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT COUNT(DISTINCT ip_address)
                FROM visitor_logs
                WHERE timestamp > ?
            ''', (cutoff_time,))

            count = cursor.fetchone()[0]
            conn.close()

            return count

        except Exception as e:
            logger.error(f"Error getting live visitor count: {str(e)}")
            return 0

    def get_visitor_map_data(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get visitor data formatted for map visualization."""
        try:
            cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT country, city, latitude, longitude, 
                       COUNT(*) as visits,
                       GROUP_CONCAT(DISTINCT ip_address) as ips
                FROM visitor_logs
                WHERE timestamp > ? 
                  AND latitude IS NOT NULL 
                  AND longitude IS NOT NULL
                GROUP BY country, city, latitude, longitude
                ORDER BY visits DESC
            ''', (cutoff_time,))

            map_data = [
                {
                    'country': row[0],
                    'city': row[1],
                    'lat': row[2],
                    'lng': row[3],
                    'visits': row[4],
                    'ip_count': len(row[5].split(',')) if row[5] else 0
                }
                for row in cursor.fetchall()
            ]

            conn.close()
            return map_data

        except Exception as e:
            logger.error(f"Error getting visitor map data: {str(e)}")
            return []


visitor_tracker = VisitorTracker()
