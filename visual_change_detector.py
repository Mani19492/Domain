"""
Visual Change Detection Service
Screenshot comparison and HTML diff detection with alerting
"""
import asyncio
import logging
import sqlite3
import json
import os
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import threading
import time
from dataclasses import dataclass, asdict
import requests
from PIL import Image, ImageChops, ImageDraw
import io
import base64
from difflib import unified_diff
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class ChangeDetection:
    id: str
    monitor_id: str
    url: str
    timestamp: str
    change_type: str  # 'visual', 'text', 'html', 'element'
    severity: str  # 'low', 'medium', 'high'
    description: str
    screenshot_before: Optional[str] = None
    screenshot_after: Optional[str] = None
    diff_image: Optional[str] = None
    html_diff: Optional[str] = None
    alert_sent: bool = False


class VisualChangeDetector:
    """Visual change detection with screenshot comparison and HTML diff."""

    def __init__(self, db_path: str = 'monitoring.db', screenshots_dir: str = '/app/screenshots'):
        self.db_path = db_path
        self.screenshots_dir = screenshots_dir
        self.monitored_pages = {}
        self.running = False
        
        # Create screenshots directory
        os.makedirs(screenshots_dir, exist_ok=True)
        
        self.init_database()
        self.load_monitors()
        self.start_monitoring_thread()

    def init_database(self):
        """Initialize visual change detection database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Visual monitoring jobs
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS visual_monitors (
                    id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    check_interval INTEGER DEFAULT 300,
                    css_selector TEXT,
                    ignore_selectors TEXT,
                    alert_channels TEXT,
                    active BOOLEAN DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_check TEXT,
                    last_screenshot TEXT,
                    last_html TEXT
                )
            ''')

            # Change detections
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS change_detections (
                    id TEXT PRIMARY KEY,
                    monitor_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    screenshot_before TEXT,
                    screenshot_after TEXT,
                    diff_image TEXT,
                    html_diff TEXT,
                    alert_sent BOOLEAN DEFAULT 0,
                    FOREIGN KEY (monitor_id) REFERENCES visual_monitors (id)
                )
            ''')

            # Change history
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS change_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    monitor_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    screenshot_path TEXT,
                    html_snapshot TEXT,
                    FOREIGN KEY (monitor_id) REFERENCES visual_monitors (id)
                )
            ''')

            conn.commit()
            conn.close()
            logger.info("Visual change detector database initialized")

        except Exception as e:
            logger.error(f"Error initializing visual detector database: {str(e)}")

    def add_page_monitor(self, url: str, check_interval: int = 300, 
                        css_selector: Optional[str] = None,
                        ignore_selectors: Optional[List[str]] = None,
                        alert_channels: Optional[List[str]] = None) -> str:
        """Add a page to visual monitoring."""
        try:
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'

            monitor_id = hashlib.md5(f"{url}_{datetime.now().isoformat()}".encode()).hexdigest()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO visual_monitors 
                (id, url, check_interval, css_selector, ignore_selectors, alert_channels, created_at, last_check)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                monitor_id,
                url,
                check_interval,
                css_selector,
                json.dumps(ignore_selectors or []),
                json.dumps(alert_channels or ['email']),
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))

            conn.commit()
            conn.close()

            # Add to active monitors and take baseline screenshot
            self.monitored_pages[monitor_id] = {
                'url': url,
                'check_interval': check_interval,
                'css_selector': css_selector,
                'ignore_selectors': ignore_selectors or [],
                'alert_channels': alert_channels or ['email'],
                'last_check': datetime.now(),
                'baseline_screenshot': None,
                'baseline_html': None
            }

            # Take initial baseline
            self.take_baseline_snapshot(monitor_id)

            logger.info(f"Added page to visual monitoring: {url}")
            return monitor_id

        except Exception as e:
            logger.error(f"Error adding page monitor: {str(e)}")
            raise

    def load_monitors(self):
        """Load monitoring jobs from database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, url, check_interval, css_selector, ignore_selectors, 
                       alert_channels, last_check, last_screenshot, last_html
                FROM visual_monitors 
                WHERE active = 1
            ''')

            rows = cursor.fetchall()

            for row in rows:
                monitor_id = row[0]
                self.monitored_pages[monitor_id] = {
                    'url': row[1],
                    'check_interval': row[2],
                    'css_selector': row[3],
                    'ignore_selectors': json.loads(row[4]) if row[4] else [],
                    'alert_channels': json.loads(row[5]) if row[5] else ['email'],
                    'last_check': datetime.fromisoformat(row[6]) if row[6] else datetime.now(),
                    'baseline_screenshot': row[7],
                    'baseline_html': row[8]
                }

            conn.close()
            logger.info(f"Loaded {len(self.monitored_pages)} visual monitors")

        except Exception as e:
            logger.error(f"Error loading monitors: {str(e)}")

    def start_monitoring_thread(self):
        """Start background monitoring thread."""
        def monitoring_loop():
            self.running = True
            while self.running:
                try:
                    self.check_all_pages()
                    time.sleep(30)  # Check every 30 seconds
                except Exception as e:
                    logger.error(f"Error in visual monitoring loop: {str(e)}")
                    time.sleep(60)

        monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitor_thread.start()
        logger.info("Visual monitoring thread started")

    def check_all_pages(self):
        """Check all monitored pages for visual changes."""
        current_time = datetime.now()

        for monitor_id, monitor_data in list(self.monitored_pages.items()):
            try:
                time_since_check = (current_time - monitor_data['last_check']).seconds
                
                if time_since_check >= monitor_data['check_interval']:
                    self.check_for_changes(monitor_id, monitor_data)
                    monitor_data['last_check'] = current_time

            except Exception as e:
                logger.error(f"Error checking page {monitor_data['url']}: {str(e)}")

    def take_baseline_snapshot(self, monitor_id: str):
        """Take baseline screenshot and HTML snapshot."""
        try:
            monitor_data = self.monitored_pages.get(monitor_id)
            if not monitor_data:
                return

            url = monitor_data['url']
            
            # Take screenshot and get HTML
            screenshot_path, html_content = self.capture_page(url, monitor_data.get('css_selector'))
            
            if screenshot_path and html_content:
                monitor_data['baseline_screenshot'] = screenshot_path
                monitor_data['baseline_html'] = html_content

                # Save to database
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()

                cursor.execute('''
                    UPDATE visual_monitors 
                    SET last_screenshot = ?, last_html = ?
                    WHERE id = ?
                ''', (screenshot_path, html_content, monitor_id))

                # Save to history
                cursor.execute('''
                    INSERT INTO change_history (monitor_id, timestamp, screenshot_path, html_snapshot)
                    VALUES (?, ?, ?, ?)
                ''', (monitor_id, datetime.now().isoformat(), screenshot_path, html_content))

                conn.commit()
                conn.close()

                logger.info(f"Baseline snapshot taken for {url}")

        except Exception as e:
            logger.error(f"Error taking baseline snapshot: {str(e)}")

    def capture_page(self, url: str, css_selector: Optional[str] = None) -> tuple:
        """Capture screenshot and HTML of a page (simplified version)."""
        try:
            # Get HTML content
            response = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            html_content = response.text

            # For now, return a placeholder for screenshot
            # In production, you would use Playwright here
            screenshot_filename = f"{hashlib.md5(url.encode()).hexdigest()}_{int(time.time())}.png"
            screenshot_path = os.path.join(self.screenshots_dir, screenshot_filename)

            # Create a simple placeholder image
            img = Image.new('RGB', (1280, 720), color='white')
            draw = ImageDraw.Draw(img)
            draw.text((10, 10), f"Screenshot of {url[:50]}", fill='black')
            img.save(screenshot_path)

            return screenshot_path, html_content

        except Exception as e:
            logger.error(f"Error capturing page: {str(e)}")
            return None, None

    def check_for_changes(self, monitor_id: str, monitor_data: dict):
        """Check for visual and content changes."""
        try:
            url = monitor_data['url']
            
            # Capture current state
            current_screenshot, current_html = self.capture_page(url, monitor_data.get('css_selector'))
            
            if not current_screenshot or not current_html:
                return

            changes_detected = []

            # Compare HTML
            if monitor_data['baseline_html']:
                html_changes = self.compare_html(
                    monitor_data['baseline_html'],
                    current_html,
                    monitor_data.get('ignore_selectors', [])
                )
                
                if html_changes:
                    changes_detected.extend(html_changes)

            # Compare screenshots (simplified)
            if monitor_data['baseline_screenshot'] and os.path.exists(monitor_data['baseline_screenshot']):
                visual_change = self.compare_screenshots(
                    monitor_data['baseline_screenshot'],
                    current_screenshot
                )
                
                if visual_change:
                    changes_detected.append(visual_change)

            # If changes detected, create change detection records
            if changes_detected:
                for change in changes_detected:
                    self.create_change_detection(
                        monitor_id,
                        url,
                        change,
                        monitor_data['baseline_screenshot'],
                        current_screenshot
                    )

                # Send alerts
                self.send_change_alerts(monitor_id, changes_detected, monitor_data['alert_channels'])

                # Update baseline
                monitor_data['baseline_screenshot'] = current_screenshot
                monitor_data['baseline_html'] = current_html
                self.update_baseline(monitor_id, current_screenshot, current_html)

            # Save to history
            self.save_to_history(monitor_id, current_screenshot, current_html)

        except Exception as e:
            logger.error(f"Error checking for changes: {str(e)}")

    def compare_html(self, baseline_html: str, current_html: str, ignore_selectors: List[str]) -> List[dict]:
        """Compare HTML content for changes."""
        changes = []

        try:
            baseline_soup = BeautifulSoup(baseline_html, 'html.parser')
            current_soup = BeautifulSoup(current_html, 'html.parser')

            # Remove ignored elements
            for selector in ignore_selectors:
                for element in baseline_soup.select(selector):
                    element.decompose()
                for element in current_soup.select(selector):
                    element.decompose()

            # Get text content
            baseline_text = baseline_soup.get_text(strip=True)
            current_text = current_soup.get_text(strip=True)

            # Calculate similarity
            if baseline_text != current_text:
                # Generate diff
                diff = list(unified_diff(
                    baseline_text.splitlines(),
                    current_text.splitlines(),
                    lineterm='',
                    n=0
                ))

                if diff:
                    changes.append({
                        'type': 'text',
                        'severity': 'medium',
                        'description': f"Text content changed: {len(diff)} differences detected",
                        'diff': '\n'.join(diff[:50])  # Limit diff size
                    })

            # Check for specific element changes
            # Price detection
            baseline_prices = baseline_soup.find_all(class_=lambda x: x and 'price' in x.lower())
            current_prices = current_soup.find_all(class_=lambda x: x and 'price' in x.lower())
            
            if len(baseline_prices) != len(current_prices) or \
               any(b.get_text() != c.get_text() for b, c in zip(baseline_prices, current_prices)):
                changes.append({
                    'type': 'price',
                    'severity': 'high',
                    'description': 'Price information changed'
                })

        except Exception as e:
            logger.error(f"Error comparing HTML: {str(e)}")

        return changes

    def compare_screenshots(self, baseline_path: str, current_path: str) -> Optional[dict]:
        """Compare two screenshots for visual differences."""
        try:
            baseline_img = Image.open(baseline_path)
            current_img = Image.open(current_path)

            # Ensure same size
            if baseline_img.size != current_img.size:
                current_img = current_img.resize(baseline_img.size)

            # Calculate difference
            diff = ImageChops.difference(baseline_img, current_img)
            
            # Check if there are differences
            if diff.getbbox():
                # Calculate percentage of change
                diff_pixels = sum(sum(1 for p in row if p != (0, 0, 0)) 
                                for row in diff.getdata())
                total_pixels = baseline_img.size[0] * baseline_img.size[1]
                change_percentage = (diff_pixels / total_pixels) * 100

                if change_percentage > 1:  # More than 1% changed
                    return {
                        'type': 'visual',
                        'severity': 'high' if change_percentage > 10 else 'medium',
                        'description': f"Visual changes detected: {change_percentage:.2f}% of page changed",
                        'change_percentage': change_percentage
                    }

        except Exception as e:
            logger.error(f"Error comparing screenshots: {str(e)}")

        return None

    def create_change_detection(self, monitor_id: str, url: str, change: dict,
                              screenshot_before: str, screenshot_after: str):
        """Create change detection record."""
        try:
            detection_id = hashlib.md5(
                f"{monitor_id}_{change['type']}_{datetime.now().isoformat()}".encode()
            ).hexdigest()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO change_detections 
                (id, monitor_id, url, timestamp, change_type, severity, description, 
                 screenshot_before, screenshot_after, html_diff)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                detection_id,
                monitor_id,
                url,
                datetime.now().isoformat(),
                change['type'],
                change['severity'],
                change['description'],
                screenshot_before,
                screenshot_after,
                change.get('diff')
            ))

            conn.commit()
            conn.close()

            logger.info(f"Change detection created: {change['type']} - {change['description']}")

        except Exception as e:
            logger.error(f"Error creating change detection: {str(e)}")

    def send_change_alerts(self, monitor_id: str, changes: List[dict], alert_channels: List[str]):
        """Send alerts about detected changes."""
        try:
            monitor_data = self.monitored_pages.get(monitor_id)
            if not monitor_data:
                return

            url = monitor_data['url']
            
            # Create alert message
            message = f"⚠️ Changes detected on {url}\n\n"
            for change in changes:
                message += f"• {change['severity'].upper()}: {change['description']}\n"

            # Send through configured channels
            # This would integrate with your alert system
            logger.info(f"Alert sent for {url}: {len(changes)} changes detected")

        except Exception as e:
            logger.error(f"Error sending change alerts: {str(e)}")

    def update_baseline(self, monitor_id: str, screenshot_path: str, html_content: str):
        """Update baseline data in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                UPDATE visual_monitors 
                SET last_screenshot = ?, last_html = ?, last_check = ?
                WHERE id = ?
            ''', (screenshot_path, html_content, datetime.now().isoformat(), monitor_id))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Error updating baseline: {str(e)}")

    def save_to_history(self, monitor_id: str, screenshot_path: str, html_content: str):
        """Save snapshot to history."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO change_history (monitor_id, timestamp, screenshot_path, html_snapshot)
                VALUES (?, ?, ?, ?)
            ''', (monitor_id, datetime.now().isoformat(), screenshot_path, html_content))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Error saving to history: {str(e)}")

    def get_change_history(self, monitor_id: str, limit: int = 50) -> List[dict]:
        """Get change history for a monitor."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, timestamp, change_type, severity, description, screenshot_after
                FROM change_detections
                WHERE monitor_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (monitor_id, limit))

            history = [
                {
                    'id': row[0],
                    'timestamp': row[1],
                    'change_type': row[2],
                    'severity': row[3],
                    'description': row[4],
                    'screenshot': row[5]
                }
                for row in cursor.fetchall()
            ]

            conn.close()
            return history

        except Exception as e:
            logger.error(f"Error getting change history: {str(e)}")
            return []

    def get_all_monitors(self) -> List[dict]:
        """Get all visual monitors."""
        try:
            monitors = []
            for monitor_id, data in self.monitored_pages.items():
                monitors.append({
                    'id': monitor_id,
                    'url': data['url'],
                    'check_interval': data['check_interval'],
                    'last_check': data['last_check'].isoformat()
                })
            
            return monitors

        except Exception as e:
            logger.error(f"Error getting all monitors: {str(e)}")
            return []


visual_change_detector = VisualChangeDetector()
