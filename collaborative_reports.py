import json
import logging
from typing import Dict, List, Any, Optional
import sqlite3
from datetime import datetime, timedelta
import hashlib
import secrets
from cryptography.fernet import Fernet
from dataclasses import dataclass, asdict
import threading
from flask_socketio import emit, join_room, leave_room

logger = logging.getLogger(__name__)

@dataclass
class ReportAnnotation:
    id: str
    report_id: str
    user_id: str
    user_name: str
    section: str
    content: str
    timestamp: str
    resolved: bool = False

@dataclass
class CollaborativeReport:
    id: str
    domain: str
    title: str
    content: dict
    created_by: str
    created_at: str
    access_token: str
    expires_at: str
    is_public: bool = False
    annotations: List[ReportAnnotation] = None

class CollaborativeReportManager:
    def __init__(self, db_path: str = 'collaborative_reports.db'):
        self.db_path = db_path
        self.active_sessions = {}
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Initialize database
        self.init_database()
    
    def init_database(self):
        """Initialize collaborative reports database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Reports table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS collaborative_reports (
                    id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    access_token TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    is_public BOOLEAN DEFAULT 0,
                    last_modified TEXT
                )
            ''')
            
            # Annotations table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS report_annotations (
                    id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    user_name TEXT NOT NULL,
                    section TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    resolved BOOLEAN DEFAULT 0,
                    FOREIGN KEY (report_id) REFERENCES collaborative_reports (id)
                )
            ''')
            
            # Collaboration sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS collaboration_sessions (
                    id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    user_name TEXT NOT NULL,
                    joined_at TEXT NOT NULL,
                    last_activity TEXT NOT NULL,
                    FOREIGN KEY (report_id) REFERENCES collaborative_reports (id)
                )
            ''')
            
            # Report access log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS report_access_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT NOT NULL,
                    user_id TEXT,
                    access_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    ip_address TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
    
    def create_collaborative_report(self, domain: str, scan_results: dict, created_by: str, title: str = None) -> dict:
        """Create a new collaborative report."""
        try:
            # Generate report ID and access token
            report_id = hashlib.md5(f"{domain}_{datetime.now().isoformat()}_{created_by}".encode()).hexdigest()
            access_token = secrets.token_urlsafe(32)
            
            # Set expiration (30 days from now)
            expires_at = (datetime.now() + timedelta(days=30)).isoformat()
            
            # Prepare report content
            report_content = {
                'scan_results': scan_results,
                'metadata': {
                    'domain': domain,
                    'scan_timestamp': datetime.now().isoformat(),
                    'version': '1.0'
                },
                'sections': {
                    'executive_summary': self.generate_executive_summary(scan_results),
                    'technical_findings': self.extract_technical_findings(scan_results),
                    'recommendations': self.extract_recommendations(scan_results),
                    'appendix': self.generate_appendix(scan_results)
                }
            }
            
            # Encrypt sensitive content
            encrypted_content = self.cipher_suite.encrypt(json.dumps(report_content).encode())
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO collaborative_reports 
                (id, domain, title, content, created_by, created_at, access_token, expires_at, last_modified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                report_id,
                domain,
                title or f"Security Analysis Report - {domain}",
                encrypted_content.decode(),
                created_by,
                datetime.now().isoformat(),
                access_token,
                expires_at,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            # Log access
            self.log_report_access(report_id, created_by, 'create')
            
            return {
                'report_id': report_id,
                'access_token': access_token,
                'share_url': f"/reports/{report_id}?token={access_token}",
                'expires_at': expires_at,
                'title': title or f"Security Analysis Report - {domain}"
            }
            
        except Exception as e:
            logger.error(f"Error creating collaborative report: {str(e)}")
            raise
    
    def get_report(self, report_id: str, access_token: str = None, user_id: str = None) -> Optional[dict]:
        """Get a collaborative report."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Verify access
            cursor.execute('''
                SELECT * FROM collaborative_reports 
                WHERE id = ? AND (access_token = ? OR is_public = 1)
            ''', (report_id, access_token))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            # Check expiration
            expires_at = datetime.fromisoformat(row[7])
            if datetime.now() > expires_at:
                return None
            
            # Decrypt content
            encrypted_content = row[3].encode()
            decrypted_content = self.cipher_suite.decrypt(encrypted_content)
            content = json.loads(decrypted_content.decode())
            
            # Get annotations
            cursor.execute('''
                SELECT * FROM report_annotations 
                WHERE report_id = ? 
                ORDER BY timestamp DESC
            ''', (report_id,))
            
            annotations = []
            for ann_row in cursor.fetchall():
                annotations.append(ReportAnnotation(
                    id=ann_row[0],
                    report_id=ann_row[1],
                    user_id=ann_row[2],
                    user_name=ann_row[3],
                    section=ann_row[4],
                    content=ann_row[5],
                    timestamp=ann_row[6],
                    resolved=bool(ann_row[7])
                ))
            
            conn.close()
            
            # Log access
            if user_id:
                self.log_report_access(report_id, user_id, 'view')
            
            return {
                'id': row[0],
                'domain': row[1],
                'title': row[2],
                'content': content,
                'created_by': row[4],
                'created_at': row[5],
                'expires_at': row[7],
                'is_public': bool(row[8]),
                'annotations': [asdict(ann) for ann in annotations]
            }
            
        except Exception as e:
            logger.error(f"Error getting report: {str(e)}")
            return None
    
    def add_annotation(self, report_id: str, user_id: str, user_name: str, section: str, content: str, access_token: str = None) -> str:
        """Add annotation to a report."""
        try:
            # Verify access to report
            report = self.get_report(report_id, access_token, user_id)
            if not report:
                raise ValueError("Report not found or access denied")
            
            # Generate annotation ID
            annotation_id = hashlib.md5(f"{report_id}_{user_id}_{datetime.now().isoformat()}".encode()).hexdigest()
            
            # Store annotation
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO report_annotations 
                (id, report_id, user_id, user_name, section, content, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                annotation_id,
                report_id,
                user_id,
                user_name,
                section,
                content,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            # Broadcast to active sessions
            self.broadcast_annotation_update(report_id, {
                'type': 'annotation_added',
                'annotation': {
                    'id': annotation_id,
                    'user_name': user_name,
                    'section': section,
                    'content': content,
                    'timestamp': datetime.now().isoformat()
                }
            })
            
            # Log access
            self.log_report_access(report_id, user_id, 'annotate')
            
            return annotation_id
            
        except Exception as e:
            logger.error(f"Error adding annotation: {str(e)}")
            raise
    
    def resolve_annotation(self, annotation_id: str, user_id: str) -> bool:
        """Resolve an annotation."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE report_annotations 
                SET resolved = 1 
                WHERE id = ?
            ''', (annotation_id,))
            
            if cursor.rowcount > 0:
                # Get report ID for broadcasting
                cursor.execute('SELECT report_id FROM report_annotations WHERE id = ?', (annotation_id,))
                report_id = cursor.fetchone()[0]
                
                conn.commit()
                conn.close()
                
                # Broadcast update
                self.broadcast_annotation_update(report_id, {
                    'type': 'annotation_resolved',
                    'annotation_id': annotation_id
                })
                
                return True
            
            conn.close()
            return False
            
        except Exception as e:
            logger.error(f"Error resolving annotation: {str(e)}")
            return False
    
    def join_collaboration_session(self, report_id: str, user_id: str, user_name: str, socket_id: str):
        """Join a collaboration session."""
        try:
            # Store session info
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO collaboration_sessions 
                (id, report_id, user_id, user_name, joined_at, last_activity)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                socket_id,
                report_id,
                user_id,
                user_name,
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            # Add to active sessions
            if report_id not in self.active_sessions:
                self.active_sessions[report_id] = {}
            
            self.active_sessions[report_id][socket_id] = {
                'user_id': user_id,
                'user_name': user_name,
                'joined_at': datetime.now()
            }
            
            # Join socket room
            join_room(f"report_{report_id}")
            
            # Broadcast user joined
            emit('user_joined', {
                'user_name': user_name,
                'timestamp': datetime.now().isoformat()
            }, room=f"report_{report_id}")
            
            logger.info(f"User {user_name} joined collaboration session for report {report_id}")
            
        except Exception as e:
            logger.error(f"Error joining collaboration session: {str(e)}")
    
    def leave_collaboration_session(self, report_id: str, socket_id: str):
        """Leave a collaboration session."""
        try:
            # Remove from active sessions
            if report_id in self.active_sessions and socket_id in self.active_sessions[report_id]:
                user_info = self.active_sessions[report_id][socket_id]
                del self.active_sessions[report_id][socket_id]
                
                # Clean up empty report sessions
                if not self.active_sessions[report_id]:
                    del self.active_sessions[report_id]
                
                # Leave socket room
                leave_room(f"report_{report_id}")
                
                # Broadcast user left
                emit('user_left', {
                    'user_name': user_info['user_name'],
                    'timestamp': datetime.now().isoformat()
                }, room=f"report_{report_id}")
            
            # Remove from database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM collaboration_sessions WHERE id = ?', (socket_id,))
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error leaving collaboration session: {str(e)}")
    
    def broadcast_annotation_update(self, report_id: str, update_data: dict):
        """Broadcast annotation update to all active sessions."""
        try:
            emit('annotation_update', update_data, room=f"report_{report_id}")
        except Exception as e:
            logger.error(f"Error broadcasting annotation update: {str(e)}")
    
    def get_active_collaborators(self, report_id: str) -> List[dict]:
        """Get list of active collaborators for a report."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get active sessions (last activity within 5 minutes)
            cutoff_time = (datetime.now() - timedelta(minutes=5)).isoformat()
            cursor.execute('''
                SELECT user_id, user_name, joined_at, last_activity
                FROM collaboration_sessions 
                WHERE report_id = ? AND last_activity > ?
            ''', (report_id, cutoff_time))
            
            collaborators = []
            for row in cursor.fetchall():
                collaborators.append({
                    'user_id': row[0],
                    'user_name': row[1],
                    'joined_at': row[2],
                    'last_activity': row[3]
                })
            
            conn.close()
            return collaborators
            
        except Exception as e:
            logger.error(f"Error getting active collaborators: {str(e)}")
            return []
    
    def generate_executive_summary(self, scan_results: dict) -> dict:
        """Generate executive summary section."""
        try:
            domain = scan_results.get('domain', 'Unknown')
            authenticity = scan_results.get('authenticity', {})
            threat_analysis = scan_results.get('threat_analysis', {})
            
            summary = {
                'domain_assessed': domain,
                'assessment_date': datetime.now().strftime('%B %d, %Y'),
                'overall_risk_level': self.determine_risk_level(threat_analysis.get('risk_score', 0)),
                'key_findings': [],
                'immediate_actions': []
            }
            
            # Key findings
            if not authenticity.get('is_genuine', True):
                summary['key_findings'].append("Domain authenticity concerns detected")
                summary['immediate_actions'].append("Verify domain legitimacy before interaction")
            
            risk_score = threat_analysis.get('risk_score', 0)
            if risk_score > 70:
                summary['key_findings'].append(f"High threat risk score: {risk_score}/100")
                summary['immediate_actions'].append("Implement immediate security controls")
            
            # Add more findings based on scan results
            recon = scan_results.get('reconnaissance', {})
            if not recon.get('ssl', {}).get('valid', False):
                summary['key_findings'].append("Invalid or missing SSL certificate")
                summary['immediate_actions'].append("Install valid SSL certificate")
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating executive summary: {str(e)}")
            return {}
    
    def extract_technical_findings(self, scan_results: dict) -> dict:
        """Extract technical findings for the report."""
        try:
            findings = {
                'infrastructure': {},
                'security_posture': {},
                'vulnerabilities': {},
                'compliance': {}
            }
            
            recon = scan_results.get('reconnaissance', {})
            
            # Infrastructure findings
            findings['infrastructure'] = {
                'ip_address': recon.get('geolocation', {}).get('ip', 'Unknown'),
                'hosting_provider': recon.get('geolocation', {}).get('isp', 'Unknown'),
                'location': f"{recon.get('geolocation', {}).get('city', 'Unknown')}, {recon.get('geolocation', {}).get('country', 'Unknown')}",
                'subdomains_discovered': len(recon.get('subdomains', [])),
                'open_ports': len(recon.get('open_ports', [])),
                'technologies_detected': len(recon.get('technologies', []))
            }
            
            # Security posture
            ssl_data = recon.get('ssl', {})
            findings['security_posture'] = {
                'ssl_certificate_valid': ssl_data.get('valid', False),
                'ssl_issuer': ssl_data.get('issuer', 'N/A'),
                'security_headers_present': sum(1 for v in recon.get('security_headers', {}).values() if v != 'Not set'),
                'threat_intelligence_flags': len(scan_results.get('threat_analysis', {}).get('rule_based_flags', []))
            }
            
            return findings
            
        except Exception as e:
            logger.error(f"Error extracting technical findings: {str(e)}")
            return {}
    
    def extract_recommendations(self, scan_results: dict) -> List[dict]:
        """Extract recommendations from scan results."""
        try:
            recommendations = []
            
            # From threat analysis
            threat_recs = scan_results.get('threat_analysis', {}).get('recommendations', [])
            for rec in threat_recs:
                recommendations.append({
                    'category': 'Security',
                    'priority': 'High',
                    'recommendation': rec,
                    'implementation_effort': 'Medium'
                })
            
            # From workflow results
            workflows = scan_results.get('workflow_results', {})
            for workflow_name, workflow_data in workflows.items():
                if 'recommendations' in workflow_data:
                    for rec in workflow_data['recommendations']:
                        recommendations.append({
                            'category': workflow_name.replace('_', ' ').title(),
                            'priority': 'Medium',
                            'recommendation': rec,
                            'implementation_effort': 'Low'
                        })
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error extracting recommendations: {str(e)}")
            return []
    
    def generate_appendix(self, scan_results: dict) -> dict:
        """Generate appendix with detailed technical data."""
        try:
            appendix = {
                'raw_dns_records': scan_results.get('reconnaissance', {}).get('dns', []),
                'whois_data': scan_results.get('reconnaissance', {}).get('whois', {}),
                'port_scan_results': scan_results.get('reconnaissance', {}).get('open_ports', []),
                'threat_intelligence_data': scan_results.get('reconnaissance', {}).get('virustotal', {}),
                'scan_metadata': {
                    'scan_timestamp': datetime.now().isoformat(),
                    'scan_duration': 'N/A',
                    'tools_used': ['Custom Reconnaissance Engine', 'AI Threat Predictor', 'Web3 Scanner']
                }
            }
            
            return appendix
            
        except Exception as e:
            logger.error(f"Error generating appendix: {str(e)}")
            return {}
    
    def determine_risk_level(self, risk_score: int) -> str:
        """Determine risk level from score."""
        if risk_score >= 80:
            return 'Critical'
        elif risk_score >= 60:
            return 'High'
        elif risk_score >= 40:
            return 'Medium'
        else:
            return 'Low'
    
    def log_report_access(self, report_id: str, user_id: str, access_type: str, ip_address: str = None):
        """Log report access for audit purposes."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO report_access_log 
                (report_id, user_id, access_type, timestamp, ip_address)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                report_id,
                user_id,
                access_type,
                datetime.now().isoformat(),
                ip_address
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error logging report access: {str(e)}")
    
    def cleanup_expired_reports(self):
        """Clean up expired reports."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Delete expired reports
            cursor.execute('''
                DELETE FROM collaborative_reports 
                WHERE expires_at < ?
            ''', (datetime.now().isoformat(),))
            
            expired_count = cursor.rowcount
            
            # Clean up orphaned annotations
            cursor.execute('''
                DELETE FROM report_annotations 
                WHERE report_id NOT IN (SELECT id FROM collaborative_reports)
            ''')
            
            # Clean up old sessions
            cutoff_time = (datetime.now() - timedelta(hours=24)).isoformat()
            cursor.execute('''
                DELETE FROM collaboration_sessions 
                WHERE last_activity < ?
            ''', (cutoff_time,))
            
            conn.commit()
            conn.close()
            
            if expired_count > 0:
                logger.info(f"Cleaned up {expired_count} expired reports")
            
        except Exception as e:
            logger.error(f"Error cleaning up expired reports: {str(e)}")

# Initialize global collaborative report manager
collaborative_report_manager = CollaborativeReportManager()