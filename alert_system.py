"""
Multi-Channel Alert System
Email, SMS, Discord, Slack, Telegram, and Push notifications
"""
import logging
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional
from datetime import datetime
from config import Config
import json

logger = logging.getLogger(__name__)


class AlertSystem:
    """Multi-channel alert notification system."""

    def __init__(self):
        self.config = Config()
        self.alert_history = []

    def send_alert(self, alert_type: str, message: str, channels: List[str], 
                  data: Optional[Dict[str, Any]] = None):
        """Send alert through multiple channels."""
        try:
            for channel in channels:
                if channel == 'email':
                    self.send_email_alert(alert_type, message, data)
                elif channel == 'sms':
                    self.send_sms_alert(message)
                elif channel == 'discord':
                    self.send_discord_alert(message, data)
                elif channel == 'slack':
                    self.send_slack_alert(message, data)
                elif channel == 'telegram':
                    self.send_telegram_alert(message)
                elif channel == 'webhook':
                    self.send_webhook_alert(alert_type, message, data)
                elif channel == 'push':
                    self.send_push_notification(alert_type, message)

            # Log alert
            self.alert_history.append({
                'timestamp': datetime.now().isoformat(),
                'type': alert_type,
                'message': message,
                'channels': channels
            })

            logger.info(f"Alert sent via {', '.join(channels)}: {alert_type}")

        except Exception as e:
            logger.error(f"Error sending alert: {str(e)}")

    def send_email_alert(self, subject: str, message: str, data: Optional[Dict[str, Any]] = None):
        """Send email alert via SMTP."""
        try:
            if not self.config.SMTP_USERNAME or not self.config.SMTP_PASSWORD:
                logger.warning("Email credentials not configured")
                return

            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[Domain Monitor Alert] {subject}"
            msg['From'] = self.config.SMTP_USERNAME
            msg['To'] = self.config.SMTP_USERNAME  # Send to self

            # Create HTML email
            html_body = f"""
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: #1a1a2e; color: white; padding: 20px; border-radius: 5px; }}
                    .content {{ background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }}
                    .footer {{ color: #666; font-size: 12px; margin-top: 20px; }}
                    .alert-high {{ border-left: 4px solid #dc3545; }}
                    .alert-medium {{ border-left: 4px solid #ffc107; }}
                    .alert-low {{ border-left: 4px solid #28a745; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>🔔 Domain Monitoring Alert</h2>
                    </div>
                    <div class="content">
                        <h3>{subject}</h3>
                        <p>{message}</p>
                    </div>
            """

            if data:
                html_body += "<div class='content'><h4>Details:</h4><ul>"
                for key, value in data.items():
                    html_body += f"<li><strong>{key}:</strong> {value}</li>"
                html_body += "</ul></div>"

            html_body += """
                    <div class="footer">
                        <p>This is an automated alert from your Domain Monitoring System.</p>
                        <p>Timestamp: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
                    </div>
                </div>
            </body>
            </html>
            """

            # Attach HTML part
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)

            # Send email
            with smtplib.SMTP(self.config.SMTP_SERVER, self.config.SMTP_PORT) as server:
                server.starttls()
                server.login(self.config.SMTP_USERNAME, self.config.SMTP_PASSWORD)
                server.send_message(msg)

            logger.info(f"Email alert sent: {subject}")

        except Exception as e:
            logger.error(f"Error sending email alert: {str(e)}")

    def send_sms_alert(self, message: str):
        """Send SMS alert via Twilio."""
        try:
            if not self.config.TWILIO_ACCOUNT_SID or not self.config.TWILIO_AUTH_TOKEN:
                logger.warning("Twilio credentials not configured")
                return

            from twilio.rest import Client

            client = Client(
                self.config.TWILIO_ACCOUNT_SID,
                self.config.TWILIO_AUTH_TOKEN
            )

            # Send SMS
            sms = client.messages.create(
                body=f"[Domain Monitor] {message[:160]}",  # SMS limit
                from_=self.config.TWILIO_PHONE_NUMBER,
                to=self.config.TWILIO_PHONE_NUMBER  # Configure recipient
            )

            logger.info(f"SMS alert sent: {sms.sid}")

        except ImportError:
            logger.error("Twilio library not installed. Install with: pip install twilio")
        except Exception as e:
            logger.error(f"Error sending SMS alert: {str(e)}")

    def send_discord_alert(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Send alert to Discord via webhook."""
        try:
            discord_webhook = self.config.__dict__.get('DISCORD_WEBHOOK_URL')
            if not discord_webhook:
                logger.warning("Discord webhook not configured")
                return

            # Create embed
            embed = {
                "title": "🔔 Domain Monitoring Alert",
                "description": message,
                "color": 0xff0000,  # Red color
                "timestamp": datetime.now().isoformat(),
                "footer": {
                    "text": "Domain Monitoring System"
                }
            }

            if data:
                embed["fields"] = [
                    {"name": key, "value": str(value), "inline": True}
                    for key, value in data.items()
                ]

            payload = {
                "embeds": [embed]
            }

            response = requests.post(
                discord_webhook,
                json=payload,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 204:
                logger.info("Discord alert sent successfully")
            else:
                logger.error(f"Discord alert failed: {response.status_code}")

        except Exception as e:
            logger.error(f"Error sending Discord alert: {str(e)}")

    def send_slack_alert(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Send alert to Slack via webhook."""
        try:
            if not self.config.SLACK_WEBHOOK_URL:
                logger.warning("Slack webhook not configured")
                return

            # Create Slack message
            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🔔 Domain Monitoring Alert"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Alert Message:*\n{message}"
                    }
                }
            ]

            if data:
                fields = [
                    {
                        "type": "mrkdwn",
                        "text": f"*{key}:*\n{value}"
                    }
                    for key, value in data.items()
                ]
                blocks.append({
                    "type": "section",
                    "fields": fields
                })

            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    }
                ]
            })

            payload = {
                "blocks": blocks
            }

            response = requests.post(
                self.config.SLACK_WEBHOOK_URL,
                json=payload,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                logger.info("Slack alert sent successfully")
            else:
                logger.error(f"Slack alert failed: {response.status_code}")

        except Exception as e:
            logger.error(f"Error sending Slack alert: {str(e)}")

    def send_telegram_alert(self, message: str):
        """Send alert to Telegram via bot API."""
        try:
            telegram_bot_token = self.config.__dict__.get('TELEGRAM_BOT_TOKEN')
            telegram_chat_id = self.config.__dict__.get('TELEGRAM_CHAT_ID')

            if not telegram_bot_token or not telegram_chat_id:
                logger.warning("Telegram credentials not configured")
                return

            url = f"https://api.telegram.org/bot{telegram_bot_token}/sendMessage"
            
            payload = {
                "chat_id": telegram_chat_id,
                "text": f"🔔 *Domain Monitoring Alert*\n\n{message}",
                "parse_mode": "Markdown"
            }

            response = requests.post(url, json=payload)

            if response.status_code == 200:
                logger.info("Telegram alert sent successfully")
            else:
                logger.error(f"Telegram alert failed: {response.status_code}")

        except Exception as e:
            logger.error(f"Error sending Telegram alert: {str(e)}")

    def send_webhook_alert(self, alert_type: str, message: str, data: Optional[Dict[str, Any]] = None):
        """Send alert to custom webhook."""
        try:
            webhook_url = self.config.__dict__.get('CUSTOM_WEBHOOK_URL')
            if not webhook_url:
                logger.warning("Custom webhook not configured")
                return

            payload = {
                "alert_type": alert_type,
                "message": message,
                "timestamp": datetime.now().isoformat(),
                "data": data or {}
            }

            response = requests.post(
                webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )

            if response.status_code in [200, 201, 204]:
                logger.info("Webhook alert sent successfully")
            else:
                logger.error(f"Webhook alert failed: {response.status_code}")

        except Exception as e:
            logger.error(f"Error sending webhook alert: {str(e)}")

    def send_push_notification(self, title: str, message: str):
        """Send browser push notification (placeholder)."""
        try:
            # This would integrate with a push notification service
            # like OneSignal, Firebase Cloud Messaging, etc.
            logger.info(f"Push notification: {title} - {message}")
            
            # For now, just log it
            # In production, implement actual push notification service

        except Exception as e:
            logger.error(f"Error sending push notification: {str(e)}")

    def create_alert_for_change_detection(self, url: str, changes: List[dict], channels: List[str]):
        """Create formatted alert for change detection."""
        try:
            subject = f"Changes Detected: {url}"
            
            message = f"Visual/content changes detected on {url}:\n\n"
            for change in changes:
                severity_emoji = {
                    'high': '🔴',
                    'medium': '🟡',
                    'low': '🟢'
                }.get(change.get('severity', 'low'), '⚪')
                
                message += f"{severity_emoji} {change.get('severity', 'unknown').upper()}: {change.get('description', 'No description')}\n"

            data = {
                'URL': url,
                'Changes Count': len(changes),
                'Detected At': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            self.send_alert('Change Detection', subject, channels, data)

        except Exception as e:
            logger.error(f"Error creating change detection alert: {str(e)}")

    def create_alert_for_downtime(self, url: str, duration_seconds: int, channels: List[str]):
        """Create formatted alert for downtime incident."""
        try:
            subject = f"Downtime Alert: {url}"
            
            duration_minutes = duration_seconds // 60
            message = f"⚠️ Downtime detected for {url}\n"
            message += f"Duration: {duration_minutes} minutes ({duration_seconds} seconds)\n"
            message += f"Site is currently unreachable or returning errors."

            data = {
                'URL': url,
                'Duration': f"{duration_minutes} minutes",
                'Started At': (datetime.now() - timedelta(seconds=duration_seconds)).strftime('%Y-%m-%d %H:%M:%S')
            }

            self.send_alert('Downtime', subject, channels, data)

        except Exception as e:
            logger.error(f"Error creating downtime alert: {str(e)}")

    def create_alert_for_uptime_recovery(self, url: str, downtime_duration: int, channels: List[str]):
        """Create formatted alert for uptime recovery."""
        try:
            subject = f"Recovery: {url}"
            
            message = f"✅ Service restored for {url}\n"
            message += f"Total downtime: {downtime_duration // 60} minutes\n"
            message += f"Site is now responding normally."

            data = {
                'URL': url,
                'Downtime Duration': f"{downtime_duration // 60} minutes",
                'Recovered At': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            self.send_alert('Recovery', subject, channels, data)

        except Exception as e:
            logger.error(f"Error creating recovery alert: {str(e)}")


# Initialize global alert system
alert_system = AlertSystem()
