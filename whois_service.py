"""
WHOIS Service Module
Provides comprehensive WHOIS data extraction and parsing
"""
import whois
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import re

logger = logging.getLogger(__name__)


class WhoisService:
    """Service for retrieving and parsing WHOIS information."""

    def __init__(self):
        self.cache = {}
        self.cache_duration = 3600  # 1 hour cache

    def get_whois_data(self, domain: str) -> Dict[str, Any]:
        """Get comprehensive WHOIS data for a domain."""
        logger.info(f"Fetching WHOIS data for {domain}")

        result = {
            "domain": domain,
            "success": False,
            "error": None,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": [],
            "status": [],
            "emails": [],
            "dnssec": None,
            "registrant": {
                "name": None,
                "organization": None,
                "country": None,
                "state": None,
                "city": None
            },
            "admin": {
                "name": None,
                "organization": None,
                "email": None
            },
            "tech": {
                "name": None,
                "organization": None,
                "email": None
            },
            "raw_data": None,
            "age_days": None,
            "days_until_expiration": None
        }

        try:
            # Remove protocol if present
            clean_domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
            
            # Get WHOIS data
            w = whois.whois(clean_domain)
            
            if w:
                # Basic information
                result["registrar"] = w.registrar if hasattr(w, 'registrar') else None
                result["dnssec"] = w.dnssec if hasattr(w, 'dnssec') else None
                
                # Dates
                result["creation_date"] = self._format_date(w.creation_date)
                result["expiration_date"] = self._format_date(w.expiration_date)
                result["updated_date"] = self._format_date(w.updated_date)
                
                # Name servers
                if hasattr(w, 'name_servers') and w.name_servers:
                    result["name_servers"] = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
                
                # Status
                if hasattr(w, 'status'):
                    result["status"] = w.status if isinstance(w.status, list) else [w.status] if w.status else []
                
                # Emails
                if hasattr(w, 'emails'):
                    emails = w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else []
                    result["emails"] = [email for email in emails if email]
                
                # Registrant information
                if hasattr(w, 'name') and w.name:
                    result["registrant"]["name"] = w.name
                if hasattr(w, 'org') and w.org:
                    result["registrant"]["organization"] = w.org
                if hasattr(w, 'country') and w.country:
                    result["registrant"]["country"] = w.country
                if hasattr(w, 'state') and w.state:
                    result["registrant"]["state"] = w.state
                if hasattr(w, 'city') and w.city:
                    result["registrant"]["city"] = w.city
                
                # Calculate domain age
                if result["creation_date"]:
                    creation = self._parse_date(result["creation_date"])
                    if creation:
                        result["age_days"] = (datetime.now() - creation).days
                
                # Calculate days until expiration
                if result["expiration_date"]:
                    expiration = self._parse_date(result["expiration_date"])
                    if expiration:
                        result["days_until_expiration"] = (expiration - datetime.now()).days
                
                # Raw data
                result["raw_data"] = str(w)
                
                result["success"] = True

        except Exception as e:
            logger.error(f"Error fetching WHOIS data: {str(e)}")
            result["error"] = str(e)

        return result

    def _format_date(self, date_value) -> Optional[str]:
        """Format date value to ISO string."""
        try:
            if not date_value:
                return None
            
            # Handle list of dates (take the first one)
            if isinstance(date_value, list):
                date_value = date_value[0] if date_value else None
            
            if isinstance(date_value, datetime):
                return date_value.isoformat()
            
            if isinstance(date_value, str):
                return date_value
            
            return str(date_value) if date_value else None
        except Exception as e:
            logger.error(f"Error formatting date: {str(e)}")
            return None

    def _parse_date(self, date_string: str) -> Optional[datetime]:
        """Parse date string to datetime object."""
        try:
            if not date_string:
                return None
            
            # Try to parse ISO format
            if 'T' in date_string:
                return datetime.fromisoformat(date_string.replace('Z', '+00:00'))
            
            # Try other common formats
            for fmt in ['%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%d-%m-%Y']:
                try:
                    return datetime.strptime(date_string, fmt)
                except ValueError:
                    continue
            
            return None
        except Exception as e:
            logger.error(f"Error parsing date: {str(e)}")
            return None

    def get_domain_history(self, domain: str) -> Dict[str, Any]:
        """Get domain registration history and changes."""
        whois_data = self.get_whois_data(domain)
        
        history = {
            "domain": domain,
            "timeline": [],
            "changes_detected": []
        }
        
        if whois_data["success"]:
            # Add creation event
            if whois_data["creation_date"]:
                history["timeline"].append({
                    "date": whois_data["creation_date"],
                    "event": "Domain Registered",
                    "type": "creation"
                })
            
            # Add update event
            if whois_data["updated_date"]:
                history["timeline"].append({
                    "date": whois_data["updated_date"],
                    "event": "WHOIS Updated",
                    "type": "update"
                })
            
            # Add expiration event
            if whois_data["expiration_date"]:
                history["timeline"].append({
                    "date": whois_data["expiration_date"],
                    "event": "Domain Expires",
                    "type": "expiration"
                })
        
        return history


whois_service = WhoisService()
