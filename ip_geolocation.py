"""
IP Geolocation Module
Provides geographic location data for IP addresses
"""
import requests
import logging
from typing import Dict, Any, Optional
import socket

logger = logging.getLogger(__name__)


class IPGeolocation:
    """IP geolocation service for mapping IPs to geographic coordinates."""

    def __init__(self):
        self.api_endpoints = [
            'http://ip-api.com/json/',
            'https://ipapi.co/',
            'https://freegeoip.app/json/'
        ]

    def get_location_data(self, domain: str) -> Dict[str, Any]:
        """Get comprehensive geolocation data for a domain's IP."""
        logger.info(f"Getting geolocation data for {domain}")

        result = {
            "ip": None,
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "timezone": None,
            "isp": None,
            "org": None,
            "as": None,
            "success": False,
            "error": None
        }

        try:
            ip = self._resolve_ip(domain)
            if not ip:
                result["error"] = "Could not resolve domain to IP"
                return result

            result["ip"] = ip

            location_data = self._get_location_from_api(ip)
            if location_data:
                result.update(location_data)
                result["success"] = True
            else:
                result["error"] = "Could not retrieve geolocation data"

        except Exception as e:
            logger.error(f"Error getting geolocation: {str(e)}")
            result["error"] = str(e)

        return result

    def _resolve_ip(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address."""
        try:
            ip = socket.gethostbyname(domain)
            logger.info(f"Resolved {domain} to {ip}")
            return ip
        except socket.gaierror as e:
            logger.error(f"Could not resolve {domain}: {str(e)}")
            return None

    def _get_location_from_api(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get location data from geolocation API."""
        for endpoint in self.api_endpoints:
            try:
                if 'ip-api.com' in endpoint:
                    data = self._fetch_ipapi(ip, endpoint)
                elif 'ipapi.co' in endpoint:
                    data = self._fetch_ipapi_co(ip, endpoint)
                elif 'freegeoip' in endpoint:
                    data = self._fetch_freegeoip(ip, endpoint)
                else:
                    continue

                if data:
                    return data

            except Exception as e:
                logger.warning(f"Failed to get location from {endpoint}: {str(e)}")
                continue

        return None

    def _fetch_ipapi(self, ip: str, endpoint: str) -> Optional[Dict[str, Any]]:
        """Fetch data from ip-api.com."""
        try:
            url = f"{endpoint}{ip}"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                data = response.json()

                if data.get('status') == 'success':
                    return {
                        "country": data.get('country'),
                        "country_code": data.get('countryCode'),
                        "region": data.get('regionName'),
                        "city": data.get('city'),
                        "latitude": data.get('lat'),
                        "longitude": data.get('lon'),
                        "timezone": data.get('timezone'),
                        "isp": data.get('isp'),
                        "org": data.get('org'),
                        "as": data.get('as')
                    }
        except Exception as e:
            logger.error(f"Error fetching from ip-api: {str(e)}")

        return None

    def _fetch_ipapi_co(self, ip: str, endpoint: str) -> Optional[Dict[str, Any]]:
        """Fetch data from ipapi.co."""
        try:
            url = f"{endpoint}{ip}/json/"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                data = response.json()

                return {
                    "country": data.get('country_name'),
                    "country_code": data.get('country_code'),
                    "region": data.get('region'),
                    "city": data.get('city'),
                    "latitude": data.get('latitude'),
                    "longitude": data.get('longitude'),
                    "timezone": data.get('timezone'),
                    "isp": data.get('org'),
                    "org": data.get('org'),
                    "as": data.get('asn')
                }
        except Exception as e:
            logger.error(f"Error fetching from ipapi.co: {str(e)}")

        return None

    def _fetch_freegeoip(self, ip: str, endpoint: str) -> Optional[Dict[str, Any]]:
        """Fetch data from freegeoip.app."""
        try:
            url = f"{endpoint}{ip}"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                data = response.json()

                return {
                    "country": data.get('country_name'),
                    "country_code": data.get('country_code'),
                    "region": data.get('region_name'),
                    "city": data.get('city'),
                    "latitude": data.get('latitude'),
                    "longitude": data.get('longitude'),
                    "timezone": data.get('time_zone'),
                    "isp": None,
                    "org": None,
                    "as": None
                }
        except Exception as e:
            logger.error(f"Error fetching from freegeoip: {str(e)}")

        return None

    def get_coordinates(self, domain: str) -> tuple:
        """Get latitude and longitude for a domain."""
        location_data = self.get_location_data(domain)

        if location_data["success"]:
            return (
                location_data.get("latitude", 0),
                location_data.get("longitude", 0)
            )

        return (0, 0)


ip_geolocation = IPGeolocation()
