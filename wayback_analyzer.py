"""
Wayback Machine API Integration
Analyzes domain archive history and retrieves snapshots
"""
import requests
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class WaybackAnalyzer:
    """Wayback Machine analyzer for retrieving archived snapshots."""

    def __init__(self):
        self.availability_api = "http://archive.org/wayback/available"
        self.cdx_api = "http://web.archive.org/cdx/search/cdx"
        self.snapshot_base = "http://web.archive.org/web"

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain using Wayback Machine API."""
        logger.info(f"Analyzing Wayback Machine data for {domain}")

        result = {
            "domain": domain,
            "is_archived": False,
            "total_snapshots": 0,
            "first_snapshot": None,
            "last_snapshot": None,
            "closest_snapshot": None,
            "snapshots": [],
            "years_active": [],
            "success": False,
            "error": None
        }

        try:
            url = f"https://{domain}"

            closest = self._get_closest_snapshot(url)
            if closest:
                result["is_archived"] = True
                result["closest_snapshot"] = closest

            snapshots = self._get_all_snapshots(url)
            if snapshots:
                result["snapshots"] = snapshots
                result["total_snapshots"] = len(snapshots)

                if snapshots:
                    result["first_snapshot"] = snapshots[0]
                    result["last_snapshot"] = snapshots[-1]

                years = list(set([s["year"] for s in snapshots]))
                result["years_active"] = sorted(years)

            result["success"] = True

        except Exception as e:
            logger.error(f"Error analyzing Wayback data: {str(e)}")
            result["error"] = str(e)

        return result

    def _get_closest_snapshot(self, url: str) -> Optional[Dict[str, Any]]:
        """Get the closest available snapshot."""
        try:
            response = requests.get(
                self.availability_api,
                params={"url": url},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                archived = data.get("archived_snapshots", {})
                closest = archived.get("closest", {})

                if closest.get("available"):
                    timestamp = closest.get("timestamp", "")
                    return {
                        "available": True,
                        "url": closest.get("url", ""),
                        "timestamp": timestamp,
                        "status": closest.get("status", ""),
                        "date": self._format_timestamp(timestamp)
                    }

        except Exception as e:
            logger.error(f"Error getting closest snapshot: {str(e)}")

        return None

    def _get_all_snapshots(self, url: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all available snapshots with metadata."""
        snapshots = []

        try:
            response = requests.get(
                self.cdx_api,
                params={
                    "url": url,
                    "output": "json",
                    "fl": "timestamp,statuscode,mimetype",
                    "filter": "statuscode:200",
                    "collapse": "timestamp:8",
                    "limit": limit
                },
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()

                if len(data) > 1:
                    for row in data[1:]:
                        if len(row) >= 3:
                            timestamp = row[0]
                            statuscode = row[1]
                            mimetype = row[2]

                            snapshot_url = f"{self.snapshot_base}/{timestamp}/{url}"

                            snapshots.append({
                                "timestamp": timestamp,
                                "url": snapshot_url,
                                "status": statuscode,
                                "mimetype": mimetype,
                                "date": self._format_timestamp(timestamp),
                                "year": timestamp[:4] if len(timestamp) >= 4 else "Unknown",
                                "screenshot_url": f"{self.snapshot_base}/{timestamp}if_/{url}"
                            })

        except Exception as e:
            logger.error(f"Error getting all snapshots: {str(e)}")

        return snapshots

    def _format_timestamp(self, timestamp: str) -> str:
        """Format Wayback timestamp to readable date."""
        try:
            if len(timestamp) >= 14:
                dt = datetime.strptime(timestamp[:14], "%Y%m%d%H%M%S")
                return dt.strftime("%B %d, %Y at %H:%M:%S")
            elif len(timestamp) >= 8:
                dt = datetime.strptime(timestamp[:8], "%Y%m%d")
                return dt.strftime("%B %d, %Y")
        except Exception as e:
            logger.error(f"Error formatting timestamp: {str(e)}")

        return timestamp

    def get_snapshot_years(self, domain: str) -> List[int]:
        """Get all years when snapshots are available."""
        try:
            url = f"https://{domain}"
            response = requests.get(
                self.cdx_api,
                params={
                    "url": url,
                    "output": "json",
                    "fl": "timestamp",
                    "collapse": "timestamp:4"
                },
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                years = []

                for row in data[1:]:
                    if row and len(row[0]) >= 4:
                        year = int(row[0][:4])
                        if year not in years:
                            years.append(year)

                return sorted(years)

        except Exception as e:
            logger.error(f"Error getting snapshot years: {str(e)}")

        return []

    def get_snapshots_by_year(self, domain: str, year: int, limit: int = 20) -> List[Dict[str, Any]]:
        """Get snapshots for a specific year."""
        snapshots = []

        try:
            url = f"https://{domain}"
            from_date = f"{year}0101"
            to_date = f"{year}1231"

            response = requests.get(
                self.cdx_api,
                params={
                    "url": url,
                    "output": "json",
                    "fl": "timestamp,statuscode",
                    "from": from_date,
                    "to": to_date,
                    "filter": "statuscode:200",
                    "collapse": "timestamp:8",
                    "limit": limit
                },
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()

                for row in data[1:]:
                    if len(row) >= 2:
                        timestamp = row[0]
                        snapshot_url = f"{self.snapshot_base}/{timestamp}/{url}"

                        snapshots.append({
                            "timestamp": timestamp,
                            "url": snapshot_url,
                            "date": self._format_timestamp(timestamp),
                            "screenshot_url": f"{self.snapshot_base}/{timestamp}if_/{url}"
                        })

        except Exception as e:
            logger.error(f"Error getting snapshots by year: {str(e)}")

        return snapshots

    def get_statistics(self, domain: str) -> Dict[str, Any]:
        """Get detailed statistics about archived domain."""
        try:
            url = f"https://{domain}"
            response = requests.get(
                self.cdx_api,
                params={
                    "url": url,
                    "output": "json",
                    "fl": "timestamp,statuscode,mimetype",
                    "limit": 10000
                },
                timeout=20
            )

            stats = {
                "total_captures": 0,
                "successful_captures": 0,
                "failed_captures": 0,
                "content_types": {},
                "years": {},
                "first_capture": None,
                "last_capture": None
            }

            if response.status_code == 200:
                data = response.json()

                if len(data) > 1:
                    stats["total_captures"] = len(data) - 1

                    timestamps = []
                    for row in data[1:]:
                        if len(row) >= 3:
                            timestamp = row[0]
                            statuscode = row[1]
                            mimetype = row[2]

                            timestamps.append(timestamp)

                            if statuscode == "200":
                                stats["successful_captures"] += 1
                            else:
                                stats["failed_captures"] += 1

                            stats["content_types"][mimetype] = stats["content_types"].get(mimetype, 0) + 1

                            if len(timestamp) >= 4:
                                year = timestamp[:4]
                                stats["years"][year] = stats["years"].get(year, 0) + 1

                    if timestamps:
                        stats["first_capture"] = self._format_timestamp(min(timestamps))
                        stats["last_capture"] = self._format_timestamp(max(timestamps))

            return stats

        except Exception as e:
            logger.error(f"Error getting statistics: {str(e)}")
            return {}


wayback_analyzer = WaybackAnalyzer()
