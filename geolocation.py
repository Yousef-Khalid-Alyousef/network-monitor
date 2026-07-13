import logging
import os
import requests
import maxminddb
import ipaddress

import config

_log = logging.getLogger("network_monitor.geolocation")

# We use a free, publicly maintained mirror of the MaxMind GeoLite2 City database.
MMDB_URL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb"

_reader = None

def init_geolocation() -> None:
    global _reader
    if not os.path.exists(config.MMDB_FILE):
        _log.info(f"Downloading offline geolocation database to {config.MMDB_FILE}...")
        try:
            response = requests.get(MMDB_URL, stream=True, timeout=30)
            response.raise_for_status()
            with open(config.MMDB_FILE, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            _log.info("Database downloaded successfully.")
        except Exception as e:
            _log.error(f"Failed to download geolocation database: {e}")
            return
            
    try:
        _reader = maxminddb.open_database(config.MMDB_FILE)
    except Exception as e:
        _log.error(f"Failed to open geolocation database: {e}")

def get_location(ip: str) -> str:
    """Returns a string like 'City, Country' or 'Unknown'."""
    try:
        if ipaddress.ip_address(ip).is_private:
            return "Local Network"
    except ValueError:
        return "Invalid IP"

    if not _reader:
        return "Unknown (DB not loaded)"

    try:
        match = _reader.get(ip)
        if not match:
            return "Unknown"
        
        city = match.get("city", {}).get("names", {}).get("en", "Unknown City")
        country = match.get("country", {}).get("names", {}).get("en", "Unknown Country")
        
        if city == "Unknown City":
            return country
        return f"{city}, {country}"
    except Exception:
        return "Unknown Error"
