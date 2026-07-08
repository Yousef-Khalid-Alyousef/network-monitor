"""
Geolocation lookups for external (public) IP addresses.

Security improvements:
  - Private IPs are filtered before making any network request.
  - Request timeout is enforced (config.GEOLOCATION_TIMEOUT_SECONDS).
  - Response JSON is validated before trusting any fields.
  - Exceptions are caught and logged, never propagated to callers.
"""

import ipaddress
import logging
from typing import Optional

import requests

import config

_log = logging.getLogger("network_monitor.geolocation")


def geolocate_ip(ip: str) -> Optional[dict]:
    """Look up the geographical location of a public IP address.

    Returns a dict with 'country', 'region', 'city', 'isp' keys on success,
    or None if the IP is private, the API call fails, or the response is bad.
    """
    # --- Validate and reject private IPs ---
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        _log.debug("geolocate_ip: not a valid IP address: %r", ip)
        return None

    if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved:
        return None

    # --- Make the API request ---
    url = config.GEOLOCATION_API.format(ip=ip)
    try:
        resp = requests.get(url, timeout=config.GEOLOCATION_TIMEOUT_SECONDS)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        _log.warning("Geolocation request timed out for %s", ip)
        return None
    except requests.exceptions.RequestException as exc:
        _log.warning("Geolocation request failed for %s: %s", ip, exc)
        return None
    except ValueError:
        _log.warning("Geolocation API returned non-JSON for %s", ip)
        return None

    # --- Validate response structure ---
    if not isinstance(data, dict):
        _log.warning("Geolocation API returned unexpected type for %s", ip)
        return None

    if data.get("status") != "success":
        _log.debug("Geolocation API returned non-success for %s: %s", ip, data.get("message"))
        return None

    return {
        "country": str(data.get("country", "Unknown")),
        "region": str(data.get("regionName", "Unknown")),
        "city": str(data.get("city", "Unknown")),
        "isp": str(data.get("isp", "Unknown")),
    }
