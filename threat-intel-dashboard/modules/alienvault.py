#----------Import------------
import requests
from config import (
    ALIENVAULT_BASE_URL,
    ALIENVAULT_API_KEY,
    OTX_MALICIOUS_THRESHOLD,
    OTX_SUSPICIOUS_THRESHOLD,
    REQUEST_TIMEOUT,
    InputType,
    Verdict,
)

#-----------Functions------------

def _get_headers():
    return {"X-OTX-API-KEY": ALIENVAULT_API_KEY}

def _build_url(input_type, value, section="general"):
    urls = {
        InputType.IP:     f"{ALIENVAULT_BASE_URL}/indicators/IPv4/{value}/{section}",
        InputType.DOMAIN: f"{ALIENVAULT_BASE_URL}/indicators/domain/{value}/{section}",
        InputType.HASH:   f"{ALIENVAULT_BASE_URL}/indicators/file/{value}/{section}",
    }
    return urls[input_type]

def _determine_verdict(pulse_count):
    if pulse_count >= OTX_MALICIOUS_THRESHOLD:
        return Verdict.MALICIOUS
    if pulse_count >= OTX_SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN

def _extract_pulses(data):
    """Extrait les 5 premiers pulses pour l'affichage"""
    pulses = data.get("pulse_info", {}).get("pulses", [])
    return [
        {
            "name":   p.get("name"),
            "author": p.get("author_name"),
            "tags":   p.get("tags", [])[:5],
        }
        for p in pulses[:5]
    ]

def _parse_response(data, input_type):
    pulse_count = data.get("pulse_info", {}).get("count", 0)
    return {
        "source":       "AlienVault OTX",
        "verdict":      _determine_verdict(pulse_count),
        "pulse_count":  pulse_count,
        "pulses":       _extract_pulses(data),
        "country":      data.get("country_name"),
        "city":         data.get("city"),
        "asn":          data.get("asn"),
        "whitelisted":  data.get("whitelisted", False),
        "error":        None,
    }

def _error(input_type, message):
    return {
        "source":      "AlienVault OTX",
        "verdict":     Verdict.ERROR,
        "pulse_count": None,
        "pulses":      [],
        "error":       message,
    }

def query_otx(value, input_type):
    if not ALIENVAULT_API_KEY:
        return _error(input_type, "ALIENVAULT_API_KEY manquante dans .env")

    try:
        url = _build_url(input_type, value)
        response = requests.get(
            url,
            headers=_get_headers(),
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 400:
            return _error(input_type, "Indicateur invalide.")
        if response.status_code == 401:
            return _error(input_type, "Clé API OTX invalide.")

        response.raise_for_status()
        return _parse_response(response.json(), input_type)

    except requests.exceptions.Timeout:
        return _error(input_type, f"Timeout après {REQUEST_TIMEOUT} secondes.")
    except requests.exceptions.ConnectionError:
        return _error(input_type, "Erreur réseau — impossible de joindre OTX.")
    except Exception as e:
        return _error(input_type, f"Erreur inattendue : {e}")