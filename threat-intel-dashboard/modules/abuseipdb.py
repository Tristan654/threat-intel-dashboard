import requests
from config import (ABUSEIPDB_API_KEY,
    ABUSEIPDB_BASE_URL,
    ABUSEIPDB_MALICIOUS_THRESHOLD,
    ABUSEIPDB_SUSPICIOUS_THRESHOLD,
    REQUEST_TIMEOUT,
    InputType,
    Verdict,)


def _get_headers():
    """ """
    return {'Key' : ABUSEIPDB_API_KEY, 'Accept' : 'application/json'}

def _determine_verdict(score):
    """Score de confiance 0-100"""
    if score >= ABUSEIPDB_MALICIOUS_THRESHOLD:
        return Verdict.MALICIOUS
    if score >= ABUSEIPDB_SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN



def _parse_response(data):
    """"""
    d = data.get("data", {})
    score = d.get("abuseConfidenceScore", 0)

    return {
        "source":            "AbuseIPDB",
        "verdict":           _determine_verdict(score),
        "confidence_score":  score,
        "total_reports":     d.get("totalReports", 0),
        "last_reported_at":  d.get("lastReportedAt"),
        "country_code":      d.get("countryCode"),
        "isp":               d.get("isp"),
        "is_tor":            d.get("isTor", False),
        "is_whitelisted":    d.get("isWhitelisted", False),
        "error":             None,
    }

   
def _error(message):
    return {
        "source":           "AbuseIPDB",
        "verdict":          Verdict.ERROR,
        "confidence_score": None,
        "error":            message,
    }



def query(value, input_type):
    if input_type != InputType.IP:
        return {
            "source":           "AbuseIPDB",
            "verdict":          Verdict.UNSUPPORTED,
            "confidence_score": None,
            "error":            "AbuseIPDB supporte uniquement les IPs.",
        }
    if not ABUSEIPDB_API_KEY:
        return _error("ABUSEIPDB_API_KEY manquante dans .env")

    params = {
        "ipAddress":    value,
        "maxAgeInDays": 90, # report des ip dans 90 dernier jours pas avant 
    }

    try:
        response = requests.get(
            f"{ABUSEIPDB_BASE_URL}/check",
            headers=_get_headers(),
            params=params,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 401:
            return _error("Clé API AbuseIPDB invalide.")
        if response.status_code == 429:
            return _error("Limite journalière atteinte (1000 checks/jour).")
        if response.status_code == 422:
            return _error(f"IP invalide : '{value}'")

        response.raise_for_status()
        return _parse_response(response.json())

    except requests.exceptions.Timeout:
        return _error(f"Timeout après {REQUEST_TIMEOUT} secondes.")
    except requests.exceptions.ConnectionError:
        return _error("Erreur réseau — impossible de joindre AbuseIPDB.")
    except Exception as e:
        return _error(f"Erreur inattendue : {e}")
    return 1