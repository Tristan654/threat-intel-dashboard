import requests
from config import (
    VIRUSTOTAL_BASE_URL,
    VIRUSTOTAL_API_KEY,
    VT_MALICIOUS_THRESHOLD,
    VT_SUSPICIOUS_THRESHOLD,
    REQUEST_TIMEOUT,
    InputType,
    Verdict,
)

def _get_headers():
    """Retourne le header d'authentification pour l'API VirusTotal"""
    return {"x-apikey": VIRUSTOTAL_API_KEY}

def _build_url(input_type, value):
    """Construit l'URL selon le type d'input"""
    urls = {
        InputType.IP:     f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{value}",
        InputType.DOMAIN: f"{VIRUSTOTAL_BASE_URL}/domains/{value}",
        InputType.HASH:   f"{VIRUSTOTAL_BASE_URL}/files/{value}",
    }
    return urls[input_type]

def _determine_verdict(malicious, suspicious):
    """Calcule le verdict selon les seuils définis dans config.py"""
    if malicious >= VT_MALICIOUS_THRESHOLD:
        return Verdict.MALICIOUS
    if malicious >= VT_SUSPICIOUS_THRESHOLD or suspicious >= VT_SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN

def _parse_stats(attrs):
    """Extrait les stats de détection depuis les attributs de la réponse"""
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }

def _parse_response(data, input_type):
    """Transforme la réponse brute de l'API en dict standardisé"""
    attrs = data.get("data", {}).get("attributes", {})
    stats = _parse_stats(attrs)

    # Récupère les moteurs qui ont détecté quelque chose de suspect
    engines = attrs.get("last_analysis_results", {})
    flagging_engines = []

    for name, info in engines.items():
        if info.get("category") in ("malicious", "suspicious"):
            flagging_engines.append({
            "engine": name,
            "result": info.get("result")
            })

    flagging_engines = flagging_engines[:10]

    return {
        "source":           "VirusTotal",
        "verdict":          _determine_verdict(stats["malicious"], stats["suspicious"]),
        "malicious":        stats["malicious"],
        "suspicious":       stats["suspicious"],
        "harmless":         stats["harmless"],
        "undetected":       stats["undetected"],
        "total_engines":    sum(stats.values()),
        "flagging_engines": flagging_engines,
        "country":          attrs.get("country"),
        "reputation":       attrs.get("reputation"),
        "error":            None,
    }

def _error(message):
    """Retourne un dict d'erreur standardisé"""
    return {
        "source":  "VirusTotal",
        "verdict": Verdict.ERROR,
        "error":   message,
    }

def query(value, input_type):
    """
    Point d'entrée principal du module.
    Appelle l'API VirusTotal et retourne un dict standardisé.
    """
    if not VIRUSTOTAL_API_KEY:
        return _error("VIRUSTOTAL_API_KEY manquante dans .env")

    try:
        url = _build_url(input_type, value)
        response = requests.get(url, headers=_get_headers(), timeout=REQUEST_TIMEOUT)

        if response.status_code == 404:
            return _error("Ressource non trouvée dans la base VirusTotal.")
        if response.status_code == 429:
            return _error("Limite de requêtes atteinte. Attends 60 secondes.")
        if response.status_code == 401:
            return _error("Clé API VirusTotal invalide.")

        response.raise_for_status()
        return _parse_response(response.json(), input_type)

    except requests.exceptions.Timeout:
        return _error(f"Timeout après {REQUEST_TIMEOUT} secondes.")
    except requests.exceptions.ConnectionError:
        return _error("Erreur réseau — impossible de joindre VirusTotal.")
    except Exception as e:
        return _error(f"Erreur inattendue : {e}")