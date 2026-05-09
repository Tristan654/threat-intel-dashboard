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

def _get_header():
    return {"X-OTX-API-KEY": ALIENVAULT_API_KEY}

def _build_url(input_type, value):
    urls = {Verdict.IP : f"{ALIENVAULT_BASE_URL}/indicators/IPv4/" }#flemmme de faire les 2 autre
    return urls[input_type]


def _error():
    return {"source" : "OTX", "verdict" : Verdict.ERROR}

def _determine_verdict(score):
    if score >= OTX_MALICIOUS_THRESHOLD:
        return Verdict.MALICIOUS
    if score >= OTX_SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN

def _parse_response(value):
    data = value.get("pulse_info",{})
    return {
        "source" : "OTX",
        "count" : data.get("pulse_info",0)
        #flemem apres
    }

def query (input_type,value):
    #flemme 
    return 1 