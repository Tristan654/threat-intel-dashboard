#----------Import------------
import os
from dotenv import load_dotenv

load_dotenv()#lit et stocke ce qu'il y a dans les fichier .env

# Clés API
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "")

FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret")

# URLs de base des APIs
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL  = "https://api.abuseipdb.com/api/v2"
ALIENVAULT_BASE_URL = "https://otx.alienvault.com/api/v1"

# Seuils VirusTotal
VT_MALICIOUS_THRESHOLD  = 5
VT_SUSPICIOUS_THRESHOLD = 1

# Seuils AbuseIPDB
ABUSEIPDB_MALICIOUS_THRESHOLD  = 50
ABUSEIPDB_SUSPICIOUS_THRESHOLD = 20

# Seuils AlienVault OTX
OTX_MALICIOUS_THRESHOLD  = 3
OTX_SUSPICIOUS_THRESHOLD = 1

# Timeout requêtes HTTP
REQUEST_TIMEOUT = 15

#-----Types d'input------ (juste grouper des constantes pas besoin de constructeur) 
class InputType:
    IP     = "ip"
    DOMAIN = "domain"
    HASH   = "hash"

# -----Verdicts--------
class Verdict:
    MALICIOUS   = "MALICIOUS"
    SUSPICIOUS  = "SUSPICIOUS"
    CLEAN       = "CLEAN"
    ERROR       = "ERROR"
    UNSUPPORTED = "UNSUPPORTED"