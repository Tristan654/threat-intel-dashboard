
#----------Import------------
import re
import ipaddress


#---------Constante----------
# Regex pour détecter un hash MD5 (32), SHA-1 (40) ou SHA-256 (64)
HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")#compile → Python lit le pattern une seule fois et le stocke

# Regex pour détecter un nom de domaine
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


#-----------Functions------------

def detect_input_type(value):
    value = value.strip()#rm space (beginning and end)

    # 1.IP 
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    # 2. hash 
    if HASH_PATTERN.match(value):
        return "hash"

    # 3. domain
    if DOMAIN_PATTERN.match(value):
        return "domain"

    raise ValueError(f"Input non reconnu : '{value}'")

def sanitize(value):# rm space and uppercase
    return value.strip().lower()