Description
A Python-based threat intelligence aggregation tool that queries multiple public threat databases simultaneously and returns a consolidated maliciousness verdict for a given indicator (IP address, domain name, or file hash).
Built as a portfolio project to demonstrate practical threat intelligence workflows used in SOC environments.


VirusTotal
Tu lui envoies une IP, un domaine ou un fichier. Il le soumet automatiquement à 70+ antivirus en même temps et te dit combien d'entre eux le considèrent comme dangereux. C'est la référence mondiale pour vérifier si quelque chose est malveillant.

AbuseIPDB
Une base de données communautaire où des milliers d'admins système dans le monde signalent les IPs qui les ont attaqués. Tu soumets une IP et tu obtiens un score de 0 à 100 qui représente la probabilité qu'elle soit utilisée pour des attaques.

AlienVault OTX
Une plateforme où des chercheurs en sécurité du monde entier publient des rapports sur des campagnes d'attaque réelles. Tu soumets un indicateur et tu sais s'il est lié à une attaque documentée, par qui, et dans quel contexte.


Features

Submit an IP address, domain name, or file hash (MD5 / SHA-1 / SHA-256)
Queries 3 threat intelligence sources in parallel : VirusTotal, AbuseIPDB, AlienVault OTX
Returns a consolidated verdict : MALICIOUS / SUSPICIOUS / CLEAN
Displays per-source details : detection scores, geolocation, threat campaigns, flagging engines
Lightweight web interface built with Flask


threat-intel-dashboard/
│
├── app.py
├── aggregator.py
├── config.py
├── requirements.txt
├── .env.example
├── .env
│
├── modules/
│   ├── __init__.py
│   ├── virustotal.py
│   ├── abuseipdb.py
│   └── alienvault.py
│
├── utils/
│   ├── __init__.py
│   └── validator.py
│
└── templates/
    ├── index.html
    └── results.html


# 1. Clone the repository
git clone https://github.com/your-username/threat-intel-dashboard.git
cd threat-intel-dashboard

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate  # Windows : venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt


