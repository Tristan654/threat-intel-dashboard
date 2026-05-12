Description

Outil d'agrégation de threat intelligence développé en Python. Il interroge simultanément 3 bases de données publiques de cybersécurité et retourne un verdict consolidé pour un indicateur donné — adresse IP, nom de domaine ou hash de fichier.
Projet portfolio conçu pour reproduire un workflow d'analyse d'IOCs tel qu'il est pratiqué dans un environnement SOC.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Sources de données

VirusTotal — soumet l'indicateur à 70+ moteurs antivirus simultanément et retourne le nombre de détections. Référence mondiale pour évaluer la malveillance d'un fichier, d'une IP ou d'un domaine.
AbuseIPDB — base de données communautaire alimentée par des milliers d'administrateurs système qui signalent les IPs malveillantes. Retourne un score de confiance de 0 à 100. IP uniquement.
AlienVault OTX — plateforme collaborative où des chercheurs en sécurité publient des rapports sur des campagnes d'attaque réelles. Permet de savoir si un indicateur est lié à une attaque documentée et dans quel contexte.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Fonctionnalités

Soumettre une IP, un domaine ou un hash (MD5 / SHA-1 / SHA-256)
Interrogation des 3 sources en parallèle
Verdict consolidé : MALICIOUS / SUSPICIOUS / CLEAN
Détail par source : score de détection, géolocalisation, campagnes associées
Interface web légère avec Flask
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Structure du projet

threat-intel-dashboard/
│
├── app.py               # Serveur Flask — routes et interface web
├── aggregator.py        # Orchestre les 3 modules et calcule le verdict global
├── config.py            # Clés API, URLs de base, seuils de verdict
├── requirements.txt     # Dépendances Python
├── .env                 # Clés API secrètes — ne jamais commiter
├── .env.example         # Template du .env à remplir
│
├── modules/
│   ├── __init__.py      # Rend le dossier importable par Python
│   ├── virustotal.py    # Intégration API VirusTotal
│   ├── abuseipdb.py     # Intégration API AbuseIPDB
│   └── alienvault.py    # Intégration API AlienVault OTX
│
├── utils/
│   ├── __init__.py      # Rend le dossier importable par Python
│   └── validator.py     # Détecte le type d'input : IP / domaine / hash
│
└── templates/
    ├── index.html       # Formulaire de recherche
    └── results.html     # Affichage du rapport

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Installation

# 1. Cloner le repo
git clone https://github.com/ton-username/threat-intel-dashboard.git
cd threat-intel-dashboard

# 2. Créer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Configurer les clés API
touch .env
# Remplir les 3 clés API dans le fichier .env

# 5. Lancer l'application
python3 app.py
# Ouvrir http://localhost:5000 dans le navigateur

