# -*- coding: utf-8 -*-
"""
Configuration Flask pour l'application web
"""

import os

# Chemin de base de l'application
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Clé secrète pour la sécurité
SECRET_KEY = 'ee46bbedd377eb642a7e4264fa1ff08a81bb182907d7b00ac3ec1c2b2ad27074'

# Configuration de la base de données
DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'app.db')

# Fichier de configuration
CONFIG_FILE = os.path.join(BASE_DIR, 'config.ini')

# Fichiers de liste blanche/noire
WHITELIST_FILE = '/home/suricata/pfe_ddos_mitigation/whitelist.txt'
BLACKLIST_FILE = '/home/suricata/pfe_ddos_mitigation/blacklist.txt'

# Configuration du serveur
DEBUG = False
TESTING = False

# Configuration de la journalisation
LOG_LEVEL = 'INFO'
LOG_FILE = os.path.join(BASE_DIR, 'logs', 'app.log')

# Configuration de la session
SESSION_TYPE = 'filesystem'
SESSION_PERMANENT = False
PERMANENT_SESSION_LIFETIME = 3600  # 1 heure
