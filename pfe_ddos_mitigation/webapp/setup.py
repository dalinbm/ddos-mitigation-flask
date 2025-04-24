#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de configuration pour le déploiement en production
"""

import os
import sys
import argparse
import configparser
import logging
import secrets
import getpass
from pathlib import Path

# Configuration du logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_config_file(config_path, config_template_path=None):
    """Crée un fichier de configuration"""
    logger.info(f"Création du fichier de configuration: {config_path}")
    
    config = configparser.ConfigParser()
    
    # Chargement du template si spécifié
    if config_template_path and os.path.exists(config_template_path):
        config.read(config_template_path)
    
    # Configuration Elasticsearch
    if 'elasticsearch' not in config:
        config['elasticsearch'] = {}
    
    es_host = input("Adresse du serveur Elasticsearch [localhost]: ") or "localhost"
    es_port = input("Port du serveur Elasticsearch [9200]: ") or "9200"
    es_index = input("Nom de l'indice Elasticsearch [prediction_ml]: ") or "prediction_ml"
    es_use_auth = input("Utiliser l'authentification pour Elasticsearch? (o/n) [n]: ").lower() == 'o'
    
    config['elasticsearch']['host'] = es_host
    config['elasticsearch']['port'] = es_port
    config['elasticsearch']['index'] = es_index
    config['elasticsearch']['time_range_hours'] = "24"
    
    if es_use_auth:
        es_username = input("Nom d'utilisateur Elasticsearch: ")
        es_password = getpass.getpass("Mot de passe Elasticsearch: ")
        config['elasticsearch']['username'] = es_username
        config['elasticsearch']['password'] = es_password
    
    es_use_ssl = input("Utiliser SSL pour Elasticsearch? (o/n) [n]: ").lower() == 'o'
    config['elasticsearch']['use_ssl'] = str(es_use_ssl).lower()
    
    # Configuration Fortigate
    if 'fortigate' not in config:
        config['fortigate'] = {}
    
    fg_host = input("Adresse du Fortigate [localhost]: ") or "localhost"
    fg_port = input("Port SSH du Fortigate [22]: ") or "22"
    fg_username = input("Nom d'utilisateur Fortigate [admin]: ") or "admin"
    fg_password = getpass.getpass("Mot de passe Fortigate: ")
    fg_use_group = input("Utiliser un groupe d'adresses pour le blocage? (o/n) [n]: ").lower() == 'o'
    
    config['fortigate']['host'] = fg_host
    config['fortigate']['port'] = fg_port
    config['fortigate']['username'] = fg_username
    config['fortigate']['password'] = fg_password
    config['fortigate']['use_group'] = str(fg_use_group).lower()
    
    if fg_use_group:
        fg_group_name = input("Nom du groupe d'adresses Fortigate: ")
        config['fortigate']['group_name'] = fg_group_name
    
    # Configuration du planificateur
    if 'scheduler' not in config:
        config['scheduler'] = {}
    
    scheduler_enabled = input("Activer le planificateur de mitigation automatique? (o/n) [n]: ").lower() == 'o'
    scheduler_interval = input("Intervalle d'exécution du planificateur (en heures) [1]: ") or "1"
    scheduler_dry_run = input("Activer le mode simulation (dry run)? (o/n) [o]: ").lower() != 'n'
    
    config['scheduler']['enabled'] = str(scheduler_enabled).lower()
    config['scheduler']['interval'] = scheduler_interval
    config['scheduler']['unit'] = "hours"
    config['scheduler']['dry_run'] = str(scheduler_dry_run).lower()
    config['scheduler']['start_time'] = "00:00"
    
    # Configuration générale
    if 'general' not in config:
        config['general'] = {}
    
    block_duration = input("Durée de blocage des IP (en heures) [24]: ") or "24"
    whitelist_file = input("Chemin du fichier de liste blanche [/home/ubuntu/pfe_ddos_mitigation/whitelist.txt]: ") or "/home/ubuntu/pfe_ddos_mitigation/whitelist.txt"
    log_level = input("Niveau de journalisation (DEBUG, INFO, WARNING, ERROR, CRITICAL) [INFO]: ") or "INFO"
    
    config['general']['block_duration_hours'] = block_duration
    config['general']['whitelist_file'] = whitelist_file
    config['general']['log_level'] = log_level
    
    # Sauvegarde du fichier de configuration
    with open(config_path, 'w') as f:
        config.write(f)
    
    logger.info(f"Fichier de configuration créé: {config_path}")
    return True

def create_flask_config(app_path):
    """Crée la configuration Flask"""
    logger.info("Création de la configuration Flask")
    
    config_path = os.path.join(app_path, 'config.py')
    
    # Génération d'une clé secrète
    secret_key = secrets.token_hex(32)
    
    # Création du fichier de configuration
    with open(config_path, 'w') as f:
        f.write(f"""# -*- coding: utf-8 -*-
\"\"\"
Configuration Flask pour l'application web
\"\"\"

import os

# Chemin de base de l'application
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Clé secrète pour la sécurité
SECRET_KEY = '{secret_key}'

# Configuration de la base de données
DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'app.db')

# Fichier de configuration
CONFIG_FILE = os.path.join(BASE_DIR, 'config.ini')

# Fichiers de liste blanche/noire
WHITELIST_FILE = '/home/ubuntu/pfe_ddos_mitigation/whitelist.txt'
BLACKLIST_FILE = '/home/ubuntu/pfe_ddos_mitigation/blacklist.txt'

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
""")
    
    logger.info(f"Fichier de configuration Flask créé: {config_path}")
    return True

def create_wsgi_file(app_path):
    """Crée le fichier WSGI pour le déploiement"""
    logger.info("Création du fichier WSGI")
    
    wsgi_path = os.path.join(app_path, 'wsgi.py')
    
    # Création du fichier WSGI
    with open(wsgi_path, 'w') as f:
        f.write("""#!/usr/bin/env python3
# -*- coding: utf-8 -*-

\"\"\"
Fichier WSGI pour le déploiement en production
\"\"\"

import sys
import os

# Ajout du répertoire de l'application au chemin Python
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import de l'application
from run import app as application

if __name__ == '__main__':
    application.run()
""")
    
    # Rendre le fichier exécutable
    os.chmod(wsgi_path, 0o755)
    
    logger.info(f"Fichier WSGI créé: {wsgi_path}")
    return True

def create_systemd_service(app_path, service_name="ddos_mitigation"):
    """Crée un fichier de service systemd"""
    logger.info("Création du fichier de service systemd")
    
    service_path = os.path.join(app_path, f"{service_name}.service")
    
    # Chemin absolu de l'application
    app_abs_path = os.path.abspath(app_path)
    
    # Création du fichier de service
    with open(service_path, 'w') as f:
        f.write(f"""[Unit]
Description=Service de mitigation DDoS
After=network.target

[Service]
User=ubuntu
Group=ubuntu
WorkingDirectory={app_abs_path}
Environment="PATH={app_abs_path}/venv/bin"
ExecStart={app_abs_path}/venv/bin/gunicorn --workers 4 --bind 0.0.0.0:8000 wsgi:application
Restart=always

[Install]
WantedBy=multi-user.target
""")
    
    logger.info(f"Fichier de service systemd créé: {service_path}")
    logger.info(f"Pour installer le service, exécutez:")
    logger.info(f"sudo cp {service_path} /etc/systemd/system/")
    logger.info(f"sudo systemctl daemon-reload")
    logger.info(f"sudo systemctl enable {service_name}")
    logger.info(f"sudo systemctl start {service_name}")
    
    return True

def create_nginx_config(app_path, server_name="localhost"):
    """Crée une configuration Nginx"""
    logger.info("Création de la configuration Nginx")
    
    nginx_path = os.path.join(app_path, "nginx.conf")
    
    # Création du fichier de configuration Nginx
    with open(nginx_path, 'w') as f:
        f.write(f"""server {{
    listen 80;
    server_name {server_name};

    location / {{
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}

    location /static/ {{
        alias {os.path.join(os.path.abspath(app_path), 'app/static/')};
        expires 30d;
    }}
}}
""")
    
    logger.info(f"Fichier de configuration Nginx créé: {nginx_path}")
    logger.info(f"Pour installer la configuration Nginx, exécutez:")
    logger.info(f"sudo cp {nginx_path} /etc/nginx/sites-available/{server_name}")
    logger.info(f"sudo ln -s /etc/nginx/sites-available/{server_name} /etc/nginx/sites-enabled/")
    logger.info(f"sudo nginx -t")
    logger.info(f"sudo systemctl restart nginx")
    
    return True

def create_deployment_script(app_path):
    """Crée un script de déploiement"""
    logger.info("Création du script de déploiement")
    
    script_path = os.path.join(app_path, "deploy.sh")
    
    # Création du script de déploiement
    with open(script_path, 'w') as f:
        f.write("""#!/bin/bash

# Script de déploiement pour l'application de mitigation DDoS

set -e

# Répertoire de l'application
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

# Création de l'environnement virtuel si nécessaire
if [ ! -d "venv" ]; then
    echo "Création de l'environnement virtuel..."
    python3 -m venv venv
fi

# Activation de l'environnement virtuel
source venv/bin/activate

# Installation des dépendances
echo "Installation des dépendances..."
pip install --upgrade pip
pip install -r requirements.txt

# Création des répertoires nécessaires
mkdir -p logs
mkdir -p app/static/uploads

# Vérification de la configuration
if [ ! -f "config.ini" ]; then
    echo "Le fichier config.ini n'existe pas. Exécutez setup.py pour le créer."
    exit 1
fi

# Démarrage de l'application avec Gunicorn
echo "Démarrage de l'application..."
exec gunicorn --workers 4 --bind 0.0.0.0:8000 wsgi:application
""")
    
    # Rendre le script exécutable
    os.chmod(script_path, 0o755)
    
    logger.info(f"Script de déploiement créé: {script_path}")
    return True

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(description="Configuration du déploiement en production")
    parser.add_argument('--app-path', type=str, default=os.getcwd(), help="Chemin de l'application")
    parser.add_argument('--config-template', type=str, help="Chemin du template de configuration")
    parser.add_argument('--server-name', type=str, default="localhost", help="Nom du serveur pour Nginx")
    parser.add_argument('--service-name', type=str, default="ddos_mitigation", help="Nom du service systemd")
    
    args = parser.parse_args()
    
    app_path = args.app_path
    config_template_path = args.config_template
    server_name = args.server_name
    service_name = args.service_name
    
    # Vérification du répertoire de l'application
    if not os.path.isdir(app_path):
        logger.error(f"Le répertoire {app_path} n'existe pas")
        return 1
    
    # Création du fichier de configuration
    config_path = os.path.join(app_path, 'config.ini')
    if not create_config_file(config_path, config_template_path):
        return 1
    
    # Création de la configuration Flask
    if not create_flask_config(app_path):
        return 1
    
    # Création du fichier WSGI
    if not create_wsgi_file(app_path):
        return 1
    
    # Création du fichier de service systemd
    if not create_systemd_service(app_path, service_name):
        return 1
    
    # Création de la configuration Nginx
    if not create_nginx_config(app_path, server_name):
        return 1
    
    # Création du script de déploiement
    if not create_deployment_script(app_path):
        return 1
    
    logger.info("Configuration du déploiement terminée avec succès")
    logger.info("Pour déployer l'application, exécutez:")
    logger.info(f"cd {app_path} && ./deploy.sh")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
