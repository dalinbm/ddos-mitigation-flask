#!/bin/bash

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
