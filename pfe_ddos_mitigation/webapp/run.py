#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Application web pour la gestion de la mitigation DDoS
Point d'entrée de l'application
"""

import os
from app import create_app

# Création de l'application Flask
app = create_app()

if __name__ == '__main__':
    # Exécution de l'application en mode développement
    app.run(host='0.0.0.0', port=5000, debug=True)
