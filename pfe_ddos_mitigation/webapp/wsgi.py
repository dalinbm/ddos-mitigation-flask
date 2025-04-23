#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fichier WSGI pour le déploiement en production
"""

import sys
import os

# Ajout du répertoire de l'application au chemin Python
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import de l'application
from run import app as application

if __name__ == '__main__':
    application.run()
