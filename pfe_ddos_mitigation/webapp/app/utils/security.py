#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de sécurité pour l'application web
"""

from functools import wraps
from flask import current_app, request, abort, g
from flask_login import current_user
import logging
import re
import ipaddress
from datetime import datetime

# Configuration du logger
logger = logging.getLogger(__name__)

def admin_required(f):
    """Décorateur pour restreindre l'accès aux administrateurs"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            logger.warning(f"Tentative d'accès non autorisé à {request.path} par {current_user.username if current_user.is_authenticated else 'utilisateur anonyme'}")
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def log_request():
    """Journalise les requêtes importantes"""
    # Liste des chemins à exclure de la journalisation (pour éviter de surcharger les logs)
    exclude_paths = [
        r'^/static/',
        r'^/favicon\.ico$',
        r'^/dashboard/api/',
        r'^/visualization/api/'
    ]
    
    # Vérification si le chemin doit être exclu
    for pattern in exclude_paths:
        if re.match(pattern, request.path):
            return
    
    # Journalisation de la requête
    ip = request.remote_addr
    method = request.method
    path = request.path
    user = current_user.username if current_user.is_authenticated else 'anonyme'
    
    logger.info(f"Requête: {method} {path} - IP: {ip} - Utilisateur: {user}")

def check_ip_whitelist(ip):
    """Vérifie si une adresse IP est en liste blanche"""
    try:
        # Récupération de la liste blanche
        whitelist_file = current_app.config.get('WHITELIST_FILE')
        
        if not whitelist_file:
            return False
        
        try:
            with open(whitelist_file, 'r') as f:
                whitelist = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split('#', 1)
                        whitelist.append(parts[0].strip())
        except FileNotFoundError:
            logger.warning(f"Fichier de liste blanche non trouvé: {whitelist_file}")
            return False
        
        # Vérification si l'IP est dans la liste blanche
        return ip in whitelist
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de la liste blanche: {str(e)}")
        return False

def check_ip_blacklist(ip):
    """Vérifie si une adresse IP est en liste noire"""
    try:
        # Récupération de la liste noire
        blacklist_file = current_app.config.get('BLACKLIST_FILE')
        
        if not blacklist_file:
            return False
        
        try:
            with open(blacklist_file, 'r') as f:
                blacklist = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split('#', 1)
                        blacklist.append(parts[0].strip())
        except FileNotFoundError:
            logger.warning(f"Fichier de liste noire non trouvé: {blacklist_file}")
            return False
        
        # Vérification si l'IP est dans la liste noire
        return ip in blacklist
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de la liste noire: {str(e)}")
        return False

def validate_ip_address(ip):
    """Valide une adresse IP"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def sanitize_input(input_str):
    """Nettoie une chaîne d'entrée pour éviter les injections"""
    if not input_str:
        return input_str
    
    # Suppression des caractères dangereux
    sanitized = re.sub(r'[;<>&|]', '', input_str)
    
    return sanitized

def init_app(app):
    """Initialise le module de sécurité"""
    # Enregistrement du hook before_request
    @app.before_request
    def before_request():
        # Journalisation de la requête
        log_request()
        
        # Vérification de l'adresse IP
        ip = request.remote_addr
        
        # Stockage de l'heure de début de la requête
        g.start_time = datetime.now()
        
        # Vérification de la liste noire (sauf pour les ressources statiques)
        if not request.path.startswith('/static/') and check_ip_blacklist(ip):
            logger.warning(f"Tentative d'accès bloquée pour l'IP en liste noire: {ip}")
            abort(403)
    
    # Enregistrement du hook after_request
    @app.after_request
    def after_request(response):
        # Ajout des en-têtes de sécurité
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Calcul du temps de réponse
        if hasattr(g, 'start_time'):
            elapsed = datetime.now() - g.start_time
            response.headers['X-Response-Time'] = f"{elapsed.total_seconds():.6f}s"
        
        return response
    
    # Configuration du gestionnaire d'erreurs 403
    @app.errorhandler(403)
    def forbidden(e):
        return app.render_template('errors/403.html'), 403
    
    # Configuration du gestionnaire d'erreurs 404
    @app.errorhandler(404)
    def not_found(e):
        return app.render_template('errors/404.html'), 404
    
    # Configuration du gestionnaire d'erreurs 500
    @app.errorhandler(500)
    def server_error(e):
        return app.render_template('errors/500.html'), 500
    
    # Ajout des variables globales pour les templates
    @app.context_processor
    def inject_globals():
        return {
            'now': datetime.now()
        }
