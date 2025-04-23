#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de gestion des adresses IP pour l'application web
"""

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required
import logging
import json
from datetime import datetime, timedelta
import ipaddress
import random

from app.elasticsearch.client import ElasticsearchClient
from app.fortigate.ssh_client import FortigateSSHClient

# Création du blueprint
bp = Blueprint('ip_management', __name__, url_prefix='/ip')

# Configuration du logger
logger = logging.getLogger(__name__)

@bp.route('/')
@login_required
def index():
    """Page de gestion des adresses IP"""
    try:
        # Récupération des adresses IP bloquées
        blocked_ips = get_blocked_ips()
        
        # Récupération de la liste blanche
        whitelist = get_whitelist()
        
        # Données pour l'historique des blocages
        history_data = get_blocking_history_data()
        
        return render_template(
            'ip_management/index.html',
            blocked_ips=blocked_ips,
            whitelist=whitelist,
            history_data=history_data
        )
    except Exception as e:
        logger.error(f"Erreur lors du chargement de la page de gestion des IP: {str(e)}")
        return render_template(
            'ip_management/index.html',
            blocked_ips=[],
            whitelist=[],
            history_data=get_default_history_data(),
            error=str(e)
        )

@bp.route('/block', methods=['POST'])
@login_required
def block_ip():
    """Bloque une adresse IP manuellement"""
    try:
        ip_address = request.form.get('ip_address')
        block_duration = int(request.form.get('block_duration', 24))
        block_reason = request.form.get('block_reason', 'Manuel')
        
        # Validation de l'adresse IP
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return jsonify({
                'success': False,
                'message': 'Adresse IP invalide.'
            }), 400
        
        # Vérification si l'IP est en liste blanche
        whitelist = load_whitelist()
        if ip_address in whitelist:
            return jsonify({
                'success': False,
                'message': 'Cette adresse IP est en liste blanche et ne peut pas être bloquée.'
            }), 400
        
        # Récupération des paramètres de configuration
        config = load_config()
        
        # Connexion au Fortigate
        fg_client = FortigateSSHClient(
            host=config['fortigate']['host'],
            username=config['fortigate']['username'],
            password=config['fortigate']['password'],
            port=config['fortigate'].get('port', 22)
        )
        
        if not fg_client.connect():
            return jsonify({
                'success': False,
                'message': 'Impossible de se connecter au Fortigate.'
            }), 500
        
        # Blocage de l'adresse IP
        if config['fortigate'].get('use_group', False):
            success = fg_client.add_ip_to_group(ip_address, config['fortigate']['group_name'])
        else:
            success = fg_client.block_ip(ip_address)
        
        # Fermeture de la connexion
        fg_client.disconnect()
        
        if success:
            # Journalisation du blocage
            log_ip_action(ip_address, 'block', 'manual', block_duration)
            
            return jsonify({
                'success': True,
                'message': f'Adresse IP {ip_address} bloquée avec succès.',
                'reset_form': True,
                'reload': True
            })
        else:
            return jsonify({
                'success': False,
                'message': f'Erreur lors du blocage de l\'adresse IP {ip_address}.'
            }), 500
    except Exception as e:
        logger.error(f"Erreur lors du blocage de l'adresse IP: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@bp.route('/add_to_whitelist', methods=['POST'])
@login_required
def add_to_whitelist():
    """Ajoute une adresse IP à la liste blanche"""
    try:
        ip_address = request.form.get('ip_address')
        description = request.form.get('description', '')
        
        # Validation de l'adresse IP
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return jsonify({
                'success': False,
                'message': 'Adresse IP invalide.'
            }), 400
        
        # Récupération des paramètres de configuration
        config = load_config()
        whitelist_file = config['general']['whitelist_file']
        
        # Vérification si l'IP est déjà en liste blanche
        whitelist = load_whitelist()
        if ip_address in whitelist:
            return jsonify({
                'success': False,
                'message': 'Cette adresse IP est déjà en liste blanche.'
            }), 400
        
        # Ajout à la liste blanche
        try:
            with open(whitelist_file, 'a') as f:
                f.write(f"\n{ip_address} # {description} (ajouté le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")
            
            # Journalisation de l'action
            log_ip_action(ip_address, 'whitelist', 'manual')
            
            return jsonify({
                'success': True,
                'message': f'Adresse IP {ip_address} ajoutée à la liste blanche avec succès.',
                'reset_form': True,
                'reload': True
            })
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout à la liste blanche: {str(e)}")
            return jsonify({
                'success': False,
                'message': f'Erreur lors de l\'ajout à la liste blanche: {str(e)}'
            }), 500
    except Exception as e:
        logger.error(f"Erreur lors de l'ajout à la liste blanche: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@bp.route('/api/ip/unblock', methods=['POST'])
@login_required
def api_unblock_ip():
    """API pour débloquer une adresse IP"""
    try:
        data = request.get_json()
        ip_address = data.get('ip_address')
        
        if not ip_address:
            return jsonify({
                'success': False,
                'message': 'Adresse IP non spécifiée.'
            }), 400
        
        # Récupération des paramètres de configuration
        config = load_config()
        
        # Connexion au Fortigate
        fg_client = FortigateSSHClient(
            host=config['fortigate']['host'],
            username=config['fortigate']['username'],
            password=config['fortigate']['password'],
            port=config['fortigate'].get('port', 22)
        )
        
        if not fg_client.connect():
            return jsonify({
                'success': False,
                'message': 'Impossible de se connecter au Fortigate.'
            }), 500
        
        # Déblocage de l'adresse IP
        success = fg_client.unblock_ip(ip_address=ip_address)
        
        # Fermeture de la connexion
        fg_client.disconnect()
        
        if success:
            # Journalisation du déblocage
            log_ip_action(ip_address, 'unblock', 'manual')
            
            return jsonify({
                'success': True,
                'message': f'Adresse IP {ip_address} débloquée avec succès.'
            })
        else:
            return jsonify({
                'success': False,
                'message': f'Erreur lors du déblocage de l\'adresse IP {ip_address}.'
            }), 500
    except Exception as e:
        logger.error(f"Erreur lors du déblocage de l'adresse IP: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@bp.route('/api/ip/whitelist/remove', methods=['POST'])
@login_required
def api_remove_from_whitelist():
    """API pour supprimer une adresse IP de la liste blanche"""
    try:
        data = request.get_json()
        ip_address = data.get('ip_address')
        
        if not ip_address:
            return jsonify({
                'success': False,
                'message': 'Adresse IP non spécifiée.'
            }), 400
        
        # Récupération des paramètres de configuration
        config = load_config()
        whitelist_file = config['general']['whitelist_file']
        
        # Vérification si l'IP est en liste blanche
        whitelist = load_whitelist()
        if ip_address not in whitelist:
            return jsonify({
                'success': False,
                'message': 'Cette adresse IP n\'est pas en liste blanche.'
            }), 400
        
        # Suppression de la liste blanche
        try:
            with open(whitelist_file, 'r') as f:
                lines = f.readlines()
            
            with open(whitelist_file, 'w') as f:
                for line in lines:
                    if not line.strip().startswith(ip_address):
                        f.write(line)
            
            # Journalisation de l'action
            log_ip_action(ip_address, 'whitelist_remove', 'manual')
            
            return jsonify({
                'success': True,
                'message': f'Adresse IP {ip_address} supprimée de la liste blanche avec succès.'
            })
        except Exception as e:
            logger.error(f"Erreur lors de la suppression de la liste blanche: {str(e)}")
            return jsonify({
                'success': False,
                'message': f'Erreur lors de la suppression de la liste blanche: {str(e)}'
            }), 500
    except Exception as e:
        logger.error(f"Erreur lors de la suppression de la liste blanche: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@bp.route('/api/ip/details')
@login_required
def api_ip_details():
    """API pour récupérer les détails d'une adresse IP"""
    try:
        ip_address = request.args.get('ip')
        
        if not ip_address:
            return jsonify({
                'success': False,
                'message': 'Adresse IP non spécifiée.'
            }), 400
        
        # Récupération des détails de l'adresse IP
        details = get_ip_details(ip_address)
        
        return jsonify({
            'success': True,
            'details': details
        })
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des détails de l'adresse IP: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

def get_blocked_ips():
    """Récupère la liste des adresses IP bloquées"""
    try:
        # Récupération des paramètres de configuration
        config = load_config()
        
        # Connexion au Fortigate
        fg_client = FortigateSSHClient(
            host=config['fortigate']['host'],
            username=config['fortigate']['username'],
            password=config['fortigate']['password'],
            port=config['fortigate'].get('port', 22)
        )
        
        if not fg_client.connect():
            logger.error("Impossible de se connecter au Fortigate.")
            return []
        
        # Récupération des adresses IP bloquées
        blocked_ips = fg_client.get_blocked_ips()
        
        # Fermeture de la connexion
        fg_client.disconnect()
        
        # Ajout des informations d'expiration
        for ip in blocked_ips:
            if 'block_date' in ip and ip['block_date'] != 'Inconnu':
                try:
                    block_date = datetime.strptime(ip['block_date'], '%Y-%m-%d %H:%M:%S')
                    duration = config['general'].get('block_duration_hours', 24)
                    expiration = block_date + timedelta(hours=duration)
                    ip['expiration'] = expiration.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    ip['expiration'] = None
            else:
                ip['expiration'] = None
        
        return blocked_ips
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des adresses IP bloquées: {str(e)}")
        return []

def get_whitelist():
    """Récupère la liste blanche avec descriptions"""
    try:
        # Récupération des paramètres de configuration
        config = load_config()
        whitelist_file = config['general']['whitelist_file']
        
        whitelist = []
        try:
            with open(whitelist_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split('#', 1)
                        ip = parts[0].strip()
                        description = parts[1].strip() if len(parts) > 1 else ''
                        
                        whitelist.append({
                            'address': ip,
                            'description': description
                        })
        except FileNotFoundError:
            logger.warning(f"Fichier de liste blanche non trouvé: {whitelist_file}")
        
        return whitelist
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la liste blanche: {str(e)}")
        return []

def get_ip_details(ip_address):
    """Récupère les détails d'une adresse IP"""
    try:
        # Récupération des paramètres de configuration
        config = load_config()
        
        # Informations de base
        details = {
            'address': ip_address,
            'block_date': 'Inconnu',
            'reason': 'Inconnu',
            'expiration': None,
            'attack_history': []
        }
        
        # Récupération des informations de blocage
        try:
            fg_client = FortigateSSHClient(
                host=config['fortigate']['host'],
                username=config['fortigate']['username'],
                password=config['fortigate']['password'],
                port=config['fortigate'].get('port', 22)
            )
            
            if fg_client.connect():
                blocked_ips = fg_client.get_blocked_ips()
                fg_client.disconnect()
                
                for ip in blocked_ips:
                    if ip['address'] == ip_address:
                        details['block_date'] = ip['block_date']
                        details['reason'] = ip.get('reason', 'ml_prediction')
                        
                        # Calcul de l'expiration
                        if details['block_date'] != 'Inconnu':
                            try:
                                block_date = datetime.strptime(details['block_date'], '%Y-%m-%d %H:%M:%S')
                                duration = config['general'].get('block_duration_hours', 24)
                                expiration = block_date + timedelta(hours=duration)
                                details['expiration'] = expiration.strftime('%Y-%m-%d %H:%M:%S')
                            except:
                                details['expiration'] = None
                        
                        break
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des informations de blocage: {str(e)}")
        
        # Récupération de l'historique des attaques
        try:
            es_client = ElasticsearchClient(
                host=config['elasticsearch']['host'],
                port=config['elasticsearch']['port'],
                index=config['elasticsearch']['index'],
                username=config['elasticsearch'].get('username'),
                password=config['elasticsearch'].get('password'),
                use_ssl=config['elasticsearch'].get('use_ssl', False)
            )
            
            if es_client.check_connection():
                # Construction de la requête pour trouver les attaques liées à cette IP
                query = {
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"ml_prediction": 1}},
                                {"term": {"src_ip": ip_address}}
                            ]
                        }
                    },
                    "sort": [
                        {"@timestamp": {"order": "desc"}}
                    ]
                }
                
                try:
                    response = es_client.es.search(
                        index=es_client.index,
                        body=query,
                        size=10
                    )
                    
                    hits = response.get('hits', {}).get('hits', [])
                    
                    for hit in hits:
                        source = hit.get('_source', {})
                        
                        # Conversion du timestamp
                        timestamp = source.get('@timestamp')
                        if timestamp:
                            try:
                                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                                formatted_timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                            except:
                                formatted_timestamp = timestamp
                        else:
                            formatted_timestamp = 'N/A'
                        
                        # Détermination de la sévérité
                        severity = source.get('alert_severity', 'low').lower()
                        
                        # Type d'attaque
                        attack_type = source.get('protocol', 'Unknown')
                        
                        details['attack_history'].append({
                            'timestamp': formatted_timestamp,
                            'type': attack_type,
                            'severity': severity
                        })
                except Exception as e:
                    logger.error(f"Erreur lors de la recherche dans Elasticsearch: {str(e)}")
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'historique des attaques: {str(e)}")
        
        return details
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des détails de l'adresse IP: {str(e)}")
        return {
            'address': ip_address,
            'block_date': 'Inconnu',
            'reason': 'Inconnu',
            'expiration': None,
            'attack_history': []
        }

def get_blocking_history_data():
    """Récupère les données d'historique des blocages"""
    try:
        # Récupération des adresses IP bloquées
        blocked_ips = get_blocked_ips()
        
        # Préparation des données
        day_data = prepare_history_data(blocked_ips, 'day')
        week_data = prepare_history_data(blocked_ips, 'week')
        month_data = prepare_history_data(blocked_ips, 'month')
        
        return {
            'day': day_data,
            'week': week_data,
            'month': month_data,
            'all': {
                'labels': ['Total'],
                'counts': [len(blocked_ips)]
            }
        }
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des données d'historique des blocages: {str(e)}")
        return get_default_history_data()

def prepare_history_data(blocked_ips, period):
    """Prépare les données d'historique pour une période donnée"""
    now = datetime.now()
    
    if period == 'day':
        # Dernières 24 heures par heure
        labels = [(now - timedelta(hours=i)).strftime('%H:00') for i in range(24, 0, -1)]
        counts = [0] * 24
        
        for ip in blocked_ips:
            if 'block_date' in ip and ip['block_date'] != 'Inconnu':
                try:
                    block_date = datetime.strptime(ip['block_date'], '%Y-%m-%d %H:%M:%S')
                    if now - block_date <= timedelta(hours=24):
                        hour_diff = int((now - block_date).total_seconds() / 3600)
                        if 0 <= hour_diff < 24:
                            counts[hour_diff] += 1
                except:
                    pass
    
    elif period == 'week':
        # Dernière semaine par jour
        labels = [(now - timedelta(days=i)).strftime('%d/%m') for i in range(7, 0, -1)]
        counts = [0] * 7
        
        for ip in blocked_ips:
            if 'block_date' in ip and ip['block_date'] != 'Inconnu':
                try:
                    block_date = datetime.strptime(ip['block_date'], '%Y-%m-%d %H:%M:%S')
                    if now - block_date <= timedelta(days=7):
                        day_diff = int((now - block_date).total_seconds() / 86400)
                        if 0 <= day_diff < 7:
                            counts[day_diff] += 1
                except:
                    pass
    
    elif period == 'month':
        # Dernier mois par jour
        labels = [(now - timedelta(days=i)).strftime('%d/%m') for i in range(30, 0, -1)]
        counts = [0] * 30
        
        for ip in blocked_ips:
            if 'block_date' in ip and ip['block_date'] != 'Inconnu':
                try:
                    block_date = datetime.strptime(ip['block_date'], '%Y-%m-%d %H:%M:%S')
                    if now - block_date <= timedelta(days=30):
                        day_diff = int((now - block_date).total_seconds() / 86400)
                        if 0 <= day_diff < 30:
                            counts[day_diff] += 1
                except:
                    pass
    
    return {
        'labels': labels,
        'counts': counts
    }

def get_default_history_data():
    """Retourne des données d'historique par défaut en cas d'erreur"""
    now = datetime.now()
    
    # Dernières 24 heures par heure
    day_labels = [(now - timedelta(hours=i)).strftime('%H:00') for i in range(24, 0, -1)]
    day_counts = [0] * 24
    
    # Dernière semaine par jour
    week_labels = [(now - timedelta(days=i)).strftime('%d/%m') for i in range(7, 0, -1)]
    week_counts = [0] * 7
    
    # Dernier mois par jour
    month_labels = [(now - timedelta(days=i)).strftime('%d/%m') for i in range(30, 0, -1)]
    month_counts = [0] * 30
    
    return {
        'day': {
            'labels': day_labels,
            'counts': day_counts
        },
        'week': {
            'labels': week_labels,
            'counts': week_counts
        },
        'month': {
            'labels': month_labels,
            'counts': month_counts
        },
        'all': {
            'labels': ['Total'],
            'counts': [0]
        }
    }

def log_ip_action(ip_address, action, source, duration=None):
    """Journalise une action sur une adresse IP"""
    log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ip_actions.log')
    
    try:
        with open(log_file, 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            duration_str = f", duration={duration}h" if duration else ""
            f.write(f"{timestamp} | {ip_address} | {action} | {source}{duration_str}\n")
    except Exception as e:
        logger.error(f"Erreur lors de la journalisation de l'action sur l'adresse IP: {str(e)}")

def load_config():
    """Charge la configuration depuis le fichier config.ini"""
    config_file = current_app.config.get('CONFIG_FILE')
    
    # Configuration par défaut
    default_config = {
        'elasticsearch': {
            'host': 'localhost',
            'port': 9200,
            'index': 'prediction_ml',
            'time_range_hours': 24
        },
        'fortigate': {
            'host': 'localhost',
            'port': 22,
            'username': 'admin',
            'password': '',
            'use_group': False
        },
        'scheduler': {
            'enabled': False,
            'interval': 1,
            'unit': 'hours',
            'dry_run': True
        },
        'general': {
            'block_duration_hours': 24,
            'whitelist_file': '/home/ubuntu/pfe_ddos_mitigation/whitelist.txt',
            'log_level': 'INFO'
        }
    }
    
    try:
        import configparser
        config = configparser.ConfigParser()
        config.read(config_file)
        
        # Conversion du fichier INI en dictionnaire
        result = {}
        for section in config.sections():
            result[section] = {}
            for key, value in config[section].items():
                # Conversion des types
                if value.isdigit():
                    result[section][key] = int(value)
                elif value.lower() in ('true', 'false'):
                    result[section][key] = value.lower() == 'true'
                else:
                    result[section][key] = value
        
        # Fusion avec la configuration par défaut
        for section in default_config:
            if section not in result:
                result[section] = default_config[section]
            else:
                for key in default_config[section]:
                    if key not in result[section]:
                        result[section][key] = default_config[section][key]
        
        return result
    except Exception as e:
        logger.error(f"Erreur lors du chargement de la configuration: {str(e)}")
        return default_config

def load_whitelist():
    """Charge la liste blanche depuis le fichier"""
    try:
        config = load_config()
        whitelist_file = config['general']['whitelist_file']
        
        whitelist = []
        try:
            with open(whitelist_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split('#', 1)
                        whitelist.append(parts[0].strip())
        except FileNotFoundError:
            logger.warning(f"Fichier de liste blanche non trouvé: {whitelist_file}")
        
        return whitelist
    except Exception as e:
        logger.error(f"Erreur lors du chargement de la liste blanche: {str(e)}")
        return []
