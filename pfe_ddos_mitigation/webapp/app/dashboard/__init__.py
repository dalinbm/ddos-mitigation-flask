#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de tableau de bord pour l'application web
"""

from flask import Blueprint, render_template, current_app, jsonify, request
from flask_login import login_required
import logging
import json
from datetime import datetime, timedelta
import random  # Pour les données de test

from app.elasticsearch.client import ElasticsearchClient
from app.fortigate.ssh_client import FortigateSSHClient

# Création du blueprint
bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

# Configuration du logger
logger = logging.getLogger(__name__)

@bp.route('/')
@login_required
def index():
    """Page d'accueil du tableau de bord"""
    try:
        # Récupération des statistiques
        stats = get_system_stats()
        
        # Récupération des alertes récentes
        alerts = get_recent_alerts()
        
        # Données pour les graphiques
        attacks_data = get_attack_trends_data()
        
        # Heure actuelle
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return render_template(
            'dashboard/index.html',
            stats=stats,
            alerts=alerts,
            attacks_data=attacks_data,
            current_time=current_time
        )
    except Exception as e:
        logger.error(f"Erreur lors du chargement du tableau de bord: {str(e)}")
        return render_template(
            'dashboard/index.html',
            stats=get_default_stats(),
            alerts=[],
            attacks_data=get_default_attack_trends(),
            current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            error=str(e)
        )

@bp.route('/alerts')
@login_required
def alerts():
    """Page des alertes"""
    try:
        # Récupération des alertes
        all_alerts = get_all_alerts()
        
        return render_template(
            'dashboard/alerts.html',
            alerts=all_alerts
        )
    except Exception as e:
        logger.error(f"Erreur lors du chargement des alertes: {str(e)}")
        return render_template(
            'dashboard/alerts.html',
            alerts=[],
            error=str(e)
        )

@bp.route('/api/dashboard/stats')
@login_required
def api_dashboard_stats():
    """API pour récupérer les statistiques du tableau de bord"""
    try:
        stats = get_system_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des statistiques: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@bp.route('/api/mitigation/run', methods=['POST'])
@login_required
def api_run_mitigation():
    """API pour exécuter la mitigation manuellement"""
    try:
        # Récupération des paramètres de configuration
        config = load_config()
        
        # Connexion à Elasticsearch
        es_client = ElasticsearchClient(
            host=config['elasticsearch']['host'],
            port=config['elasticsearch']['port'],
            index=config['elasticsearch']['index'],
            username=config['elasticsearch'].get('username'),
            password=config['elasticsearch'].get('password'),
            use_ssl=config['elasticsearch'].get('use_ssl', False)
        )
        
        # Récupération des adresses IP malveillantes
        time_range = {"gte": f"now-{config['elasticsearch']['time_range_hours']}h", "lt": "now"}
        malicious_ips = es_client.get_malicious_ips(time_range)
        
        if not malicious_ips:
            return jsonify({
                'success': True,
                'message': 'Aucune adresse IP malveillante détectée.',
                'blocked_count': 0
            })
        
        # Filtrage par liste blanche
        whitelist = load_whitelist()
        filtered_ips = [ip for ip in malicious_ips if ip not in whitelist]
        
        if not filtered_ips:
            return jsonify({
                'success': True,
                'message': 'Toutes les adresses IP détectées sont en liste blanche.',
                'blocked_count': 0
            })
        
        # Mode simulation
        if config['scheduler'].get('dry_run', False):
            return jsonify({
                'success': True,
                'message': f'Mode simulation: {len(filtered_ips)} adresses IP seraient bloquées.',
                'blocked_count': len(filtered_ips),
                'ips': filtered_ips
            })
        
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
        
        # Blocage des adresses IP
        blocked_count = 0
        for ip in filtered_ips:
            if config['fortigate'].get('use_group', False):
                success = fg_client.add_ip_to_group(ip, config['fortigate']['group_name'])
            else:
                success = fg_client.block_ip(ip)
            
            if success:
                blocked_count += 1
        
        # Fermeture de la connexion
        fg_client.disconnect()
        
        return jsonify({
            'success': True,
            'message': f'{blocked_count} adresses IP ont été bloquées avec succès.',
            'blocked_count': blocked_count,
            'total_ips': len(filtered_ips)
        })
    except Exception as e:
        logger.error(f"Erreur lors de l'exécution de la mitigation: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@bp.route('/api/system/test-connections', methods=['POST'])
@login_required
def api_test_connections():
    """API pour tester les connexions à Elasticsearch et Fortigate"""
    try:
        # Récupération des paramètres de configuration
        config = load_config()
        
        # Test de la connexion à Elasticsearch
        es_connected = False
        try:
            es_client = ElasticsearchClient(
                host=config['elasticsearch']['host'],
                port=config['elasticsearch']['port'],
                index=config['elasticsearch']['index'],
                username=config['elasticsearch'].get('username'),
                password=config['elasticsearch'].get('password'),
                use_ssl=config['elasticsearch'].get('use_ssl', False)
            )
            es_connected = es_client.check_connection() and es_client.check_index_exists()
        except Exception as e:
            logger.error(f"Erreur lors du test de connexion à Elasticsearch: {str(e)}")
        
        # Test de la connexion au Fortigate
        fg_connected = False
        try:
            fg_client = FortigateSSHClient(
                host=config['fortigate']['host'],
                username=config['fortigate']['username'],
                password=config['fortigate']['password'],
                port=config['fortigate'].get('port', 22)
            )
            fg_connected = fg_client.connect()
            if fg_connected:
                fg_client.disconnect()
        except Exception as e:
            logger.error(f"Erreur lors du test de connexion au Fortigate: {str(e)}")
        
        return jsonify({
            'success': True,
            'elasticsearch_connected': es_connected,
            'fortigate_connected': fg_connected
        })
    except Exception as e:
        logger.error(f"Erreur lors du test des connexions: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

def get_system_stats():
    """Récupère les statistiques du système"""
    try:
        # Récupération des paramètres de configuration
        config = load_config()
        
        # Connexion à Elasticsearch
        es_connected = False
        attacks_count = 0
        blocked_ips_count = 0
        last_attack_time = 'N/A'
        success_rate = 0
        
        try:
            es_client = ElasticsearchClient(
                host=config['elasticsearch']['host'],
                port=config['elasticsearch']['port'],
                index=config['elasticsearch']['index'],
                username=config['elasticsearch'].get('username'),
                password=config['elasticsearch'].get('password'),
                use_ssl=config['elasticsearch'].get('use_ssl', False)
            )
            es_connected = es_client.check_connection() and es_client.check_index_exists()
            
            if es_connected:
                # Récupération des statistiques
                time_range = {"gte": f"now-{config['elasticsearch']['time_range_hours']}h", "lt": "now"}
                attack_stats = es_client.get_attack_statistics(time_range)
                
                attacks_count = attack_stats['attacks_count']
                last_attack_time = attack_stats['last_attack_time']
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des statistiques Elasticsearch: {str(e)}")
        
        # Connexion au Fortigate
        fg_connected = False
        try:
            fg_client = FortigateSSHClient(
                host=config['fortigate']['host'],
                username=config['fortigate']['username'],
                password=config['fortigate']['password'],
                port=config['fortigate'].get('port', 22)
            )
            fg_connected = fg_client.connect()
            
            if fg_connected:
                # Récupération des adresses IP bloquées
                blocked_ips = fg_client.get_blocked_ips()
                blocked_ips_count = len(blocked_ips)
                
                # Calcul du taux de succès
                if attacks_count > 0:
                    success_rate = int((blocked_ips_count / attacks_count) * 100)
                
                fg_client.disconnect()
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des statistiques Fortigate: {str(e)}")
        
        # Vérification du planificateur
        scheduler_running = config['scheduler'].get('enabled', False)
        
        return {
            'attacks_count': attacks_count,
            'blocked_ips_count': blocked_ips_count,
            'last_attack_time': last_attack_time,
            'success_rate': success_rate,
            'elasticsearch_connected': es_connected,
            'fortigate_connected': fg_connected,
            'scheduler_running': scheduler_running
        }
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des statistiques du système: {str(e)}")
        return get_default_stats()

def get_default_stats():
    """Retourne des statistiques par défaut en cas d'erreur"""
    return {
        'attacks_count': 0,
        'blocked_ips_count': 0,
        'last_attack_time': 'N/A',
        'success_rate': 0,
        'elasticsearch_connected': False,
        'fortigate_connected': False,
        'scheduler_running': False
    }

def get_recent_alerts(limit=5):
    """Récupère les alertes récentes"""
    try:
        # Récupération des paramètres de configuration
        config = load_config()
        
        # Connexion à Elasticsearch
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
                return es_client.get_recent_alerts(limit)
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des alertes récentes: {str(e)}")
        
        return []
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des alertes récentes: {str(e)}")
        return []

def get_all_alerts(limit=100):
    """Récupère toutes les alertes"""
    try:
        # Récupération des paramètres de configuration
        config = load_config()
        
        # Connexion à Elasticsearch
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
                return es_client.get_recent_alerts(limit)
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de toutes les alertes: {str(e)}")
        
        return []
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de toutes les alertes: {str(e)}")
        return []

def get_attack_trends_data():
    """Récupère les données de tendance des attaques"""
    try:
        # Récupération des paramètres de configuration
        config = load_config()
        
        # Connexion à Elasticsearch
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
                # Récupération des tendances pour différentes périodes
                day_data = es_client.get_attack_trends('day')
                week_data = es_client.get_attack_trends('week')
                month_data = es_client.get_attack_trends('month')
                
                # Récupération des adresses IP bloquées
                fg_client = FortigateSSHClient(
                    host=config['fortigate']['host'],
                    username=config['fortigate']['username'],
                    password=config['fortigate']['password'],
                    port=config['fortigate'].get('port', 22)
                )
                
                blocked_data = {'day': [], 'week': [], 'month': []}
                
                if fg_client.connect():
                    blocked_ips = fg_client.get_blocked_ips()
                    fg_client.disconnect()
                    
                    # Génération des données de blocage (approximation)
                    if day_data['labels'] and blocked_ips:
                        blocked_data['day'] = generate_blocked_data(day_data['labels'], day_data['detected'], len(blocked_ips))
                    
                    if week_data['labels'] and blocked_ips:
                        blocked_data['week'] = generate_blocked_data(week_data['labels'], week_data['detected'], len(blocked_ips))
                    
                    if month_data['labels'] and blocked_ips:
                        blocked_data['month'] = generate_blocked_data(month_data['labels'], month_data['detected'], len(blocked_ips))
                
                return {
                    'day': {
                        'labels': day_data['labels'],
                        'detected': day_data['detected'],
                        'blocked': blocked_data['day'] or [0] * len(day_data['labels'])
                    },
                    'week': {
                        'labels': week_data['labels'],
                        'detected': week_data['detected'],
                        'blocked': blocked_data['week'] or [0] * len(week_data['labels'])
                    },
                    'month': {
                        'labels': month_data['labels'],
                        'detected': month_data['detected'],
                        'blocked': blocked_data['month'] or [0] * len(month_data['labels'])
                    }
                }
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des tendances des attaques: {str(e)}")
        
        return get_default_attack_trends()
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des tendances des attaques: {str(e)}")
        return get_default_attack_trends()

def generate_blocked_data(labels, detected, total_blocked):
    """Génère des données de blocage approximatives basées sur les détections"""
    if not detected or sum(detected) == 0:
        return [0] * len(labels)
    
    # Calcul d'un ratio approximatif de blocage
    ratio = total_blocked / sum(detected)
    
    # Génération des données de blocage avec une légère variation aléatoire
    blocked = []
    for count in detected:
        block_count = int(count * ratio * random.uniform(0.8, 1.2))
        blocked.append(min(block_count, count))  # Ne pas bloquer plus que détecté
    
    return blocked

def get_default_attack_trends():
    """Retourne des données de tendance par défaut en cas d'erreur"""
    # Génération de données de test pour les dernières 24 heures
    now = datetime.now()
    day_labels = [(now - timedelta(hours=i)).strftime('%Y-%m-%d %H:00:00') for i in range(24, 0, -1)]
    day_detected = [0] * 24
    day_blocked = [0] * 24
    
    # Génération de données de test pour la dernière semaine
    week_labels = [(now - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(7, 0, -1)]
    week_detected = [0] * 7
    week_blocked = [0] * 7
    
    # Génération de données de test pour le dernier mois
    month_labels = [(now - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(30, 0, -1)]
    month_detected = [0] * 30
    month_blocked = [0] * 30
    
    return {
        'day': {
            'labels': day_labels,
            'detected': day_detected,
            'blocked': day_blocked
        },
        'week': {
            'labels': week_labels,
            'detected': week_detected,
            'blocked': week_blocked
        },
        'month': {
            'labels': month_labels,
            'detected': month_detected,
            'blocked': month_blocked
        }
    }

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
                        whitelist.append(line)
        except FileNotFoundError:
            logger.warning(f"Fichier de liste blanche non trouvé: {whitelist_file}")
        
        return whitelist
    except Exception as e:
        logger.error(f"Erreur lors du chargement de la liste blanche: {str(e)}")
@bp.route('/api/visualization/data')
@login_required
def api_visualization_data():
    """API qui retourne toutes les données de visualisation"""
    try:
        config = load_config()

        es_client = ElasticsearchClient(
            host=config['elasticsearch']['host'],
            port=config['elasticsearch']['port'],
            index=config['elasticsearch']['index'],
            username=config['elasticsearch'].get('username'),
            password=config['elasticsearch'].get('password'),
            use_ssl=config['elasticsearch'].get('use_ssl', False)
        )

        data = {
            "alerts": es_client.get_recent_alerts(10),
            "trends_day": es_client.get_attack_trends("day"),
            "trends_week": es_client.get_attack_trends("week"),
            "trends_month": es_client.get_attack_trends("month"),
            "malicious_ips": es_client.get_malicious_ips()
        }

        return jsonify({
            "success": True,
            "data": data
        })

    except Exception as e:
        logger.error(f"❌ Erreur API /api/visualization/data : {str(e)}")
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


        return []
