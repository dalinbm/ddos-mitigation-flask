#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de configuration pour l'application web
"""

from flask import Blueprint, render_template, request, jsonify, current_app, send_file
from flask_login import login_required
import logging
import os
import json
import configparser
from datetime import datetime
import tempfile
import shutil

from app.elasticsearch.client import ElasticsearchClient
from app.fortigate.ssh_client import FortigateSSHClient

# Création du blueprint
bp = Blueprint('config', __name__, url_prefix='/config')

# Configuration du logger
logger = logging.getLogger(__name__)

@bp.route('/')
@login_required
def index():
    """Page de configuration"""
    try:
        # Récupération de la configuration
        config = load_config()
        
        # Récupération des tâches planifiées
        scheduled_jobs = get_scheduled_jobs()
        
        return render_template(
            'config/index.html',
            config=config,
            scheduled_jobs=scheduled_jobs
        )
    except Exception as e:
        logger.error(f"Erreur lors du chargement de la page de configuration: {str(e)}")
        return render_template(
            'config/index.html',
            config=get_default_config(),
            scheduled_jobs=[],
            error=str(e)
        )

@bp.route('/update_elasticsearch', methods=['POST'])
@login_required
def update_elasticsearch():
    """Met à jour la configuration Elasticsearch"""
    try:
        # Récupération des paramètres
        es_host = request.form.get('es_host')
        es_port = request.form.get('es_port')
        es_index = request.form.get('es_index')
        es_use_auth = 'es_use_auth' in request.form
        es_username = request.form.get('es_username', '')
        es_password = request.form.get('es_password', '')
        es_use_ssl = 'es_use_ssl' in request.form
        es_time_range = request.form.get('es_time_range')
        
        # Validation des paramètres
        if not es_host or not es_port or not es_index or not es_time_range:
            return jsonify({
                'success': False,
                'message': 'Tous les champs obligatoires doivent être remplis.'
            }), 400
        
        # Récupération de la configuration actuelle
        config = load_config()
        
        # Mise à jour de la configuration
        config['elasticsearch']['host'] = es_host
        config['elasticsearch']['port'] = int(es_port)
        config['elasticsearch']['index'] = es_index
        config['elasticsearch']['time_range_hours'] = int(es_time_range)
        
        if es_use_auth:
            config['elasticsearch']['username'] = es_username
            config['elasticsearch']['password'] = es_password
        else:
            config['elasticsearch'].pop('username', None)
            config['elasticsearch'].pop('password', None)
        
        config['elasticsearch']['use_ssl'] = es_use_ssl
        
        # Sauvegarde de la configuration
        if save_config(config):
            return jsonify({
                'success': True,
                'message': 'Configuration Elasticsearch mise à jour avec succès.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Erreur lors de la sauvegarde de la configuration.'
            }), 500
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour de la configuration Elasticsearch: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@bp.route('/update_fortigate', methods=['POST'])
@login_required
def update_fortigate():
    """Met à jour la configuration Fortigate"""
    try:
        # Récupération des paramètres
        fg_host = request.form.get('fg_host')
        fg_port = request.form.get('fg_port')
        fg_username = request.form.get('fg_username')
        fg_password = request.form.get('fg_password')
        fg_use_group = 'fg_use_group' in request.form
        fg_group_name = request.form.get('fg_group_name', '')
        
        # Validation des paramètres
        if not fg_host or not fg_port or not fg_username or not fg_password:
            return jsonify({
                'success': False,
                'message': 'Tous les champs obligatoires doivent être remplis.'
            }), 400
        
        if fg_use_group and not fg_group_name:
            return jsonify({
                'success': False,
                'message': 'Le nom du groupe d\'adresses doit être spécifié.'
            }), 400
        
        # Récupération de la configuration actuelle
        config = load_config()
        
        # Mise à jour de la configuration
        config['fortigate']['host'] = fg_host
        config['fortigate']['port'] = int(fg_port)
        config['fortigate']['username'] = fg_username
        config['fortigate']['password'] = fg_password
        config['fortigate']['use_group'] = fg_use_group
        
        if fg_use_group:
            config['fortigate']['group_name'] = fg_group_name
        else:
            config['fortigate'].pop('group_name', None)
        
        # Sauvegarde de la configuration
        if save_config(config):
            return jsonify({
                'success': True,
                'message': 'Configuration Fortigate mise à jour avec succès.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Erreur lors de la sauvegarde de la configuration.'
            }), 500
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour de la configuration Fortigate: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@bp.route('/update_scheduler', methods=['POST'])
@login_required
def update_scheduler():
    """Met à jour la configuration du planificateur"""
    try:
        # Récupération des paramètres
        scheduler_interval = request.form.get('scheduler_interval')
        scheduler_unit = request.form.get('scheduler_unit')
        scheduler_enabled = 'scheduler_enabled' in request.form
        scheduler_start_time = request.form.get('scheduler_start_time')
        scheduler_dry_run = 'scheduler_dry_run' in request.form
        
        # Validation des paramètres
        if not scheduler_interval or not scheduler_unit:
            return jsonify({
                'success': False,
                'message': 'Tous les champs obligatoires doivent être remplis.'
            }), 400
        
        # Récupération de la configuration actuelle
        config = load_config()
        
        # Mise à jour de la configuration
        config['scheduler']['interval'] = int(scheduler_interval)
        config['scheduler']['unit'] = scheduler_unit
        config['scheduler']['enabled'] = scheduler_enabled
        config['scheduler']['start_time'] = scheduler_start_time
        config['scheduler']['dry_run'] = scheduler_dry_run
        
        # Sauvegarde de la configuration
        if save_config(config):
            # Mise à jour des tâches planifiées si nécessaire
            if scheduler_enabled:
                update_scheduled_jobs(config)
            
            return jsonify({
                'success': True,
                'message': 'Configuration du planificateur mise à jour avec succès.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Erreur lors de la sauvegarde de la configuration.'
            }), 500
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour de la configuration du planificateur: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@bp.route('/update_general', methods=['POST'])
@login_required
def update_general():
    """Met à jour la configuration générale"""
    try:
        # Récupération des paramètres
        block_duration = request.form.get('block_duration')
        whitelist_file = request.form.get('whitelist_file')
        log_level = request.form.get('log_level')
        
        # Validation des paramètres
        if not block_duration or not whitelist_file or not log_level:
            return jsonify({
                'success': False,
                'message': 'Tous les champs obligatoires doivent être remplis.'
            }), 400
        
        # Récupération de la configuration actuelle
        config = load_config()
        
        # Mise à jour de la configuration
        config['general']['block_duration_hours'] = int(block_duration)
        config['general']['whitelist_file'] = whitelist_file
        config['general']['log_level'] = log_level
        
        # Sauvegarde de la configuration
        if save_config(config):
            # Mise à jour du niveau de journalisation
            update_log_level(log_level)
            
            return jsonify({
                'success': True,
                'message': 'Configuration générale mise à jour avec succès.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Erreur lors de la sauvegarde de la configuration.'
            }), 500
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour de la configuration générale: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@bp.route('/api/config/test-elasticsearch', methods=['POST'])
@login_required
def api_test_elasticsearch():
    """API pour tester la connexion à Elasticsearch"""
    try:
        data = request.get_json()
        
        host = data.get('host')
        port = data.get('port')
        index = data.get('index')
        use_auth = data.get('use_auth', False)
        username = data.get('username', '')
        password = data.get('password', '')
        use_ssl = data.get('use_ssl', False)
        
        if not host or not port or not index:
            return jsonify({
                'success': False,
                'message': 'Paramètres incomplets.'
            }), 400
        
        # Test de la connexion
        try:
            es_client = ElasticsearchClient(
                host=host,
                port=port,
                index=index,
                username=username if use_auth else None,
                password=password if use_auth else None,
                use_ssl=use_ssl
            )
            
            connection_ok = es_client.check_connection()
            index_exists = es_client.check_index_exists()
            
            if connection_ok and index_exists:
                return jsonify({
                    'success': True,
                    'message': 'Connexion à Elasticsearch réussie et indice trouvé.'
                })
            elif connection_ok:
                return jsonify({
                    'success': False,
                    'message': f'Connexion à Elasticsearch réussie mais l\'indice {index} n\'existe pas.'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Impossible de se connecter à Elasticsearch.'
                })
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Erreur lors du test de connexion: {str(e)}'
            })
    except Exception as e:
        logger.error(f"Erreur lors du test de connexion à Elasticsearch: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@bp.route('/api/config/test-fortigate', methods=['POST'])
@login_required
def api_test_fortigate():
    """API pour tester la connexion au Fortigate"""
    try:
        data = request.get_json()
        
        host = data.get('host')
        port = data.get('port')
        username = data.get('username')
        password = data.get('password')
        
        if not host or not port or not username or not password:
            return jsonify({
                'success': False,
                'message': 'Paramètres incomplets.'
            }), 400
        
        # Test de la connexion
        try:
            fg_client = FortigateSSHClient(
                host=host,
                username=username,
                password=password,
                port=port
            )
            
            if fg_client.connect():
                fg_client.disconnect()
                return jsonify({
                    'success': True,
                    'message': 'Connexion au Fortigate réussie.'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Impossible de se connecter au Fortigate.'
                })
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Erreur lors du test de connexion: {str(e)}'
            })
    except Exception as e:
        logger.error(f"Erreur lors du test de connexion au Fortigate: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@bp.route('/backup_config')
@login_required
def backup_config():
    """Sauvegarde la configuration"""
    try:
        config_file = current_app.config.get('CONFIG_FILE')
        
        if not os.path.exists(config_file):
            return jsonify({
                'success': False,
                'message': 'Fichier de configuration non trouvé.'
            }), 404
        
        # Création d'un fichier temporaire pour la sauvegarde
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        backup_filename = f"config_backup_{timestamp}.ini"
        
        # Envoi du fichier
        return send_file(
            config_file,
            as_attachment=True,
            download_name=backup_filename,
            mimetype='text/plain'
        )
    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde de la configuration: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@bp.route('/restore_config', methods=['POST'])
@login_required
def restore_config():
    """Restaure la configuration"""
    try:
        if 'config_file' not in request.files:
            return jsonify({
                'success': False,
                'message': 'Aucun fichier sélectionné.'
            }), 400
        
        file = request.files['config_file']
        
        if file.filename == '':
            return jsonify({
                'success': False,
                'message': 'Aucun fichier sélectionné.'
            }), 400
        
        # Vérification du format du fichier
        try:
            content = file.read().decode('utf-8')
            file.seek(0)  # Réinitialisation du curseur
            
            config = configparser.ConfigParser()
            config.read_string(content)
            
            # Vérification des sections requises
            required_sections = ['elasticsearch', 'fortigate', 'scheduler', 'general']
            for section in required_sections:
                if section not in config.sections():
                    return jsonify({
                        'success': False,
                        'message': f'Format de fichier invalide: section {section} manquante.'
                    }), 400
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Format de fichier invalide: {str(e)}'
            }), 400
        
        # Sauvegarde de la configuration actuelle
        config_file = current_app.config.get('CONFIG_FILE')
        backup_file = f"{config_file}.bak"
        
        try:
            shutil.copy2(config_file, backup_file)
        except Exception as e:
            logger.warning(f"Impossible de sauvegarder la configuration actuelle: {str(e)}")
        
        # Restauration de la configuration
        try:
            file.save(config_file)
            return jsonify({
                'success': True,
                'message': 'Configuration restaurée avec succès. Veuillez rafraîchir la page pour voir les changements.'
            })
        except Exception as e:
            # Tentative de restauration de la sauvegarde
            try:
                if os.path.exists(backup_file):
                    shutil.copy2(backup_file, config_file)
            except:
                pass
            
            return jsonify({
                'success': False,
                'message': f'Erreur lors de la restauration de la configuration: {str(e)}'
            }), 500
    except Exception as e:
        logger.error(f"Erreur lors de la restauration de la configuration: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@bp.route('/view_logs')
@login_required
def view_logs():
    """Affiche les journaux du système"""
    try:
        # Récupération des journaux
        logs = get_logs()
        
        return render_template(
            'config/logs.html',
            logs=logs
        )
    except Exception as e:
        logger.error(f"Erreur lors de l'affichage des journaux: {str(e)}")
        return render_template(
            'config/logs.html',
            logs=[],
            error=str(e)
        )

@bp.route('/download_logs')
@login_required
def download_logs():
    """Télécharge les journaux du système"""
    try:
        # Récupération des journaux
        logs = get_logs(raw=True)
        
        # Création d'un fichier temporaire
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.log') as temp:
            temp.write(logs)
            temp_path = temp.name
        
        # Envoi du fichier
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=f"ddos_mitigation_logs_{timestamp}.log",
            mimetype='text/plain'
        )
    except Exception as e:
        logger.error(f"Erreur lors du téléchargement des journaux: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@bp.route('/api/scheduler/delete-job', methods=['POST'])
@login_required
def api_delete_job():
    """API pour supprimer une tâche planifiée"""
    try:
        data = request.get_json()
        job_id = data.get('job_id')
        
        if not job_id:
            return jsonify({
                'success': False,
                'message': 'ID de tâche non spécifié.'
            }), 400
        
        # Suppression de la tâche
        if delete_scheduled_job(job_id):
            return jsonify({
                'success': True,
                'message': 'Tâche supprimée avec succès.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Erreur lors de la suppression de la tâche.'
            }), 500
    except Exception as e:
        logger.error(f"Erreur lors de la suppression de la tâche: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

def load_config():
    """Charge la configuration depuis le fichier config.ini"""
    config_file = current_app.config.get('CONFIG_FILE')
    
    # Configuration par défaut
    default_config = get_default_config()
    
    try:
        # Vérification si le fichier existe
        if not os.path.exists(config_file):
            # Création du fichier avec la configuration par défaut
            save_config(default_config)
            return default_config
        
        # Chargement de la configuration
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

def get_default_config():
    """Retourne la configuration par défaut"""
    return {
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
            'dry_run': True,
            'start_time': '00:00'
        },
        'general': {
            'block_duration_hours': 24,
            'whitelist_file': '/home/ubuntu/pfe_ddos_mitigation/whitelist.txt',
            'log_level': 'INFO'
        }
    }

def save_config(config):
    """Sauvegarde la configuration dans le fichier config.ini"""
    config_file = current_app.config.get('CONFIG_FILE')
    
    try:
        # Conversion du dictionnaire en fichier INI
        ini_config = configparser.ConfigParser()
        
        for section, values in config.items():
            ini_config[section] = {}
            for key, value in values.items():
                ini_config[section][key] = str(value)
        
        # Sauvegarde dans le fichier
        with open(config_file, 'w') as f:
            ini_config.write(f)
        
        return True
    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde de la configuration: {str(e)}")
        return False

def get_scheduled_jobs():
    """Récupère les tâches planifiées"""
    # Dans une implémentation réelle, cette fonction récupérerait les tâches
    # planifiées depuis le système de planification (cron, APScheduler, etc.)
    # Pour l'exemple, nous retournons des données fictives
    return [
        {
            'id': '1',
            'next_run': (datetime.now() + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'),
            'interval': '1 heure'
        }
    ]

def update_scheduled_jobs(config):
    """Met à jour les tâches planifiées"""
    # Dans une implémentation réelle, cette fonction mettrait à jour les tâches
    # planifiées dans le système de planification (cron, APScheduler, etc.)
    pass

def delete_scheduled_job(job_id):
    """Supprime une tâche planifiée"""
    # Dans une implémentation réelle, cette fonction supprimerait la tâche
    # planifiée du système de planification (cron, APScheduler, etc.)
    return True

def update_log_level(level):
    """Met à jour le niveau de journalisation"""
    try:
        numeric_level = getattr(logging, level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(f'Niveau de journalisation invalide: {level}')
        
        # Mise à jour du niveau de journalisation
        logging.getLogger().setLevel(numeric_level)
        
        return True
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour du niveau de journalisation: {str(e)}")
        return False

def get_logs(max_lines=1000, raw=False):
    """Récupère les journaux du système"""
    log_files = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs', 'app.log'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'auth', 'login.log'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ip_management', 'ip_actions.log')
    ]
    
    logs = []
    raw_logs = ""
    
    for log_file in log_files:
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    
                    if raw:
                        raw_logs += f"=== {os.path.basename(log_file)} ===\n"
                        raw_logs += "".join(lines[-max_lines:])
                        raw_logs += "\n\n"
                    else:
                        for line in lines[-max_lines:]:
                            line = line.strip()
                            if line:
                                parts = line.split('|', 2)
                                if len(parts) >= 3:
                                    timestamp = parts[0].strip()
                                    source = os.path.basename(log_file)
                                    message = parts[2].strip()
                                    
                                    logs.append({
                                        'timestamp': timestamp,
                                        'source': source,
                                        'message': message
                                    })
                                else:
                                    logs.append({
                                        'timestamp': 'N/A',
                                        'source': os.path.basename(log_file),
                                        'message': line
                                    })
        except Exception as e:
            logger.error(f"Erreur lors de la lecture du fichier de journalisation {log_file}: {str(e)}")
    
    if raw:
        return raw_logs
    
    # Tri par timestamp décroissant
    logs.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return logs
