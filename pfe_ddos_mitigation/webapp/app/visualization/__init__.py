#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de visualisation des données Elasticsearch
"""

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required
import logging
import json
from datetime import datetime, timedelta
import pandas as pd
import plotly
import plotly.express as px
import plotly.graph_objects as go

from app.elasticsearch.client import ElasticsearchClient

# Création du blueprint
bp = Blueprint('visualization', __name__, url_prefix='/visualization')

# Configuration du logger
logger = logging.getLogger(__name__)

@bp.route('/')
@login_required
def index():
    """Page principale de visualisation"""
    try:
        # Récupération des paramètres
        time_range = request.args.get('time_range', 'day')
        
        # Récupération des données pour les visualisations
        attack_distribution = get_attack_distribution(time_range)
        geo_distribution = get_geo_distribution(time_range)
        severity_distribution = get_severity_distribution(time_range)
        timeline_data = get_timeline_data(time_range)
        
        return render_template(
            'visualization/index.html',
            time_range=time_range,
            attack_distribution=attack_distribution,
            geo_distribution=geo_distribution,
            severity_distribution=severity_distribution,
            timeline_data=timeline_data
        )
    except Exception as e:
        logger.error(f"Erreur lors du chargement de la page de visualisation: {str(e)}")
        return render_template(
            'visualization/index.html',
            time_range='day',
            attack_distribution={},
            geo_distribution={},
            severity_distribution={},
            timeline_data={},
            error=str(e)
        )

@bp.route('/attack_details')
@login_required
def attack_details():
    """Page de détails d'une attaque spécifique"""
    try:
        # Récupération des paramètres
        attack_type = request.args.get('type')
        time_range = request.args.get('time_range', 'day')
        
        if not attack_type:
            return render_template(
                'visualization/attack_details.html',
                attack_type=None,
                time_range=time_range,
                error="Type d'attaque non spécifié"
            )
        
        # Récupération des détails de l'attaque
        attack_details = get_attack_details(attack_type, time_range)
        
        return render_template(
            'visualization/attack_details.html',
            attack_type=attack_type,
            time_range=time_range,
            attack_details=attack_details
        )
    except Exception as e:
        logger.error(f"Erreur lors du chargement des détails de l'attaque: {str(e)}")
        return render_template(
            'visualization/attack_details.html',
            attack_type=attack_type if 'attack_type' in locals() else None,
            time_range=time_range if 'time_range' in locals() else 'day',
            error=str(e)
        )

@bp.route('/api/visualization/attack_distribution')
@login_required
def api_attack_distribution():
    """API pour récupérer la distribution des attaques"""
    try:
        time_range = request.args.get('time_range', 'day')
        attack_distribution = get_attack_distribution(time_range)
        
        return jsonify({
            'success': True,
            'data': attack_distribution
        })
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la distribution des attaques: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@bp.route('/api/visualization/geo_distribution')
@login_required
def api_geo_distribution():
    """API pour récupérer la distribution géographique des attaques"""
    try:
        time_range = request.args.get('time_range', 'day')
        geo_distribution = get_geo_distribution(time_range)
        
        return jsonify({
            'success': True,
            'data': geo_distribution
        })
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la distribution géographique des attaques: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@bp.route('/api/visualization/severity_distribution')
@login_required
def api_severity_distribution():
    """API pour récupérer la distribution des sévérités des attaques"""
    try:
        time_range = request.args.get('time_range', 'day')
        severity_distribution = get_severity_distribution(time_range)
        
        return jsonify({
            'success': True,
            'data': severity_distribution
        })
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la distribution des sévérités: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@bp.route('/api/visualization/timeline')
@login_required
def api_timeline():
    """API pour récupérer les données de la timeline des attaques"""
    try:
        time_range = request.args.get('time_range', 'day')
        timeline_data = get_timeline_data(time_range)
        
        return jsonify({
            'success': True,
            'data': timeline_data
        })
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des données de timeline: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

def get_attack_distribution(time_range='day'):
    """Récupère la distribution des types d'attaques"""
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
        
        if not es_client.check_connection():
            logger.error("Impossible de se connecter à Elasticsearch")
            return {}
        
        # Définition de la plage de temps
        es_time_range = get_elasticsearch_time_range(time_range)
        
        # Construction de la requête
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"ml_prediction": 1}}
                    ],
                    "filter": [
                        {"range": {"@timestamp": es_time_range}}
                    ]
                }
            },
            "aggs": {
                "attack_types": {
                    "terms": {
                        "field": "protocol.keyword",
                        "size": 10
                    }
                }
            },
            "size": 0
        }
        
        # Exécution de la requête
        response = es_client.es.search(
            index=es_client.index,
            body=query
        )
        
        # Extraction des résultats
        buckets = response.get('aggregations', {}).get('attack_types', {}).get('buckets', [])
        
        # Préparation des données pour le graphique
        labels = []
        values = []
        
        for bucket in buckets:
            labels.append(bucket.get('key', 'Unknown'))
            values.append(bucket.get('doc_count', 0))
        
        # Création du graphique avec Plotly
        if labels and values:
            fig = px.pie(
                names=labels,
                values=values,
                title="Distribution des types d'attaques",
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            
            # Configuration du graphique
            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(
                margin=dict(l=20, r=20, t=40, b=20),
                legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5)
            )
            
            # Conversion en JSON
            graph_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
            
            return {
                'graph': graph_json,
                'data': {
                    'labels': labels,
                    'values': values
                }
            }
        
        return {}
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la distribution des attaques: {str(e)}")
        return {}

def get_geo_distribution(time_range='day'):
    """Récupère la distribution géographique des attaques"""
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
        
        if not es_client.check_connection():
            logger.error("Impossible de se connecter à Elasticsearch")
            return {}
        
        # Définition de la plage de temps
        es_time_range = get_elasticsearch_time_range(time_range)
        
        # Construction de la requête
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"ml_prediction": 1}}
                    ],
                    "filter": [
                        {"range": {"@timestamp": es_time_range}}
                    ]
                }
            },
            "aggs": {
                "countries": {
                    "terms": {
                        "field": "geoip.country_name.keyword",
                        "size": 20
                    }
                }
            },
            "size": 0
        }
        
        # Exécution de la requête
        response = es_client.es.search(
            index=es_client.index,
            body=query
        )
        
        # Extraction des résultats
        buckets = response.get('aggregations', {}).get('countries', {}).get('buckets', [])
        
        # Préparation des données pour le graphique
        countries = []
        counts = []
        
        for bucket in buckets:
            countries.append(bucket.get('key', 'Unknown'))
            counts.append(bucket.get('doc_count', 0))
        
        # Création du graphique avec Plotly
        if countries and counts:
            fig = px.choropleth(
                locations=countries,
                locationmode='country names',
                color=counts,
                hover_name=countries,
                color_continuous_scale=px.colors.sequential.Plasma,
                title="Distribution géographique des attaques"
            )
            
            # Configuration du graphique
            fig.update_layout(
                margin=dict(l=0, r=0, t=40, b=0),
                coloraxis_colorbar=dict(title="Nombre d'attaques")
            )
            
            # Conversion en JSON
            graph_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
            
            return {
                'graph': graph_json,
                'data': {
                    'countries': countries,
                    'counts': counts
                }
            }
        
        return {}
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la distribution géographique des attaques: {str(e)}")
        return {}

def get_severity_distribution(time_range='day'):
    """Récupère la distribution des sévérités des attaques"""
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
        
        if not es_client.check_connection():
            logger.error("Impossible de se connecter à Elasticsearch")
            return {}
        
        # Définition de la plage de temps
        es_time_range = get_elasticsearch_time_range(time_range)
        
        # Construction de la requête
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"ml_prediction": 1}}
                    ],
                    "filter": [
                        {"range": {"@timestamp": es_time_range}}
                    ]
                }
            },
            "aggs": {
                "severities": {
                    "terms": {
                        "field": "alert_severity.keyword",
                        "size": 5
                    }
                }
            },
            "size": 0
        }
        
        # Exécution de la requête
        response = es_client.es.search(
            index=es_client.index,
            body=query
        )
        
        # Extraction des résultats
        buckets = response.get('aggregations', {}).get('severities', {}).get('buckets', [])
        
        # Préparation des données pour le graphique
        severities = []
        counts = []
        colors = []
        
        # Définition des couleurs par sévérité
        severity_colors = {
            'critical': '#e74c3c',
            'high': '#e67e22',
            'medium': '#f39c12',
            'low': '#3498db',
            'info': '#2ecc71'
        }
        
        for bucket in buckets:
            severity = bucket.get('key', 'unknown').lower()
            severities.append(severity.capitalize())
            counts.append(bucket.get('doc_count', 0))
            colors.append(severity_colors.get(severity, '#95a5a6'))
        
        # Création du graphique avec Plotly
        if severities and counts:
            fig = go.Figure(data=[
                go.Bar(
                    x=severities,
                    y=counts,
                    marker_color=colors
                )
            ])
            
            # Configuration du graphique
            fig.update_layout(
                title="Distribution des sévérités d'attaques",
                xaxis_title="Sévérité",
                yaxis_title="Nombre d'attaques",
                margin=dict(l=20, r=20, t=40, b=20)
            )
            
            # Conversion en JSON
            graph_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
            
            return {
                'graph': graph_json,
                'data': {
                    'severities': severities,
                    'counts': counts,
                    'colors': colors
                }
            }
        
        return {}
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la distribution des sévérités: {str(e)}")
        return {}

def get_timeline_data(time_range='day'):
    """Récupère les données de la timeline des attaques"""
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
        
        if not es_client.check_connection():
            logger.error("Impossible de se connecter à Elasticsearch")
            return {}
        
        # Définition de la plage de temps et de l'intervalle
        es_time_range = get_elasticsearch_time_range(time_range)
        interval = get_interval_for_time_range(time_range)
        
        # Construction de la requête
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"ml_prediction": 1}}
                    ],
                    "filter": [
                        {"range": {"@timestamp": es_time_range}}
                    ]
                }
            },
            "aggs": {
                "timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": interval,
                        "format": "yyyy-MM-dd HH:mm:ss"
                    },
                    "aggs": {
                        "protocols": {
                            "terms": {
                                "field": "protocol.keyword",
                                "size": 5
                            }
                        }
                    }
                }
            },
            "size": 0
        }
        
        # Exécution de la requête
        response = es_client.es.search(
            index=es_client.index,
            body=query
        )
        
        # Extraction des résultats
        buckets = response.get('aggregations', {}).get('timeline', {}).get('buckets', [])
        
        # Récupération des protocoles uniques
        protocols = set()
        for bucket in buckets:
            for protocol_bucket in bucket.get('protocols', {}).get('buckets', []):
                protocols.add(protocol_bucket.get('key'))
        
        protocols = list(protocols)
        
        # Préparation des données pour le graphique
        timestamps = []
        data = {protocol: [] for protocol in protocols}
        
        for bucket in buckets:
            timestamp = bucket.get('key_as_string')
            timestamps.append(timestamp)
            
            # Initialisation des compteurs pour chaque protocole
            protocol_counts = {protocol: 0 for protocol in protocols}
            
            # Mise à jour des compteurs avec les données du bucket
            for protocol_bucket in bucket.get('protocols', {}).get('buckets', []):
                protocol = protocol_bucket.get('key')
                count = protocol_bucket.get('doc_count', 0)
                if protocol in protocol_counts:
                    protocol_counts[protocol] = count
            
            # Ajout des compteurs aux séries de données
            for protocol in protocols:
                data[protocol].append(protocol_counts[protocol])
        
        # Création du graphique avec Plotly
        if timestamps and data:
            fig = go.Figure()
            
            for protocol in protocols:
                fig.add_trace(go.Scatter(
                    x=timestamps,
                    y=data[protocol],
                    mode='lines+markers',
                    name=protocol
                ))
            
            # Configuration du graphique
            fig.update_layout(
                title="Timeline des attaques par protocole",
                xaxis_title="Temps",
                yaxis_title="Nombre d'attaques",
                margin=dict(l=20, r=20, t=40, b=20),
                legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5)
            )
            
            # Conversion en JSON
            graph_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
            
            return {
                'graph': graph_json,
                'data': {
                    'timestamps': timestamps,
                    'protocols': protocols,
                    'series': data
                }
            }
        
        return {}
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des données de timeline: {str(e)}")
        return {}

def get_attack_details(attack_type, time_range='day'):
    """Récupère les détails d'une attaque spécifique"""
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
        
        if not es_client.check_connection():
            logger.error("Impossible de se connecter à Elasticsearch")
            return {}
        
        # Définition de la plage de temps
        es_time_range = get_elasticsearch_time_range(time_range)
        
        # Construction de la requête pour les statistiques
        stats_query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"ml_prediction": 1}},
                        {"term": {"protocol.keyword": attack_type}}
                    ],
                    "filter": [
                        {"range": {"@timestamp": es_time_range}}
                    ]
                }
            },
            "aggs": {
                "severities": {
                    "terms": {
                        "field": "alert_severity.keyword",
                        "size": 5
                    }
                },
                "source_ips": {
                    "terms": {
                        "field": "src_ip.keyword",
                        "size": 10
                    }
                },
                "destination_ips": {
                    "terms": {
                        "field": "dest_ip.keyword",
                        "size": 10
                    }
                },
                "source_countries": {
                    "terms": {
                        "field": "geoip.country_name.keyword",
                        "size": 10
                    }
                }
            },
            "size": 0
        }
        
        # Exécution de la requête pour les statistiques
        stats_response = es_client.es.search(
            index=es_client.index,
            body=stats_query
        )
        
        # Extraction des résultats pour les statistiques
        severities = []
        severity_counts = []
        
        for bucket in stats_response.get('aggregations', {}).get('severities', {}).get('buckets', []):
            severities.append(bucket.get('key', 'Unknown').capitalize())
            severity_counts.append(bucket.get('doc_count', 0))
        
        source_ips = []
        source_ip_counts = []
        
        for bucket in stats_response.get('aggregations', {}).get('source_ips', {}).get('buckets', []):
            source_ips.append(bucket.get('key', 'Unknown'))
            source_ip_counts.append(bucket.get('doc_count', 0))
        
        destination_ips = []
        destination_ip_counts = []
        
        for bucket in stats_response.get('aggregations', {}).get('destination_ips', {}).get('buckets', []):
            destination_ips.append(bucket.get('key', 'Unknown'))
            destination_ip_counts.append(bucket.get('doc_count', 0))
        
        source_countries = []
        source_country_counts = []
        
        for bucket in stats_response.get('aggregations', {}).get('source_countries', {}).get('buckets', []):
            source_countries.append(bucket.get('key', 'Unknown'))
            source_country_counts.append(bucket.get('doc_count', 0))
        
        # Construction de la requête pour les exemples d'attaques
        examples_query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"ml_prediction": 1}},
                        {"term": {"protocol.keyword": attack_type}}
                    ],
                    "filter": [
                        {"range": {"@timestamp": es_time_range}}
                    ]
                }
            },
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ],
            "size": 10
        }
        
        # Exécution de la requête pour les exemples d'attaques
        examples_response = es_client.es.search(
            index=es_client.index,
            body=examples_query
        )
        
        # Extraction des résultats pour les exemples d'attaques
        examples = []
        
        for hit in examples_response.get('hits', {}).get('hits', []):
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
            
            examples.append({
                'timestamp': formatted_timestamp,
                'src_ip': source.get('src_ip', 'Unknown'),
                'dest_ip': source.get('dest_ip', 'Unknown'),
                'severity': source.get('alert_severity', 'Unknown').capitalize(),
                'details': source
            })
        
        # Création des graphiques
        
        # Graphique des sévérités
        if severities and severity_counts:
            severity_colors = {
                'Critical': '#e74c3c',
                'High': '#e67e22',
                'Medium': '#f39c12',
                'Low': '#3498db',
                'Info': '#2ecc71'
            }
            
            colors = [severity_colors.get(severity, '#95a5a6') for severity in severities]
            
            severity_fig = go.Figure(data=[
                go.Bar(
                    x=severities,
                    y=severity_counts,
                    marker_color=colors
                )
            ])
            
            severity_fig.update_layout(
                title=f"Distribution des sévérités pour les attaques {attack_type}",
                xaxis_title="Sévérité",
                yaxis_title="Nombre d'attaques",
                margin=dict(l=20, r=20, t=40, b=20)
            )
            
            severity_graph = json.dumps(severity_fig, cls=plotly.utils.PlotlyJSONEncoder)
        else:
            severity_graph = None
        
        # Graphique des adresses IP sources
        if source_ips and source_ip_counts:
            source_ip_fig = go.Figure(data=[
                go.Bar(
                    x=source_ips,
                    y=source_ip_counts,
                    marker_color='#3498db'
                )
            ])
            
            source_ip_fig.update_layout(
                title=f"Top 10 des adresses IP sources pour les attaques {attack_type}",
                xaxis_title="Adresse IP source",
                yaxis_title="Nombre d'attaques",
                margin=dict(l=20, r=20, t=40, b=20)
            )
            
            source_ip_graph = json.dumps(source_ip_fig, cls=plotly.utils.PlotlyJSONEncoder)
        else:
            source_ip_graph = None
        
        # Graphique des pays sources
        if source_countries and source_country_counts:
            source_country_fig = px.choropleth(
                locations=source_countries,
                locationmode='country names',
                color=source_country_counts,
                hover_name=source_countries,
                color_continuous_scale=px.colors.sequential.Plasma,
                title=f"Distribution géographique des attaques {attack_type}"
            )
            
            source_country_fig.update_layout(
                margin=dict(l=0, r=0, t=40, b=0),
                coloraxis_colorbar=dict(title="Nombre d'attaques")
            )
            
            source_country_graph = json.dumps(source_country_fig, cls=plotly.utils.PlotlyJSONEncoder)
        else:
            source_country_graph = None
        
        return {
            'attack_type': attack_type,
            'time_range': time_range,
            'total_count': sum(severity_counts) if severity_counts else 0,
            'severities': {
                'labels': severities,
                'counts': severity_counts,
                'graph': severity_graph
            },
            'source_ips': {
                'ips': source_ips,
                'counts': source_ip_counts,
                'graph': source_ip_graph
            },
            'destination_ips': {
                'ips': destination_ips,
                'counts': destination_ip_counts
            },
            'source_countries': {
                'countries': source_countries,
                'counts': source_country_counts,
                'graph': source_country_graph
            },
            'examples': examples
        }
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des détails de l'attaque: {str(e)}")
        return {}

def get_elasticsearch_time_range(time_range):
    """Convertit une plage de temps en format Elasticsearch"""
    if time_range == 'hour':
        return {"gte": "now-1h", "lt": "now"}
    elif time_range == 'day':
        return {"gte": "now-1d", "lt": "now"}
    elif time_range == 'week':
        return {"gte": "now-7d", "lt": "now"}
    elif time_range == 'month':
        return {"gte": "now-30d", "lt": "now"}
    else:
        return {"gte": "now-1d", "lt": "now"}

def get_interval_for_time_range(time_range):
    """Retourne l'intervalle approprié pour une plage de temps"""
    if time_range == 'hour':
        return '5m'
    elif time_range == 'day':
        return '1h'
    elif time_range == 'week':
        return '1d'
    elif time_range == 'month':
        return '1d'
    else:
        return '1h'

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
