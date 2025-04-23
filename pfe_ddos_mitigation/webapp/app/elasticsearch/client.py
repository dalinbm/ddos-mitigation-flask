#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import BadRequestError, TransportError


class ElasticsearchClient:
    def __init__(self, host="localhost", port=9200, index="suricata-ml",
                 username=None, password=None, use_ssl=False):
        self.logger = logging.getLogger("ElasticsearchClient")
        logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

        self.index = index
        scheme = "https" if use_ssl else "http"

        self.config = {
            "hosts": [f"{scheme}://{host}:{port}"]
        }

        if username and password:
            self.config["basic_auth"] = (username, password)

        if use_ssl:
            self.config["verify_certs"] = False

        # Headers à utiliser UNIQUEMENT pour perform_request
        self.headers = {
            "Accept": "application/vnd.elasticsearch+json;compatible-with=8",
            "Content-Type": "application/vnd.elasticsearch+json;compatible-with=8"
        }

        try:
            self.es = Elasticsearch(**self.config)
            self.logger.info(f"✅ Connexion à Elasticsearch établie: {host}:{port}")
        except Exception as e:
            self.logger.error(f"❌ Erreur création client Elasticsearch : {str(e)}")
            raise

    def check_connection(self):
        """Ping Elasticsearch avec perform_request"""
        try:
            response = self.es.perform_request(
                method="GET",
                path="/",
                headers=self.headers
            )
            cluster = response.get("cluster_name", "N/A")
            version = response.get("version", {}).get("number", "N/A")
            self.logger.info(f"✅ Elasticsearch connecté - Cluster: {cluster} | Version: {version}")
            return True
        except Exception as e:
            self.logger.error(f"❌ Elasticsearch non connecté : {e}")
            return False

    def check_index_exists(self):
        """Vérifie si l'index existe"""
        try:
            self.es.perform_request(
                method="HEAD",
                path=f"/{self.index}",
                headers=self.headers
            )
            return True
        except Exception as e:
            self.logger.error(f"❌ Erreur vérification index : {e}")
            return False

    def search_raw(self, query, size=1000):
        """Requête brute avec perform_request"""
        try:
            response = self.es.perform_request(
                method="POST",
                path=f"/{self.index}/_search",
                headers=self.headers,
                body=json.dumps(query),
                params={"size": size}
            )
            return response.get("hits", {}).get("hits", [])
        except Exception as e:
            self.logger.error(f"❌ Erreur recherche Elasticsearch : {str(e)}")
            return []

    def get_malicious_ips(self, time_range=None):
        """IPs avec ml_prediction = 1"""
        query = {
            "query": {
                "bool": {
                    "must": [{"term": {"ml_prediction": 1}}]
                }
            }
        }

        if time_range:
            query["query"]["bool"]["filter"] = [
                {"range": {"timestamp": time_range}}
            ]

        hits = self.search_raw(query)
        ips = list({hit["_source"].get("src_ip") for hit in hits if hit["_source"].get("src_ip")})
        self.logger.info(f"✅ IPs malveillantes récupérées : {len(ips)}")
        return ips

    def get_recent_alerts(self, limit=10):
        """Récupère les alertes récentes"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event_type.keyword": "alert"}}
                    ]
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}]
        }

        hits = self.search_raw(query, size=limit)
        alerts = []

        for hit in hits:
            src = hit["_source"]
            alerts.append({
                "timestamp": src.get("timestamp", "N/A"),
                "type": src.get("alert_severity", "info"),
                "type_label": f"{src.get('alert_severity', 'Info')}",
                "message": f"Attaque détectée de {src.get('src_ip')} vers {src.get('dest_ip')} via {src.get('protocol')}",
                "source": src
            })

        self.logger.info(f"✅ Alertes récupérées : {len(alerts)}")
        return alerts

    def get_attack_statistics(self, time_range):
        """Nombre d'attaques + dernière date"""
        query = {
            "query": {
                "range": {
                    "timestamp": time_range
                }
            },
            "size": 0,
            "aggs": {
                "last_attack_time": {
                    "max": {
                        "field": "timestamp"
                    }
                }
            }
        }

        try:
            result = self.es.search(index=self.index, body=query)
            attacks_count = result.get("hits", {}).get("total", {}).get("value", 0)
            last_attack_time = result.get("aggregations", {}).get("last_attack_time", {}).get("value_as_string", "N/A")

            return {
                "attacks_count": attacks_count,
                "last_attack_time": last_attack_time
            }
        except Exception as e:
            self.logger.error(f"❌ Erreur get_attack_statistics : {str(e)}")
            return {
                "attacks_count": 0,
                "last_attack_time": "N/A"
            }

    def get_attack_trends(self, period="day"):
        """Tendances d’attaques par jour/heure"""
        now = datetime.utcnow()

        if period == "day":
            interval = "hour"
            gte = (now - timedelta(days=1)).isoformat()
        elif period == "week":
            interval = "day"
            gte = (now - timedelta(weeks=1)).isoformat()
        elif period == "month":
            interval = "day"
            gte = (now - timedelta(days=30)).isoformat()
        else:
            interval = "day"
            gte = (now - timedelta(days=7)).isoformat()

        query = {
            "size": 0,
            "query": {
                "range": {
                    "timestamp": {
                        "gte": gte,
                        "lt": now.isoformat()
                    }
                }
            },
            "aggs": {
                "attacks_over_time": {
                    "date_histogram": {
                        "field": "timestamp",
                        "calendar_interval": interval,
                        "format": "yyyy-MM-dd HH:mm:ss"
                    }
                }
            }
        }

        try:
            response = self.es.search(index=self.index, body=query)
            buckets = response.get("aggregations", {}).get("attacks_over_time", {}).get("buckets", [])

            labels = [bucket["key_as_string"] for bucket in buckets]
            counts = [bucket["doc_count"] for bucket in buckets]

            return {
                "labels": labels,
                "detected": counts
            }

        except Exception as e:
            self.logger.error(f"❌ Erreur get_attack_trends : {str(e)}")
            return {
                "labels": [],
                "detected": []
            }
