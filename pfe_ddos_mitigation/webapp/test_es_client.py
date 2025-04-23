# test_es_client.py
from app.elasticsearch.client import ElasticsearchClient

es_client = ElasticsearchClient(
    host="10.10.10.3",
    port=9200,
    index="suricata-ml"
)

print("Connecté :", es_client.check_connection())
print("Index existe ?", es_client.check_index_exists())
print("Alertes :", es_client.get_recent_alerts())
print("IPs :", es_client.get_malicious_ips())
print("Client config :", es_client.config)
