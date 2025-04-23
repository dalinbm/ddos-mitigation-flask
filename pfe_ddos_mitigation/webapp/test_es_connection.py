from app.elasticsearch.client import ElasticsearchClient

client = ElasticsearchClient(
    host="10.10.10.3",
    port=9200,
    index="prediction_ml",
    username=None,
    password=None,
    use_ssl=False
)

if client.check_connection():
    print("✅ Elasticsearch est bien connecté !")
else:
    print("❌ Échec de connexion à Elasticsearch.")
