#!/usr/bin/env python3
# test_fortigate_client.py

from app.fortigate.ssh_client import FortigateSSHClient
from app.dashboard import load_config
from flask import Flask

# Flask init (mock app context for current_app)
app = Flask(__name__)
app.config['CONFIG_FILE'] = 'config.ini'

with app.app_context():
    config = load_config()

    fg_client = FortigateSSHClient(
        host=config['fortigate']['host'],
        username=config['fortigate']['username'],
        password=config['fortigate']['password'],
        port=config['fortigate'].get('port', 22)
    )

    if fg_client.connect():
        print("✅ Connexion SSH au Fortigate réussie !")

        output, error = fg_client.execute_command("get system status")
        if output:
            print("🧠 Infos Fortigate :\n", output)
        else:
            print("⚠️ Aucune sortie")

        fg_client.disconnect()
    else:
        print("❌ Échec de la connexion SSH au Fortigate")
