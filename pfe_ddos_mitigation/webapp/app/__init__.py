#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Initialisation de l'application Flask
"""
import os
from flask import Flask
from flask_bootstrap import Bootstrap
from flask_login import LoginManager
from app.auth import User  # ✅ Bien placé ici

# Initialisation des extensions
bootstrap = Bootstrap()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Veuillez vous connecter pour accéder à cette page.'
login_manager.login_message_category = 'info'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def create_app(test_config=None):
    """Crée et configure l'application Flask"""
    app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'), instance_relative_config=True)
    
    # Configuration par défaut
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev_key_change_in_production'),
        DATABASE=os.path.join(app.instance_path, 'webapp.sqlite'),
        UPLOAD_FOLDER=os.path.join(BASE_DIR, 'uploads'),
        CONFIG_FILE=os.path.join(os.getcwd(), "config.ini"),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16 MB max upload size
    )
    
    if test_config is not None:
        app.config.from_mapping(test_config)
    
    try:
        os.makedirs(app.instance_path, exist_ok=True)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    except OSError:
        pass
    
    bootstrap.init_app(app)
    login_manager.init_app(app)
    
    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp)
    
    from app.dashboard import bp as dashboard_bp
    app.register_blueprint(dashboard_bp)
    
    from app.ip_management import bp as ip_management_bp
    app.register_blueprint(ip_management_bp)
    
    from app.config import bp as config_bp
    app.register_blueprint(config_bp)
    from app.visualization import bp as visualization_bp
    app.register_blueprint(visualization_bp)
    
    # ✅ LoginManager: enregistrer le user_loader ici
    login_manager.user_loader(User.get)

    @app.route('/')
    def index():
        from flask import redirect, url_for
        return redirect(url_for('dashboard.index'))
    from datetime import datetime
    @app.context_processor
    def inject_now():
        return {'now': datetime.now()}
        
    @app.route('/es_status')
    def es_status():
        from flask import jsonify
        from app.elasticsearch.client import ElasticsearchClient

        try:
            es_client = ElasticsearchClient(
                host="10.10.10.3",
                port=9200,
                use_ssl=False  # ou True si tu gardes le SSL
            )

            if es_client.check_connection():
                return jsonify({"status": "ok", "message": "Connexion réussie à Elasticsearch ✅"}), 200
            else:
                return jsonify({"status": "error", "message": "Elasticsearch ne répond pas ❌"}), 500

        except Exception as e:
            return jsonify({"status": "error", "message": f"Erreur de connexion Elasticsearch : {str(e)}"}), 500


    return app
