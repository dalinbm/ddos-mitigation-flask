#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'authentification pour l'application web
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
from datetime import datetime

# Création du blueprint
bp = Blueprint('auth', __name__, url_prefix='/auth')

# Chemin du fichier des utilisateurs
USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.json')

# Classe User pour Flask-Login
class User:
    def __init__(self, id, username, password_hash, email=None, role='user'):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.email = email
        self.role = role
        self.is_active = True
        self.is_authenticated = True
        self.is_anonymous = False
    
    def get_id(self):
        return self.id
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @staticmethod
    def get(user_id):
        users = load_users()
        for user in users:
            if user['id'] == user_id:
                return User(
                    id=user['id'],
                    username=user['username'],
                    password_hash=user['password_hash'],
                    email=user.get('email'),
                    role=user.get('role', 'user')
                )
        return None

# Fonction pour charger les utilisateurs depuis le fichier JSON
def load_users():
    if not os.path.exists(USERS_FILE):
        # Création d'un utilisateur admin par défaut
        admin_user = {
            'id': '1',
            'username': 'admin',
            'password_hash': generate_password_hash('admin'),
            'email': 'admin@example.com',
            'role': 'admin'
        }
        save_users([admin_user])
        return [admin_user]
    
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Erreur lors du chargement des utilisateurs: {str(e)}")
        return []

# Fonction pour sauvegarder les utilisateurs dans le fichier JSON
def save_users(users):
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
        return True
    except Exception as e:
        print(f"Erreur lors de la sauvegarde des utilisateurs: {str(e)}")
        return False

# Fonction pour initialiser le module d'authentification
def init_app(app):
    from flask_login import LoginManager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.get(user_id)

# Routes d'authentification
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        users = load_users()
        user_data = None
        
        for user in users:
            if user['username'] == username:
                user_data = user
                break
        
        if user_data and check_password_hash(user_data['password_hash'], password):
            user = User(
                id=user_data['id'],
                username=user_data['username'],
                password_hash=user_data['password_hash'],
                email=user_data.get('email'),
                role=user_data.get('role', 'user')
            )
            login_user(user, remember=remember)
            
            # Journalisation de la connexion
            log_login(username, True)
            
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('dashboard.index')
            
            flash('Connexion réussie.', 'success')
            return redirect(next_page)
        
        # Journalisation de la tentative de connexion échouée
        log_login(username, False)
        
        flash('Nom d\'utilisateur ou mot de passe incorrect.', 'danger')
    
    return render_template('auth/login.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('auth.login'))

@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_user.check_password(current_password):
            flash('Mot de passe actuel incorrect.', 'danger')
        elif new_password != confirm_password:
            flash('Les nouveaux mots de passe ne correspondent pas.', 'danger')
        elif len(new_password) < 6:
            flash('Le nouveau mot de passe doit contenir au moins 6 caractères.', 'danger')
        else:
            # Mise à jour du mot de passe
            users = load_users()
            for user in users:
                if user['id'] == current_user.id:
                    user['password_hash'] = generate_password_hash(new_password)
                    break
            
            if save_users(users):
                flash('Mot de passe mis à jour avec succès.', 'success')
            else:
                flash('Erreur lors de la mise à jour du mot de passe.', 'danger')
    
    return render_template('auth/profile.html')

# Fonction pour journaliser les connexions
def log_login(username, success):
    log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'login.log')
    
    try:
        with open(log_file, 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ip = request.remote_addr
            status = 'SUCCESS' if success else 'FAILURE'
            f.write(f"{timestamp} | {ip} | {username} | {status}\n")
    except Exception as e:
        print(f"Erreur lors de la journalisation de la connexion: {str(e)}")
