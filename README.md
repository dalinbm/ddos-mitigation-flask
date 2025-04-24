# Documentation du Système de Mitigation DDoS

## Vue d'ensemble

Le Système de Mitigation DDoS est une application web complète qui permet de détecter et de bloquer automatiquement les attaques DDoS en utilisant le machine learning. L'application s'intègre avec Elasticsearch pour la détection des attaques et avec Fortigate via SSH pour le blocage des adresses IP malveillantes.

## Architecture

L'architecture du système comprend les composants suivants :

1. **Frontend** : Interface utilisateur web développée avec Flask et Bootstrap
2. **Backend** : API REST pour l'interaction avec Elasticsearch et Fortigate
3. **Module Elasticsearch** : Interroge l'indice prediction_ml pour identifier les attaques
4. **Module Fortigate** : Communique avec le pare-feu Fortigate via SSH pour bloquer les IP
5. **Module de visualisation** : Affiche des graphiques interactifs des données d'attaques
6. **Module de gestion des IP** : Permet de gérer les adresses IP bloquées et la liste blanche
7. **Module d'authentification** : Sécurise l'accès à l'application
8. **Module de sécurité** : Implémente diverses mesures de sécurité

## Fonctionnalités principales

### Tableau de bord
- Vue d'ensemble des attaques DDoS détectées
- Statistiques en temps réel
- Alertes et notifications

### Visualisation des attaques
- Distribution des types d'attaques
- Distribution géographique
- Distribution par sévérité
- Timeline des attaques
- Détails par type d'attaque

### Gestion des IP
- Liste des adresses IP bloquées
- Liste blanche pour les adresses IP à ne jamais bloquer
- Blocage manuel d'adresses IP
- Déblocage d'adresses IP
- Historique des blocages

### Configuration
- Paramètres de connexion à Elasticsearch
- Paramètres de connexion à Fortigate
- Configuration du planificateur de mitigation automatique
- Paramètres généraux

### Authentification et sécurité
- Connexion sécurisée
- Gestion des profils utilisateurs
- Contrôle d'accès basé sur les rôles
- Protection contre les attaques web courantes

## Installation et déploiement

### Prérequis
- Python 3.8 ou supérieur
- Elasticsearch
- Fortigate avec accès SSH
- Serveur web (Nginx recommandé)
- Serveur d'application (Gunicorn recommandé)

### Installation

1. Clonez le dépôt :
   ```
   git clone https://github.com/votre-utilisateur/pfe_ddos_mitigation.git
   cd pfe_ddos_mitigation/webapp
   ```

2. Exécutez le script de configuration :
   ```
   ./setup.py
   ```
   Ce script vous guidera à travers la configuration de l'application.

3. Déployez l'application :
   ```
   ./deploy.sh
   ```

### Configuration pour la production

Pour un déploiement en production, suivez ces étapes supplémentaires :

1. Installez le service systemd :
   ```
   sudo cp ddos_mitigation.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable ddos_mitigation
   sudo systemctl start ddos_mitigation
   ```

2. Configurez Nginx :
   ```
   sudo cp nginx.conf /etc/nginx/sites-available/ddos_mitigation
   sudo ln -s /etc/nginx/sites-available/ddos_mitigation /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx
   ```

## Utilisation

### Connexion
Accédez à l'application via votre navigateur et connectez-vous avec les identifiants configurés.

### Tableau de bord
Le tableau de bord affiche une vue d'ensemble des attaques DDoS détectées et des statistiques en temps réel.

### Visualisation
La page de visualisation permet d'explorer les données d'attaques sous différentes formes :
- Distribution des types d'attaques
- Distribution géographique
- Distribution par sévérité
- Timeline des attaques

### Gestion des IP
La page de gestion des IP permet de :
- Voir les adresses IP actuellement bloquées
- Bloquer manuellement une adresse IP
- Débloquer une adresse IP
- Gérer la liste blanche
- Consulter l'historique des blocages

### Configuration
La page de configuration permet de modifier les paramètres de l'application :
- Connexion à Elasticsearch
- Connexion à Fortigate
- Planificateur de mitigation automatique
- Paramètres généraux

## Maintenance

### Journaux
Les journaux de l'application sont stockés dans le répertoire `logs`.

### Sauvegarde
Il est recommandé de sauvegarder régulièrement les fichiers suivants :
- `config.ini` : Configuration de l'application
- `app.db` : Base de données de l'application
- `whitelist.txt` : Liste blanche des adresses IP

### Mise à jour
Pour mettre à jour l'application, suivez ces étapes :
1. Arrêtez le service : `sudo systemctl stop ddos_mitigation`
2. Mettez à jour le code source
3. Exécutez le script de déploiement : `./deploy.sh`
4. Redémarrez le service : `sudo systemctl start ddos_mitigation`

## Dépannage

### Problèmes de connexion à Elasticsearch
- Vérifiez que Elasticsearch est en cours d'exécution
- Vérifiez les paramètres de connexion dans `config.ini`
- Vérifiez que l'indice `prediction_ml` existe

### Problèmes de connexion à Fortigate
- Vérifiez que le Fortigate est accessible via SSH
- Vérifiez les paramètres de connexion dans `config.ini`
- Vérifiez que l'utilisateur a les permissions nécessaires

### Problèmes d'application
- Consultez les journaux dans le répertoire `logs`
- Vérifiez le statut du service : `sudo systemctl status ddos_mitigation`
- Redémarrez l'application : `sudo systemctl restart ddos_mitigation`

## Support

Pour toute question ou problème, veuillez contacter l'équipe de support à l'adresse dalinbm@gmail.com.

## Licence

Ce projet est distribué sous licence MIT. Voir le fichier LICENSE pour plus de détails.
