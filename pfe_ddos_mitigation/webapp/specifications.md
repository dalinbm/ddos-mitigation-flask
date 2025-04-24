# Spécifications fonctionnelles de l'interface web pour la mitigation DDoS

## Objectif
Créer une interface web conviviale pour gérer et visualiser le système de mitigation des attaques DDoS basé sur le machine learning et l'intégration avec Fortigate.

## Fonctionnalités principales

### 1. Tableau de bord
- Affichage des statistiques clés (nombre d'attaques détectées, IP bloquées, etc.)
- Graphiques de tendances des attaques sur différentes périodes
- Indicateurs d'état du système (connexion Elasticsearch, connexion Fortigate)
- Alertes et notifications des dernières activités

### 2. Visualisation des données Elasticsearch
- Affichage des entrées avec ml_prediction = 1 (attaques détectées)
- Filtrage par période, type d'attaque, adresse IP
- Graphiques de distribution des attaques par protocole, port, etc.
- Visualisation de la sévérité des attaques

### 3. Gestion des adresses IP bloquées
- Liste des adresses IP actuellement bloquées
- Possibilité d'ajouter/supprimer manuellement des adresses IP
- Historique des blocages avec horodatage
- Fonction de déblocage automatique après une période définie

### 4. Configuration du système
- Paramètres de connexion à Elasticsearch
- Paramètres de connexion SSH au Fortigate
- Configuration de la fréquence d'exécution des vérifications
- Gestion de la liste blanche des adresses IP à ne jamais bloquer

### 5. Exécution manuelle et planification
- Bouton pour exécuter manuellement la détection et le blocage
- Interface de planification des tâches automatiques (remplace cron)
- Mode simulation (dry-run) pour tester sans blocage réel
- Journalisation des exécutions avec résultats détaillés

### 6. Authentification et sécurité
- Système de connexion sécurisé pour les administrateurs
- Gestion des utilisateurs et des rôles
- Journal d'audit des actions effectuées
- Protection contre les attaques web courantes

### 7. Documentation et aide
- Guide d'utilisation intégré
- Documentation technique des API
- FAQ et dépannage
- Informations sur le projet

## Exigences techniques
- Interface responsive compatible mobile et desktop
- Temps de réponse rapide pour les opérations courantes
- Sécurisation des communications (HTTPS)
- Gestion des erreurs avec messages explicites
- Sauvegarde automatique des configurations

## Utilisateurs cibles
- Administrateurs réseau
- Équipes de sécurité informatique
- Personnel technique chargé de la surveillance du réseau
