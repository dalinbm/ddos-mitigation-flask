```
webapp/
├── app/
│   ├── __init__.py           # Initialisation de l'application Flask
│   ├── auth/                 # Module d'authentification
│   │   ├── __init__.py
│   │   ├── forms.py          # Formulaires d'authentification
│   │   ├── models.py         # Modèles d'utilisateurs
│   │   └── routes.py         # Routes d'authentification
│   ├── dashboard/            # Module de tableau de bord
│   │   ├── __init__.py
│   │   └── routes.py         # Routes du tableau de bord
│   ├── elasticsearch/        # Module d'intégration Elasticsearch
│   │   ├── __init__.py
│   │   └── client.py         # Client Elasticsearch
│   ├── fortigate/            # Module d'intégration Fortigate
│   │   ├── __init__.py
│   │   └── ssh_client.py     # Client SSH pour Fortigate
│   ├── ip_management/        # Module de gestion des IP
│   │   ├── __init__.py
│   │   ├── forms.py          # Formulaires de gestion des IP
│   │   └── routes.py         # Routes de gestion des IP
│   ├── config/               # Module de configuration
│   │   ├── __init__.py
│   │   ├── forms.py          # Formulaires de configuration
│   │   └── routes.py         # Routes de configuration
│   ├── scheduler/            # Module de planification
│   │   ├── __init__.py
│   │   └── jobs.py           # Tâches planifiées
│   ├── static/               # Fichiers statiques
│   │   ├── css/              # Styles CSS
│   │   ├── js/               # Scripts JavaScript
│   │   └── img/              # Images
│   ├── templates/            # Templates HTML
│   │   ├── base.html         # Template de base
│   │   ├── auth/             # Templates d'authentification
│   │   ├── dashboard/        # Templates de tableau de bord
│   │   ├── ip_management/    # Templates de gestion des IP
│   │   └── config/           # Templates de configuration
│   ├── utils/                # Utilitaires
│   │   ├── __init__.py
│   │   └── helpers.py        # Fonctions d'aide
│   └── models.py             # Modèles de données
├── config.py                 # Configuration de l'application
├── run.py                    # Point d'entrée de l'application
├── requirements.txt          # Dépendances Python
└── .env                      # Variables d'environnement
```
