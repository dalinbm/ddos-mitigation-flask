#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'intégration avec Fortigate via SSH
"""

import logging
import time
import paramiko
from datetime import datetime

class FortigateSSHClient:
    """Classe pour se connecter au Fortigate via SSH et bloquer des adresses IP"""
    
    def __init__(self, host, username, password, port=22):
        """
        Initialise la connexion SSH au Fortigate
        
        Args:
            host (str): Adresse IP ou nom d'hôte du Fortigate
            username (str): Nom d'utilisateur pour l'authentification SSH
            password (str): Mot de passe pour l'authentification SSH
            port (int): Port SSH (par défaut 22)
        """
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.client = None
        self.connected = False
        self.logger = logging.getLogger(__name__)
    
    def connect(self):
        """
        Établit la connexion SSH au Fortigate
        
        Returns:
            bool: True si la connexion a réussi, False sinon
        """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10
            )
            self.connected = True
            self.logger.info(f"Connexion SSH établie avec {self.host}")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la connexion SSH à {self.host}: {str(e)}")
            return False
    
    def disconnect(self):
        """Ferme la connexion SSH"""
        if self.client:
            self.client.close()
            self.connected = False
            self.logger.info(f"Connexion SSH fermée avec {self.host}")
    
    def execute_command(self, command):
        """
        Exécute une commande SSH sur le Fortigate
        
        Args:
            command (str): Commande à exécuter
            
        Returns:
            tuple: (stdout, stderr)
        """
        if not self.connected:
            self.logger.error("Tentative d'exécution de commande sans connexion SSH établie")
            return None, "Non connecté"
        
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            if error:
                self.logger.warning(f"Erreur lors de l'exécution de la commande '{command}': {error}")
            
            return output, error
        except Exception as e:
            self.logger.error(f"Erreur lors de l'exécution de la commande '{command}': {str(e)}")
            return None, str(e)
    
    def block_ip(self, ip_address, block_name=None, duration_hours=24):
        """
        Bloque une adresse IP sur le Fortigate
        
        Args:
            ip_address (str): Adresse IP à bloquer
            block_name (str, optional): Nom de l'objet d'adresse à créer
            duration_hours (int): Durée du blocage en heures (0 pour permanent)
            
        Returns:
            bool: True si le blocage a réussi, False sinon
        """
        if not block_name:
            # Génère un nom basé sur l'adresse IP et la date
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            block_name = f"BLOCK_ML_{ip_address.replace('.', '_')}_{timestamp}"
        
        # Commandes pour créer un objet d'adresse et l'ajouter à une politique de blocage
        commands = [
            "config firewall address",
            f"edit {block_name}",
            f"set subnet {ip_address} 255.255.255.255",
            "set comment \"Blocked by ML DDoS detection\"",
            "next",
            "end"
        ]
        
        # Exécution des commandes
        try:
            for cmd in commands:
                output, error = self.execute_command(cmd)
                if error:
                    self.logger.error(f"Erreur lors de l'exécution de la commande '{cmd}': {error}")
                    return False
                time.sleep(0.5)  # Pause pour éviter de surcharger le Fortigate
            
            # Vérification que l'adresse a bien été créée
            check_cmd = "show firewall address"
            output, error = self.execute_command(check_cmd)
            if block_name in output:
                self.logger.info(f"Adresse IP {ip_address} bloquée avec succès (objet: {block_name})")
                return True
            else:
                self.logger.warning(f"L'adresse IP {ip_address} semble ne pas avoir été bloquée correctement")
                return False
                
        except Exception as e:
            self.logger.error(f"Erreur lors du blocage de l'adresse IP {ip_address}: {str(e)}")
            return False
    
    def unblock_ip(self, ip_address=None, block_name=None):
        """
        Débloque une adresse IP sur le Fortigate
        
        Args:
            ip_address (str, optional): Adresse IP à débloquer
            block_name (str, optional): Nom de l'objet d'adresse à supprimer
            
        Returns:
            bool: True si le déblocage a réussi, False sinon
        """
        if not block_name and not ip_address:
            self.logger.error("Impossible de débloquer sans adresse IP ou nom d'objet")
            return False
        
        try:
            # Si on a seulement l'adresse IP, on doit d'abord trouver le nom de l'objet
            if not block_name and ip_address:
                # Récupération de la liste des objets d'adresse
                output, error = self.execute_command("show firewall address")
                if error:
                    self.logger.error(f"Erreur lors de la récupération des objets d'adresse: {error}")
                    return False
                
                # Recherche des objets correspondant à l'adresse IP
                lines = output.split('\n')
                block_names = []
                
                for i, line in enumerate(lines):
                    if f"subnet {ip_address} 255.255.255.255" in line:
                        # Recherche du nom de l'objet dans les lignes précédentes
                        for j in range(i-5, i):
                            if j >= 0 and "edit " in lines[j]:
                                name = lines[j].replace("edit ", "").strip().strip('"')
                                if name.startswith("BLOCK_ML_"):
                                    block_names.append(name)
                
                if not block_names:
                    self.logger.warning(f"Aucun objet trouvé pour l'adresse IP {ip_address}")
                    return False
                
                # Suppression de tous les objets trouvés
                success = True
                for name in block_names:
                    if not self._delete_address_object(name):
                        success = False
                
                return success
            else:
                # Si on a le nom de l'objet, on le supprime directement
                return self._delete_address_object(block_name)
                
        except Exception as e:
            self.logger.error(f"Erreur lors du déblocage de l'adresse IP: {str(e)}")
            return False
    
    def _delete_address_object(self, block_name):
        """
        Supprime un objet d'adresse
        
        Args:
            block_name (str): Nom de l'objet d'adresse à supprimer
            
        Returns:
            bool: True si la suppression a réussi, False sinon
        """
        commands = [
            "config firewall address",
            f"delete {block_name}",
            "end"
        ]
        
        try:
            for cmd in commands:
                output, error = self.execute_command(cmd)
                if error and "entry not found" not in error.lower():
                    self.logger.error(f"Erreur lors de l'exécution de la commande '{cmd}': {error}")
                    return False
                time.sleep(0.5)
            
            self.logger.info(f"Objet d'adresse {block_name} supprimé avec succès")
            return True
                
        except Exception as e:
            self.logger.error(f"Erreur lors de la suppression de l'objet d'adresse {block_name}: {str(e)}")
            return False
    
    def add_ip_to_group(self, ip_address, group_name):
        """
        Ajoute une adresse IP à un groupe d'adresses existant
        
        Args:
            ip_address (str): Adresse IP à ajouter
            group_name (str): Nom du groupe d'adresses
            
        Returns:
            bool: True si l'ajout a réussi, False sinon
        """
        # Génère un nom pour l'objet d'adresse
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        address_name = f"BLOCK_ML_{ip_address.replace('.', '_')}_{timestamp}"
        
        # Commandes pour créer un objet d'adresse
        address_commands = [
            "config firewall address",
            f"edit {address_name}",
            f"set subnet {ip_address} 255.255.255.255",
            "set comment \"Blocked by ML DDoS detection\"",
            "next",
            "end"
        ]
        
        # Commandes pour ajouter l'adresse au groupe
        group_commands = [
            "config firewall addrgrp",
            f"edit {group_name}",
            f"append member {address_name}",
            "next",
            "end"
        ]
        
        # Exécution des commandes
        try:
            # Création de l'objet d'adresse
            for cmd in address_commands:
                output, error = self.execute_command(cmd)
                if error:
                    self.logger.error(f"Erreur lors de l'exécution de la commande '{cmd}': {error}")
                    return False
                time.sleep(0.5)
            
            # Ajout au groupe
            for cmd in group_commands:
                output, error = self.execute_command(cmd)
                if error:
                    self.logger.error(f"Erreur lors de l'exécution de la commande '{cmd}': {error}")
                    return False
                time.sleep(0.5)
            
            self.logger.info(f"Adresse IP {ip_address} ajoutée avec succès au groupe {group_name}")
            return True
                
        except Exception as e:
            self.logger.error(f"Erreur lors de l'ajout de l'adresse IP {ip_address} au groupe {group_name}: {str(e)}")
            return False
    
    def get_blocked_ips(self):
        """
        Récupère la liste des adresses IP bloquées
        
        Returns:
            list: Liste des adresses IP bloquées avec leurs informations
        """
        blocked_ips = []
        
        try:
            # Récupération de la liste des objets d'adresse
            output, error = self.execute_command("show firewall address")
            if error:
                self.logger.error(f"Erreur lors de la récupération des objets d'adresse: {error}")
                return blocked_ips
            
            # Analyse de la sortie pour extraire les adresses IP bloquées
            lines = output.split('\n')
            current_block = None
            
            for line in lines:
                line = line.strip()
                
                if line.startswith("edit "):
                    name = line.replace("edit ", "").strip().strip('"')
                    if name.startswith("BLOCK_ML_"):
                        current_block = {
                            'name': name,
                            'address': None,
                            'block_date': None,
                            'reason': 'ml_prediction',
                            'expiration': None
                        }
                
                elif current_block and "set subnet" in line:
                    parts = line.replace("set subnet ", "").strip().split()
                    if len(parts) >= 1:
                        current_block['address'] = parts[0]
                
                elif current_block and "set comment" in line:
                    comment = line.replace("set comment ", "").strip().strip('"')
                    current_block['comment'] = comment
                
                elif current_block and "next" in line:
                    if current_block['address']:
                        # Extraction de la date à partir du nom
                        try:
                            # Format: BLOCK_ML_192_168_1_100_20250422123456
                            date_str = current_block['name'].split('_')[-1]
                            if len(date_str) == 14:  # Format YYYYMMDDHHmmss
                                dt = datetime.strptime(date_str, "%Y%m%d%H%M%S")
                                current_block['block_date'] = dt.strftime("%Y-%m-%d %H:%M:%S")
                        except:
                            current_block['block_date'] = "Inconnu"
                        
                        blocked_ips.append(current_block)
                    current_block = None
            
            return blocked_ips
                
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des adresses IP bloquées: {str(e)}")
            return blocked_ips
    
    def check_ip_blocked(self, ip_address):
        """
        Vérifie si une adresse IP est bloquée
        
        Args:
            ip_address (str): Adresse IP à vérifier
            
        Returns:
            bool: True si l'adresse IP est bloquée, False sinon
        """
        try:
            # Récupération de la liste des objets d'adresse
            output, error = self.execute_command("show firewall address")
            if error:
                self.logger.error(f"Erreur lors de la récupération des objets d'adresse: {error}")
                return False
            
            # Recherche de l'adresse IP dans la sortie
            return f"subnet {ip_address} 255.255.255.255" in output
                
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification de l'adresse IP {ip_address}: {str(e)}")
            return False
