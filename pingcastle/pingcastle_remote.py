#!/usr/bin/env python3
"""
PingCastle Remote Execution Tool
Automatise l'exécution de PingCastle sur un DC distant depuis Kali
"""

import os
import sys
import yaml
import subprocess
import tempfile
import shutil
import time
import zipfile
from pathlib import Path
from datetime import datetime

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class PingCastleRemote:
    def __init__(self, config_file):
        self.config = self.load_config(config_file)
        self.temp_mount = None
        
    def load_config(self, config_file):
        """Charge la configuration depuis le fichier YAML"""
        print(f"{Colors.OKBLUE}[*] Chargement de la configuration...{Colors.ENDC}")
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            print(f"{Colors.OKGREEN}[+] Configuration chargée avec succès{Colors.ENDC}")
            return config
        except Exception as e:
            print(f"{Colors.FAIL}[!] Erreur lors du chargement de la config: {e}{Colors.ENDC}")
            sys.exit(1)
    
    def check_dependencies(self):
        """Vérifie que les outils nécessaires sont installés"""
        print(f"{Colors.OKBLUE}[*] Vérification des dépendances...{Colors.ENDC}")
        
        dependencies = {
            'impacket-psexec': 'impacket-scripts',
            'impacket-wmiexec': 'impacket-scripts',
            'impacket-smbexec': 'impacket-scripts',
            'smbclient': 'smbclient',
            'mount.cifs': 'cifs-utils'
        }
        
        missing = []
        for cmd, package in dependencies.items():
            if shutil.which(cmd) is None:
                missing.append(f"{cmd} (package: {package})")
        
        if missing:
            print(f"{Colors.FAIL}[!] Dépendances manquantes:{Colors.ENDC}")
            for dep in missing:
                print(f"    - {dep}")
            print(f"\n{Colors.WARNING}Installer avec: sudo apt install impacket-scripts smbclient cifs-utils{Colors.ENDC}")
            return False
        
        print(f"{Colors.OKGREEN}[+] Toutes les dépendances sont installées{Colors.ENDC}")
        return True
    
    def extract_pingcastle(self):
        """Extrait PingCastle du ZIP"""
        print(f"{Colors.OKBLUE}[*] Extraction de PingCastle...{Colors.ENDC}")
        
        zip_path = self.config['pingcastle']['local_path']
        if not os.path.exists(zip_path):
            print(f"{Colors.FAIL}[!] Fichier ZIP introuvable: {zip_path}{Colors.ENDC}")
            return None
        
        # Créer un dossier temporaire
        extract_dir = tempfile.mkdtemp(prefix='pingcastle_')
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            print(f"{Colors.OKGREEN}[+] PingCastle extrait dans: {extract_dir}{Colors.ENDC}")
            return extract_dir
        except Exception as e:
            print(f"{Colors.FAIL}[!] Erreur lors de l'extraction: {e}{Colors.ENDC}")
            return None
    
    def mount_smb_share(self):
        """Monte le partage SMB du DC"""
        print(f"{Colors.OKBLUE}[*] Montage du partage SMB...{Colors.ENDC}")
        
        dc_ip = self.config['target']['dc_ip']
        domain = self.config['target']['domain']
        username = self.config['credentials']['username']
        password = self.config['credentials']['password']
        
        # Créer un point de montage temporaire
        self.temp_mount = tempfile.mkdtemp(prefix='dc_mount_')
        
        # Construire les options de montage
        mount_options = f'username={username},password={password},domain={domain},vers=3.0'
        
        mount_cmd = [
            'sudo', 'mount', '-t', 'cifs',
            f'//{dc_ip}/C$',
            self.temp_mount,
            '-o',
            mount_options
        ]
        
        try:
            result = subprocess.run(mount_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                print(f"{Colors.OKGREEN}[+] Partage monté sur: {self.temp_mount}{Colors.ENDC}")
                return True
            else:
                print(f"{Colors.FAIL}[!] Erreur de montage: {result.stderr}{Colors.ENDC}")
                # Tenter sans spécifier le domaine en cas d'échec
                print(f"{Colors.WARNING}[*] Tentative sans spécifier le domaine...{Colors.ENDC}")
                mount_options_nodomain = f'username={username},password={password},vers=3.0'
                mount_cmd[6] = mount_options_nodomain
                result = subprocess.run(mount_cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    print(f"{Colors.OKGREEN}[+] Partage monté sur: {self.temp_mount}{Colors.ENDC}")
                    return True
                else:
                    print(f"{Colors.FAIL}[!] Échec: {result.stderr}{Colors.ENDC}")
                    return False
        except Exception as e:
            print(f"{Colors.FAIL}[!] Erreur: {e}{Colors.ENDC}")
            return False
    
    def copy_to_dc(self, local_path):
        """Copie PingCastle sur le DC"""
        print(f"{Colors.OKBLUE}[*] Copie de PingCastle sur le DC...{Colors.ENDC}")
        
        # Convertir le chemin Windows en chemin Linux
        remote_path = self.config['pingcastle']['remote_path'].replace('C:\\', '').replace('\\', '/')
        dest_path = os.path.join(self.temp_mount, remote_path)
        
        try:
            # Créer le dossier de destination
            os.makedirs(dest_path, exist_ok=True)
            
            # Copier tous les fichiers
            for item in os.listdir(local_path):
                src = os.path.join(local_path, item)
                dst = os.path.join(dest_path, item)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)
                    print(f"    - Copie: {item}")
            
            # Créer un script batch pour faciliter l'exécution
            print(f"{Colors.OKBLUE}[*] Création du script d'exécution...{Colors.ENDC}")
            batch_content = f'''@echo off
cd /d {self.config['pingcastle']['remote_path']}
PingCastle.exe {' '.join(self.config['pingcastle']['options'])} --server {self.config['target']['dc_name']} --no-enum-limit
'''
            batch_path = os.path.join(dest_path, 'run_pingcastle.bat')
            with open(batch_path, 'w') as f:
                f.write(batch_content)
            print(f"    - Script batch créé: run_pingcastle.bat")
            
            print(f"{Colors.OKGREEN}[+] Fichiers copiés avec succès{Colors.ENDC}")
            return True
        except Exception as e:
            print(f"{Colors.FAIL}[!] Erreur lors de la copie: {e}{Colors.ENDC}")
            return False
    
    def unmount_smb_share(self):
        """Démonte le partage SMB"""
        if self.temp_mount:
            print(f"{Colors.OKBLUE}[*] Démontage du partage...{Colors.ENDC}")
            try:
                subprocess.run(['sudo', 'umount', self.temp_mount], timeout=10)
                os.rmdir(self.temp_mount)
                print(f"{Colors.OKGREEN}[+] Partage démonté{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.WARNING}[!] Erreur lors du démontage: {e}{Colors.ENDC}")
    
    def execute_pingcastle(self):
        """Execute PingCastle sur le DC à distance"""
        print(f"{Colors.OKBLUE}[*] Exécution de PingCastle sur le DC...{Colors.ENDC}")
        
        method = self.config['execution']['method']
        dc_ip = self.config['target']['dc_ip']
        domain = self.config['target']['domain']
        username = self.config['credentials']['username']
        password = self.config['credentials']['password']
        remote_path = self.config['pingcastle']['remote_path']
        
        # Utiliser le script batch pour éviter les problèmes de dépendances
        target = f'{domain}/{username}:{password}@{dc_ip}'
        pingcastle_cmd = f'{remote_path}\\run_pingcastle.bat'
        
        # Définir la variable d'environnement pour le mot de passe si nécessaire
        env = os.environ.copy()
        
        if method == 'wmiexec':
            cmd = ['impacket-wmiexec', target, pingcastle_cmd]
        elif method == 'psexec':
            cmd = ['impacket-psexec', target, pingcastle_cmd]
        elif method == 'smbexec':
            cmd = ['impacket-smbexec', target, pingcastle_cmd]
        else:
            print(f"{Colors.FAIL}[!] Méthode d'exécution inconnue: {method}{Colors.ENDC}")
            return False
        
        print(f"{Colors.OKCYAN}[*] Méthode: {method}{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Cela peut prendre plusieurs minutes...{Colors.ENDC}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config['execution']['timeout'],
                env=env
            )
            
            # PingCastle peut retourner différents codes de retour
            if 'completed' in result.stdout.lower() or 'healthcheck' in result.stdout.lower() or result.returncode == 0:
                print(f"{Colors.OKGREEN}[+] PingCastle exécuté avec succès!{Colors.ENDC}")
                if result.stdout:
                    print(f"\n{Colors.OKCYAN}Output:{Colors.ENDC}")
                    print(result.stdout[-2000:])  # Dernières 2000 caractères
                return True
            else:
                print(f"{Colors.WARNING}[!] L'exécution s'est terminée avec des avertissements{Colors.ENDC}")
                print(f"Return code: {result.returncode}")
                if result.stdout:
                    print(f"\n{Colors.OKCYAN}Output:{Colors.ENDC}")
                    print(result.stdout[-2000:])
                if result.stderr:
                    print(f"\n{Colors.WARNING}Stderr:{Colors.ENDC}")
                    print(result.stderr[-1000:])
                # Continuer quand même pour récupérer les résultats
                return True
                
        except subprocess.TimeoutExpired:
            print(f"{Colors.FAIL}[!] Timeout - L'exécution a pris trop de temps{Colors.ENDC}")
            print(f"{Colors.WARNING}[*] Les fichiers peuvent quand même avoir été générés, tentative de récupération...{Colors.ENDC}")
            return True  # Continuer pour tenter de récupérer les résultats
        except Exception as e:
            print(f"{Colors.FAIL}[!] Erreur: {e}{Colors.ENDC}")
            return False
    
    def retrieve_results(self):
        """Récupère les résultats depuis le DC"""
        print(f"{Colors.OKBLUE}[*] Récupération des résultats..{Colors.ENDC}")
        
        # Remonter le partage
        if not self.mount_smb_share():
            return False
        
        # Convertir le chemin Windows en chemin Linux
        remote_path = self.config['pingcastle']['remote_path'].replace('C:\\', '').replace('\\', '/')
        source_path = os.path.join(self.temp_mount, remote_path)
        
        # Créer le dossier de résultats local
        results_dir = self.config['output']['local_results']
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = os.path.join(results_dir, f"pingcastle_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            # Copier les fichiers HTML et XML
            extensions = ['.html', '.xml']
            files_copied = 0
            
            for file in os.listdir(source_path):
                if any(file.endswith(ext) for ext in extensions):
                    src = os.path.join(source_path, file)
                    dst = os.path.join(output_dir, file)
                    shutil.copy2(src, dst)
                    print(f"    - Récupéré: {file}")
                    files_copied += 1
            
            if files_copied > 0:
                print(f"{Colors.OKGREEN}[+] {files_copied} fichier(s) récupéré(s) dans: {output_dir}{Colors.ENDC}")
                
                # Cleanup optionnel
                if self.config['output']['cleanup']:
                    print(f"{Colors.OKBLUE}[*] Nettoyage des fichiers sur le DC...{Colors.ENDC}")
                    shutil.rmtree(source_path)
                    print(f"{Colors.OKGREEN}[+] Nettoyage effectué{Colors.ENDC}")
                
                return True
            else:
                print(f"{Colors.WARNING}[!] Aucun fichier de résultat trouvé{Colors.ENDC}")
                return False
                
        except Exception as e:
            print(f"{Colors.FAIL}[!] Erreur lors de la récupération: {e}{Colors.ENDC}")
            return False
        finally:
            self.unmount_smb_share()
    
    def run(self):
        """Execute le processus complet"""
        print(f"{Colors.HEADER}{Colors.BOLD}")
        print("=" * 60)
        print("    PingCastle Remote Execution Tool")
        print("=" * 60)
        print(f"{Colors.ENDC}")
        
        # Vérifications
        if not self.check_dependencies():
            return False
        
        # Extraction
        extract_dir = self.extract_pingcastle()
        if not extract_dir:
            return False
        
        try:
            # Montage et copie
            if not self.mount_smb_share():
                return False
            
            if not self.copy_to_dc(extract_dir):
                self.unmount_smb_share()
                return False
            
            self.unmount_smb_share()
            
            # Exécution
            if not self.execute_pingcastle():
                return False
            
            # Attendre un peu pour que les fichiers soient générés
            print(f"{Colors.OKBLUE}[*] Attente de la génération des rapports (10s)...{Colors.ENDC}")
            time.sleep(10)
            
            # Récupération des résultats
            if not self.retrieve_results():
                return False
            
            print(f"\n{Colors.OKGREEN}{Colors.BOLD}[✓] Processus terminé avec succès{Colors.ENDC}")
            return True
            
        finally:
            # Nettoyage
            if extract_dir and os.path.exists(extract_dir):
                shutil.rmtree(extract_dir)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <config.yaml>")
        sys.exit(1)
    
    config_file = sys.argv[1]
    if not os.path.exists(config_file):
        print(f"{Colors.FAIL}[!] Fichier de configuration introuvable: {config_file}{Colors.ENDC}")
        sys.exit(1)
    
    pc = PingCastleRemote(config_file)
    success = pc.run()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
