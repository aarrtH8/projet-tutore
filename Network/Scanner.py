#!/usr/bin/env python3
"""
Scanner de sécurité automatisé avec Nmap
Lit la configuration depuis un fichier XML et scanne automatiquement les hôtes up
"""

import subprocess
import xml.etree.ElementTree as ET
import re
import sys
import os
from datetime import datetime
from typing import List, Set, Tuple, Dict

class Colors:
    """Codes de couleurs ANSI pour l'affichage"""
    BLUE = '\033[1;34m'
    CYAN = '\033[1;36m'
    YELLOW = '\033[1;33m'
    RED = '\033[1;31m'
    PURPLE = '\033[1;35m'
    GREEN = '\033[1;32m'
    RESET = '\033[0m'


class Config:
    """Classe pour gérer la configuration du scanner"""
    
    def __init__(self, config_file: str = 'config.xml'):
        self.config_file = config_file
        self.networks: List[str] = []
        self.hosts: List[str] = []
        self.exclude: List[str] = []
        self.search_exploits: bool = False
        self.samba: bool = False
        self.whatweb: bool = False
        self.enable_topology: bool = False
        self.log_commands: bool = False
        self.command_log_file: str = 'nmap_commands.txt'
        
        self._load_config()
    
    def _load_config(self):
        """Charge la configuration depuis le fichier XML"""
        try:
            tree = ET.parse(self.config_file)
            root = tree.getroot()
            
            # Charger les réseaux
            networks = root.find('networks')
            if networks is not None:
                self.networks = [net.text.strip() for net in networks.findall('network') if net.text]
            
            # Charger les hôtes
            hosts = root.find('hosts')
            if hosts is not None:
                self.hosts = [host.text.strip() for host in hosts.findall('host') if host.text]
            
            # Charger les exclusions
            exclude = root.find('exclude')
            if exclude is not None:
                self.exclude = [entry.text.strip() for entry in exclude.findall('entry') if entry.text]
            
            # Charger les options
            options = root.find('options')
            if options is not None:
                self.search_exploits = options.find('search_exploits').text.lower() == 'true' if options.find('search_exploits') is not None else False
                self.samba = options.find('samba').text.lower() == 'true' if options.find('samba') is not None else False
                self.whatweb = options.find('whatweb').text.lower() == 'true' if options.find('whatweb') is not None else False
                self.enable_topology = options.find('enable_topology').text.lower() == 'true' if options.find('enable_topology') is not None else False
                self.log_commands = options.find('log_commands').text.lower() == 'true' if options.find('log_commands') is not None else False
                
                cmd_log = options.find('command_log_file')
                if cmd_log is not None and cmd_log.text:
                    self.command_log_file = cmd_log.text.strip()
            
            print(f"{Colors.GREEN}Configuration chargée depuis {self.config_file}{Colors.RESET}")
            
        except FileNotFoundError:
            print(f"{Colors.RED}Erreur: Fichier de configuration {self.config_file} introuvable{Colors.RESET}")
            sys.exit(1)
        except ET.ParseError as e:
            print(f"{Colors.RED}Erreur de parsing XML: {e}{Colors.RESET}")
            sys.exit(1)


class NetworkScanner:
    """Classe principale pour le scanner réseau"""
    
    def __init__(self, config: Config):
        self.config = config
        self.output_dir = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
        self.open_ports_cache: Dict[str, str] = {}
        
    def log_command(self, command: str):
        """Enregistre une commande dans le fichier de log si activé"""
        if self.config.log_commands:
            with open(os.path.join(self.output_dir, self.config.command_log_file), 'a') as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {command}\n")
    
    def run_command(self, command: List[str], description: str = "", capture_output: bool = True) -> Tuple[int, str, str]:
        """Exécute une commande et retourne le code de retour, stdout et stderr"""
        cmd_str = ' '.join(command)
        if description:
            print(f"{Colors.CYAN}{description}{Colors.RESET}")
        
        self.log_command(cmd_str)
        
        try:
            if capture_output:
                result = subprocess.run(command, capture_output=True, text=True)
                return result.returncode, result.stdout, result.stderr
            else:
                result = subprocess.run(command)
                return result.returncode, "", ""
        except FileNotFoundError:
            print(f"{Colors.RED}Erreur: Commande '{command[0]}' introuvable. Assurez-vous qu'elle est installée.{Colors.RESET}")
            return 1, "", ""
    
    def discover_hosts(self) -> Set[str]:
        """Découvre les hôtes actifs sur les réseaux configurés"""
        active_hosts = set()
        
        # Ajouter les hôtes individuels configurés
        active_hosts.update(self.config.hosts)
        
        # Scanner les réseaux pour trouver les hôtes up
        for network in self.config.networks:
            print(f"\n{Colors.BLUE}═══════════════════════════════════════════════════{Colors.RESET}")
            print(f"{Colors.BLUE}Découverte des hôtes sur {network}{Colors.RESET}")
            print(f"{Colors.BLUE}═══════════════════════════════════════════════════{Colors.RESET}\n")
            
            output_file = os.path.join(self.output_dir, f"discovery_{network.replace('/', '_')}.txt")
            
            # Construction de la commande nmap pour la découverte
            command = ['nmap', '-sn', network, '-oN', output_file]
            
            # Ajouter les exclusions si présentes
            if self.config.exclude:
                command.extend(['--exclude', ','.join(self.config.exclude)])
            
            returncode, stdout, stderr = self.run_command(
                command,
                f"Scan de découverte en cours..."
            )
            
            if returncode != 0:
                print(f"{Colors.RED}Erreur lors du scan de découverte sur {network}{Colors.RESET}")
                continue
            
            # Parser le fichier de sortie pour extraire les IPs des hôtes up
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    # Chercher les lignes "Nmap scan report for X.X.X.X"
                    ip_pattern = r'Nmap scan report for (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                    found_ips = re.findall(ip_pattern, content)
                    
                    # Vérifier que l'hôte est "up" et pas down
                    for ip in found_ips:
                        # Chercher la section concernant cette IP
                        ip_section = re.search(
                            rf'Nmap scan report for {re.escape(ip)}.*?(?=Nmap scan report|$)',
                            content,
                            re.DOTALL
                        )
                        if ip_section and 'Host is up' in ip_section.group(0):
                            active_hosts.add(ip)
                    
                    print(f"{Colors.GREEN}Trouvé {len(found_ips)} hôte(s) actif(s) sur {network}{Colors.RESET}")
                    for ip in found_ips:
                        print(f"  → {ip}")
                        
            except Exception as e:
                print(f"{Colors.RED}Erreur lors de l'analyse des résultats: {e}{Colors.RESET}")
        
        # Filtrer les hôtes exclus
        for exclude in self.config.exclude:
            if exclude in active_hosts:
                active_hosts.remove(exclude)
                print(f"{Colors.YELLOW}Hôte {exclude} exclu de l'analyse{Colors.RESET}")
        
        return active_hosts
    
    def print_banner(self, text: str, color: str = Colors.BLUE):
        """Affiche une bannière ASCII art"""
        banners = {
            'NMAP': r"""
 ███╗   ██╗███╗   ███╗ █████╗ ██████╗ 
 ████╗  ██║████╗ ████║██╔══██╗██╔══██╗
 ██╔██╗ ██║██╔████╔██║███████║██████╔╝
 ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ 
 ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     
 ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     """,
            
            'SEARCHSPLOIT': r"""
███████╗███████╗ █████╗ ██████╗  ██████╗██╗  ██╗███████╗██████╗ ██╗      ██████╗ ██╗████████╗
██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
███████╗█████╗  ███████║███████║██║     ███████║███████╗██████╔╝██║     ██║   ██║██║   ██║   
╚════██║██╔══╝  ██╔══██║██╔══██╗██║     ██╔══██║╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   
███████║███████╗██║  ██║██║  ██║╚██████╗██║  ██║███████║██║     ███████╗╚██████╔╝██║   ██║   
╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   """,
            
            'ENUM4LINUX': r"""
███████╗███╗   ██╗██╗   ██╗███╗   ███╗██╗  ██╗██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗
██╔════╝████╗  ██║██║   ██║████╗ ████║██║  ██║██║     ██║████╗  ██║██║   ██║╚██╗██╔╝
█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║███████║██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝ 
██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║╚════██║██║     ██║██║╚██╗██║██║   ██║ ██╔██╗ 
███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║     ██║███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗
╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝     ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝""",
            
            'WHATWEB': r"""
██╗    ██╗██╗  ██╗ █████╗ ████████╗██╗    ██╗███████╗██████╗ 
██║    ██║██║  ██║██╔══██╗╚══██╔══╝██║    ██║██╔════╝██╔══██╗
██║ █╗ ██║███████║███████║   ██║   ██║ █╗ ██║█████╗  ██████╔╝
██║███╗██║██╔══██║██╔══██║   ██║   ██║███╗██║██╔══╝  ██╔══██╗
╚███╔███╔╝██║  ██║██║  ██║   ██║   ╚███╔███╔╝███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝"""}
        
        if text in banners:
            print(f"{color}{banners[text]}{Colors.RESET}")
    
    def scan_ports_initial(self, target_ip: str) -> Tuple[str, int]:
        """
        Scan initial des ports (tous les ports TCP)
        Retourne: (ports_ouverts, nombre_de_ports)
        """
        print(f"\n{Colors.CYAN}═══════════════════════════════════════════════════{Colors.RESET}")
        print(f"{Colors.CYAN}Scan initial des ports sur {target_ip}{Colors.RESET}")
        print(f"{Colors.CYAN}═══════════════════════════════════════════════════{Colors.RESET}\n")
        
        output_file = os.path.join(self.output_dir, f"{target_ip}_initial_scan.txt")
        
        command = [
            'nmap',
            '-p-',              # Tous les ports
            '--open',           # Uniquement les ports ouverts
            target_ip,
            '-oN', output_file
        ]
        
        returncode, stdout, stderr = self.run_command(
            command,
            "Scan des 65535 ports en cours (cela peut prendre du temps)..."
        )
        
        if returncode != 0:
            print(f"{Colors.RED}Erreur lors du scan initial{Colors.RESET}")
            return "", 0
        
        # Parser les résultats
        open_ports = []
        open_services = []
        
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    # Chercher les lignes avec des ports ouverts
                    match = re.match(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)', line)
                    if match:
                        port = match.group(1)
                        service = match.group(3)
                        open_ports.append(port)
                        open_services.append(service)
            
            ports_str = ','.join(open_ports)
            num_ports = len(open_ports)
            
            print(f"{Colors.GREEN}Nombre de ports ouverts : {num_ports}{Colors.RESET}")
            print(f"{Colors.GREEN}Ports ouverts : {ports_str}{Colors.RESET}")
            print(f"{Colors.GREEN}Services : {', '.join(open_services)}{Colors.RESET}")
            
            return ports_str, num_ports
            
        except Exception as e:
            print(f"{Colors.RED}Erreur lors de l'analyse: {e}{Colors.RESET}")
            return "", 0
    
    def scan_ports_detailed(self, target_ip: str, open_ports: str):
        """
        Re-scan des ports ouverts avec détection de service et scripts
        """
        if not open_ports:
            print(f"{Colors.YELLOW}Aucun port ouvert à analyser{Colors.RESET}")
            return
        
        print(f"\n{Colors.BLUE}═══════════════════════════════════════════════════{Colors.RESET}")
        self.print_banner('NMAP', Colors.BLUE)
        print(f"{Colors.BLUE}═══════════════════════════════════════════════════{Colors.RESET}\n")
        print(f"{Colors.BLUE}Scan détaillé des ports ouverts...{Colors.RESET}\n")
        
        txt_output = os.path.join(self.output_dir, f"{target_ip}_detailed_scan.txt")
        xml_output = os.path.join(self.output_dir, f"{target_ip}_detailed_scan.xml")
        
        command = [
            'nmap',
            '-p', open_ports,
            '-sC',              # Scripts par défaut
            '-sV',              # Détection de version
            '-O',               # Détection de l'OS
            '-oX', xml_output,
            '-oN', txt_output,
            target_ip
        ]
        
        returncode, stdout, stderr = self.run_command(
            command,
            "Scan détaillé en cours..."
        )
        
        if returncode == 0:
            # Afficher les résultats des ports
            try:
                with open(txt_output, 'r') as f:
                    content = f.read()
                    # Extraire la section des ports
                    in_port_section = False
                    for line in content.split('\n'):
                        if re.match(r'^\d+/(tcp|udp)\s+open', line):
                            in_port_section = True
                            print(line)
                        elif in_port_section:
                            if line.strip() == '':
                                break
                            print(line)
            except Exception as e:
                print(f"{Colors.RED}Erreur lors de l'affichage des résultats: {e}{Colors.RESET}")
    
    def search_exploits(self, target_ip: str):
        """Recherche d'exploits avec searchsploit"""
        if not self.config.search_exploits:
            return
        
        xml_file = os.path.join(self.output_dir, f"{target_ip}_detailed_scan.xml")
        
        if not os.path.exists(xml_file):
            print(f"{Colors.YELLOW}Fichier XML non trouvé pour searchsploit{Colors.RESET}")
            return
        
        print(f"\n{Colors.YELLOW}═══════════════════════════════════════════════════{Colors.RESET}")
        self.print_banner('SEARCHSPLOIT', Colors.YELLOW)
        print(f"{Colors.YELLOW}═══════════════════════════════════════════════════{Colors.RESET}\n")
        print(f"{Colors.YELLOW}Recherche d'exploits avec Searchsploit...{Colors.RESET}\n")
        
        command = ['searchsploit', '--nmap', xml_file]
        
        returncode, stdout, stderr = self.run_command(command, capture_output=False)
        
        if returncode == 0:
            print(f"\n{Colors.YELLOW}Pour copier un exploit :{Colors.RESET}")
            print(f"searchsploit -m <numéro_exploit>")
    
    def scan_samba(self, target_ip: str):
        """Scan Samba avec enum4linux si les ports 139/445 sont ouverts"""
        if not self.config.samba:
            return
        
        scan_file = os.path.join(self.output_dir, f"{target_ip}_initial_scan.txt")
        
        if not os.path.exists(scan_file):
            return
        
        # Vérifier si les ports Samba sont ouverts
        has_samba = False
        try:
            with open(scan_file, 'r') as f:
                content = f.read()
                if re.search(r'^(445|139)/tcp\s+open', content, re.MULTILINE):
                    has_samba = True
        except Exception:
            return
        
        if not has_samba:
            print(f"{Colors.YELLOW}Ports Samba non détectés, skip enum4linux{Colors.RESET}")
            return
        
        print(f"\n{Colors.RED}═══════════════════════════════════════════════════{Colors.RESET}")
        self.print_banner('ENUM4LINUX', Colors.RED)
        print(f"{Colors.RED}═══════════════════════════════════════════════════{Colors.RESET}\n")
        print(f"{Colors.RED}Scan Samba avec Enum4linux...{Colors.RESET}\n")
        
        output_file = os.path.join(self.output_dir, f"{target_ip}_enum4linux.txt")
        
        command = ['enum4linux', '-a', target_ip]
        
        returncode, stdout, stderr = self.run_command(command)
        
        # Sauvegarder les résultats
        if stdout:
            with open(output_file, 'w') as f:
                f.write(stdout)
            print(stdout)
    
    def get_http_ports(self, target_ip: str) -> List[str]:
        """Récupère la liste des ports HTTP ouverts"""
        scan_file = os.path.join(self.output_dir, f"{target_ip}_initial_scan.txt")
        http_ports = []
        
        if not os.path.exists(scan_file):
            return http_ports
        
        try:
            with open(scan_file, 'r') as f:
                for line in f:
                    # Chercher les services HTTP/HTTPS
                    match = re.match(r'^(\d+)/tcp\s+open\s+(http|https|http-proxy)', line)
                    if match:
                        http_ports.append(match.group(1))
        except Exception:
            pass
        
        return http_ports
    
    def scan_whatweb(self, target_ip: str):
        """Scan HTTP avec WhatWeb"""
        if not self.config.whatweb:
            return
        
        http_ports = self.get_http_ports(target_ip)
        
        if not http_ports:
            print(f"{Colors.YELLOW}Aucun service HTTP détecté, skip WhatWeb{Colors.RESET}")
            return
        
        print(f"\n{Colors.BLUE}═══════════════════════════════════════════════════{Colors.RESET}")
        self.print_banner('WHATWEB', Colors.BLUE)
        print(f"{Colors.BLUE}═══════════════════════════════════════════════════{Colors.RESET}\n")
        
        for port in http_ports:
            print(f"{Colors.BLUE}Scan WhatWeb sur le port {port}...{Colors.RESET}\n")
            
            output_file = os.path.join(self.output_dir, f"{target_ip}_whatweb_{port}.txt")
            
            url = f"http://{target_ip}:{port}"
            command = ['whatweb', url]
            
            returncode, stdout, stderr = self.run_command(command)
            
            if stdout:
                print(stdout)
                with open(output_file, 'w') as f:
                    f.write(stdout)
    
    
    def scan_host(self, target_ip: str):
        """Scan complet d'un hôte"""
        print(f"\n{'=' * 80}")
        print(f"{Colors.CYAN}DÉBUT DU SCAN DE {target_ip}{Colors.RESET}")
        print(f"{'=' * 80}\n")
        
        # Scan initial des ports
        open_ports, num_ports = self.scan_ports_initial(target_ip)
        
        if num_ports == 0:
            print(f"{Colors.YELLOW}Aucun port ouvert détecté sur {target_ip}{Colors.RESET}")
            return
        
        # Stocker les ports ouverts pour cet hôte
        self.open_ports_cache[target_ip] = open_ports
        
        # Scan détaillé
        self.scan_ports_detailed(target_ip, open_ports)
        
        # Recherche d'exploits
        self.search_exploits(target_ip)
        
        # Scan Samba
        self.scan_samba(target_ip)
        
        # Scan WhatWeb
        self.scan_whatweb(target_ip)
        
        print(f"\n{'=' * 80}")
        print(f"{Colors.GREEN}FIN DU SCAN DE {target_ip}{Colors.RESET}")
        print(f"{'=' * 80}\n")
    
    def run(self):
        """Exécute le scan complet"""
        print(f"\n{Colors.CYAN}╔═══════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.CYAN}║     SCANNER DE SÉCURITÉ AUTOMATISÉ - NMAP        ║{Colors.RESET}")
        print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════╝{Colors.RESET}\n")
        
        print(f"{Colors.YELLOW}Répertoire de sortie : {self.output_dir}{Colors.RESET}\n")
        
        # Découverte des hôtes
        active_hosts = self.discover_hosts()
        
        if not active_hosts:
            print(f"{Colors.RED}Aucun hôte actif trouvé{Colors.RESET}")
            return
        
        print(f"\n{Colors.GREEN}═══════════════════════════════════════════════════{Colors.RESET}")
        print(f"{Colors.GREEN}HÔTES ACTIFS À SCANNER : {len(active_hosts)}{Colors.RESET}")
        print(f"{Colors.GREEN}═══════════════════════════════════════════════════{Colors.RESET}")
        for host in sorted(active_hosts):
            print(f"  → {host}")
        print()
        
        # Scanner chaque hôte
        for host in sorted(active_hosts):
            try:
                self.scan_host(host)
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Interruption utilisateur{Colors.RESET}")
                break
            except Exception as e:
                print(f"{Colors.RED}Erreur lors du scan de {host}: {e}{Colors.RESET}")
                continue
        
        print(f"\n{Colors.GREEN}╔═══════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.GREEN}║           SCAN TERMINÉ AVEC SUCCÈS                ║{Colors.RESET}")
        print(f"{Colors.GREEN}╚═══════════════════════════════════════════════════╝{Colors.RESET}")
        print(f"\n{Colors.YELLOW}Les résultats sont disponibles dans : {self.output_dir}{Colors.RESET}\n")


def main():
    """Point d'entrée principal"""
    # Vérifier si le script est exécuté en tant que root
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}Attention: Certaines fonctionnalités nécessitent les privilèges root{Colors.RESET}")
        print(f"{Colors.YELLOW}Exécutez avec sudo pour de meilleurs résultats{Colors.RESET}\n")
    
    # Charger la configuration
    config_file = 'config.xml'
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    
    try:
        config = Config(config_file)
        scanner = NetworkScanner(config)
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Programme interrompu par l'utilisateur{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Erreur: {e}{Colors.RESET}")
        sys.exit(1)


if __name__ == '__main__':
    main()