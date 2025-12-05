#!/usr/bin/env python3
"""
Scanner de sécurité automatisé avec Nmap
Lit la configuration depuis un fichier XML et scanne automatiquement les hôtes up
"""

import argparse
import subprocess
import xml.etree.ElementTree as ET
import re
import sys
import os
import json
import shutil
import ipaddress
from datetime import datetime
from typing import List, Set, Tuple, Dict, Any, Union

try:
    import networkx as nx
except ImportError:
    nx = None

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
        self.topology_only: bool = False
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
                self.topology_only = options.find('topology_only').text.lower() == 'true' if options.find('topology_only') is not None else False
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
    
    def __init__(self, config: Config, skip_scans: bool = False):
        self.config = config
        self.skip_scans = skip_scans
        self.output_dir = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
        self.open_ports_cache: Dict[str, str] = {}
        self.traceroute_cache: Dict[str, List[str]] = {}
        self.node_type_styles = self._build_node_type_styles()

    def _build_node_type_styles(self) -> Dict[str, Dict[str, Any]]:
        """Définit les styles partagés par type de noeud"""
        def make_style(display: str, code: str, color_hex: str, size: int, level: int) -> Dict[str, Any]:
            transparent = {
                "border": "rgba(0,0,0,0)",
                "background": "rgba(0,0,0,0)",
                "highlight": {"border": color_hex, "background": "rgba(255,255,255,0.06)"},
                "hover": {"border": color_hex, "background": "rgba(255,255,255,0.08)"},
            }
            return {
                "display": display,
                "shape": "icon",
                "icon": {"face": "FontAwesome", "code": code, "size": size, "color": color_hex},
                "color": transparent,
                "level": level
            }
        
        return {
            "scanner": make_style("Scanner", "\uf109", "#f97316", 40, 0),
            "network": make_style("Réseau", "\uf0ac", "#22d3ee", 32, 1),
            "gateway": make_style("Passerelle", "\uf6ff", "#a78bfa", 30, 2),
            "domain_controller": make_style("Contrôleur de domaine", "\uf233", "#fb7185", 34, 3),
            "windows": make_style("Hôte Windows", "\uf17a", "#38bdf8", 32, 3),
            "linux": make_style("Hôte Linux", "\uf17c", "#4ade80", 32, 3),
            "web": make_style("Serveur Web", "\uf0ac", "#fbbf24", 30, 3),
            "dns": make_style("Serveur DNS", "\uf124", "#f472b6", 30, 3),
            "mail": make_style("Serveur Mail", "\uf0e0", "#60a5fa", 30, 3),
            "database": make_style("Base de données", "\uf1c0", "#34d399", 30, 3),
            "host": make_style("Hôte générique", "\uf233", "#f5f5f4", 28, 3),
            "unknown": make_style("Inconnu", "\uf128", "#94a3b8", 28, 3),
        }

    def _get_style_for_type(self, node_type: str) -> Dict[str, Any]:
        """Retourne le style (icône/couleur) pour un type donné"""
        return self.node_type_styles.get(node_type, self.node_type_styles["unknown"])

    def infer_host_type(self, host: str) -> str:
        """Déduit un type de machine basique selon les ports ouverts connus"""
        open_ports = self.open_ports_cache.get(host, "")
        if not open_ports:
            return "unknown"
        
        port_set = {p.strip() for p in open_ports.split(',') if p.strip()}
        
        def has_ports(*values: str) -> bool:
            return any(p in port_set for p in values)
        
        if has_ports('88', '389', '636') and has_ports('445'):
            return "domain_controller"
        if has_ports('445', '3389'):
            return "windows"
        if has_ports('53',):
            return "dns"
        if has_ports('25', '110', '143', '587'):
            return "mail"
        if has_ports('80', '443', '8080', '8443'):
            return "web"
        if has_ports('22'):
            return "linux"
        if has_ports('3306', '5432', '1433'):
            return "database"
        return "host"
        
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
    
    def run_traceroute(self, target_ip: str) -> List[str]:
        """Exécute un traceroute et retourne la liste des sauts (IPs)"""
        if target_ip in self.traceroute_cache:
            return self.traceroute_cache[target_ip]
        
        if shutil.which('traceroute') is None:
            print(f"{Colors.YELLOW}Commande 'traceroute' introuvable - impossible de générer la topologie{Colors.RESET}")
            self.traceroute_cache[target_ip] = []
            return []
        
        description = f"Collecte du chemin réseau vers {target_ip} (traceroute)..."
        command = ['traceroute', '-n', '-w', '1', '-q', '1', target_ip]
        returncode, stdout, stderr = self.run_command(command, description)
        
        hops: List[str] = []
        if returncode != 0:
            print(f"{Colors.YELLOW}Traceroute vers {target_ip} indisponible ({stderr.strip()}){Colors.RESET}")
            self.traceroute_cache[target_ip] = []
            return []
        
        hop_pattern = re.compile(r'^\s*\d+\s+(\d{1,3}(?:\.\d{1,3}){3})')
        for line in stdout.splitlines():
            if 'traceroute to' in line.lower():
                continue
            match = hop_pattern.match(line)
            if match:
                hops.append(match.group(1))
        
        self.traceroute_cache[target_ip] = hops
        return hops
    
    def generate_topology_view(self, hosts: List[str]):
        """Construit une vue topologique interactive des hôtes scannés"""
        if not hosts:
            return
        if not self.config.enable_topology:
            return
        if nx is None:
            print(f"{Colors.YELLOW}Module 'networkx' manquant - impossible de générer la topologie{Colors.RESET}")
            return
        
        print(f"\n{Colors.PURPLE}Génération de la topologie réseau...{Colors.RESET}")
        
        graph = nx.Graph()
        scanner_name = os.uname().nodename if hasattr(os, 'uname') else 'Scanner'
        scanner_id = 'scanner_local'
        scanner_style = self._get_style_for_type("scanner")
        graph.add_node(
            scanner_id,
            label=f"Scanner\n{scanner_name}",
            group='scanner',
            shape=scanner_style.get("shape", "icon"),
            title=f"Noeud scanner ({scanner_name})",
            icon=scanner_style.get("icon"),
            color=scanner_style.get("color"),
            node_type='scanner',
            level=scanner_style.get("level", 0)
        )
        
        # Préparer les réseaux configurés pour contextualiser les hôtes
        network_nodes: Dict[str, Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = {}
        for network_str in self.config.networks:
            try:
                net_obj = ipaddress.ip_network(network_str, strict=False)
                network_nodes[network_str] = net_obj
                graph.add_node(
                    network_str,
                    label=str(net_obj),
                    group='network',
                    shape=self.node_type_styles['network']['shape'],
                    title=f"Réseau déclaré {net_obj}",
                    icon=self.node_type_styles['network']['icon'],
                    color=self.node_type_styles['network']['color'],
                    node_type='network',
                    level=self.node_type_styles['network'].get("level", 1)
                )
            except ValueError:
                print(f"{Colors.YELLOW}CIDR invalide ignoré pour la topologie: {network_str}{Colors.RESET}")
        
        edges_added = set()
        paths_summary = []
        
        for host in hosts:
            hops = self.run_traceroute(host)
            tooltip = f"{host}"
            ports = self.open_ports_cache.get(host)
            if ports:
                tooltip += f"<br/>Ports ouverts: {ports}"
            host_type = self.infer_host_type(host)
            host_style = self._get_style_for_type(host_type)
            
            graph.add_node(
                host,
                label=host,
                group=host_type,
                shape=host_style.get("shape", "icon"),
                title=tooltip,
                icon=host_style.get("icon"),
                color=host_style.get("color"),
                node_type=host_type,
                level=host_style.get("level", 3)
            )
            
            previous = scanner_id
            for hop in hops:
                gateway_style = self._get_style_for_type("gateway")
                graph.add_node(
                    hop,
                    label=hop,
                    group='gateway',
                    shape=gateway_style.get("shape", "icon"),
                    title=f"Saut intermédiaire {hop}",
                    icon=gateway_style.get("icon"),
                    color=gateway_style.get("color"),
                    node_type='gateway',
                    level=gateway_style.get("level", 2)
                )
                edge = tuple(sorted((previous, hop)))
                if edge not in edges_added:
                    graph.add_edge(previous, hop)
                    edges_added.add(edge)
                previous = hop
            
            # Connecter l'ultime segment hop -> host
            edge = tuple(sorted((previous, host)))
            if edge not in edges_added:
                graph.add_edge(previous, host)
                edges_added.add(edge)
            
            # Lier l'hôte à ses réseaux déclarés (si applicables)
            try:
                ip_obj = ipaddress.ip_address(host)
                for net_label, net_obj in network_nodes.items():
                    if ip_obj in net_obj:
                        edge = tuple(sorted((host, net_label)))
                        if edge not in edges_added:
                            graph.add_edge(host, net_label)
                            edges_added.add(edge)
            except ValueError:
                pass
            
            paths_summary.append({
                "host": host,
                "hops": hops
            })
        
        nodes_data = []
        for node_id, attrs in graph.nodes(data=True):
            node_entry = {
                "id": node_id,
                "label": attrs.get("label", node_id),
                "group": attrs.get("group", "host"),
                "shape": attrs.get("shape", "dot"),
                "title": attrs.get("title", attrs.get("label", node_id)),
                "icon": attrs.get("icon"),
                "node_type": attrs.get("node_type", attrs.get("group", "host")),
                "color": attrs.get("color"),
                "level": attrs.get("level")
            }
            if attrs.get("shape") != "icon" and attrs.get("size"):
                node_entry["size"] = attrs.get("size")
            nodes_data.append(node_entry)
        
        edges_data = []
        for idx, (u, v) in enumerate(graph.edges()):
            edges_data.append({
                "id": f"edge_{idx}",
                "from": u,
                "to": v
            })
        
        topology_payload: Dict[str, Any] = {
            "generated_at": datetime.now().isoformat(),
            "scanner": scanner_name,
            "hosts": hosts,
            "paths": paths_summary,
            "nodes": nodes_data,
            "edges": edges_data,
            "node_types": self.node_type_styles
        }
        
        json_path = os.path.join(self.output_dir, 'network_topology.json')
        html_path = os.path.join(self.output_dir, 'network_topology.html')
        
        with open(json_path, 'w') as f:
            json.dump(topology_payload, f, indent=2)
        
        self._write_topology_html(topology_payload, html_path)
        print(f"{Colors.GREEN}Topologie disponible: {html_path}{Colors.RESET}")
    def _write_topology_html(self, payload: Dict[str, Any], destination: str):
        """Crée une interface HTML autonome pour la topologie"""
        data_json = json.dumps(payload)
        html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Vue topologique du réseau</title>
    <style>
        body {{ font-family: 'Inter', Arial, sans-serif; margin: 0; padding: 0; background: radial-gradient(circle at top, #0f172a, #020617); color: #f8fafc; }}
        header {{ padding: 24px 32px; background: rgba(15,23,42,0.85); border-bottom: 1px solid rgba(148,163,184,0.2); backdrop-filter: blur(6px); }}
        #workspace {{ display: flex; gap: 20px; flex-wrap: wrap; padding: 20px 32px 32px; }}
        #network {{ flex: 2 1 620px; height: 72vh; border: 1px solid rgba(148,163,184,0.2); border-radius: 20px; background: rgba(8,12,24,0.65); box-shadow: 0 20px 45px rgba(2,6,23,0.65); }}
        .panel {{ flex: 1 1 260px; background: rgba(15,23,42,0.9); padding: 20px; border-radius: 16px; box-shadow: 0 16px 35px rgba(2,6,23,0.7); border: 1px solid rgba(148,163,184,0.15); }}
        .panel h2 {{ margin-top: 0; color: #58a6ff; }}
        label {{ display: block; margin: 12px 0 6px; font-size: 0.9rem; }}
        input, select {{ width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #374151; background: #111827; color: #f8f8f2; }}
        button {{ margin-top: 12px; padding: 10px; width: 100%; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }}
        button.primary {{ background: #2563eb; color: #fff; }}
        button.danger {{ background: #dc2626; color: #fff; }}
        button:disabled {{ opacity: 0.5; cursor: not-allowed; }}
        .summary {{ margin: 0 32px 32px; background: rgba(15,23,42,0.9); padding: 18px; border-radius: 16px; border: 1px solid rgba(148,163,184,0.15); box-shadow: 0 16px 35px rgba(2,6,23,0.7); }}
        .summary strong {{ color: #38bdf8; }}
        #editor-status {{ font-style: italic; color: #9ca3af; margin-top: 4px; }}
    </style>
    <link rel="stylesheet" href="https://unpkg.com/vis-network/styles/vis-network.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
</head>
<body>
    <header>
        <h1>Topologie réseau - générée le {payload['generated_at']}</h1>
        <p>Scanner: {payload['scanner']} · Hôtes analysés: {len(payload['hosts'])}</p>
    </header>
    <div id="workspace">
        <div id="network"></div>
        <div class="panel">
            <h2>Édition du nœud</h2>
            <p id="editor-status">Sélectionnez un nœud dans le graphe.</p>
            <label for="node-label">Nom affiché</label>
            <input id="node-label" type="text" placeholder="Nom du nœud" />
            <label for="node-type">Type de noeud</label>
            <select id="node-type"></select>
            <button id="update-node" class="primary" disabled>Mettre à jour</button>
            <button id="delete-node" class="danger" disabled>Supprimer</button>
<<<<<<< ours
            <button id="toggle-hops" class="secondary" type="button">Masquer les liens intermédiaires</button>
=======
>>>>>>> theirs
        </div>
    </div>
    <div class="summary">
        <strong>Chemins observés:</strong>
        <ul>
            {''.join(f"<li>{item['host']} &rarr; {' &rarr; '.join(item['hops']) if item['hops'] else 'Chemin non disponible'}</li>" for item in payload['paths'])}
        </ul>
    </div>
    <script>
        const topologyData = {data_json};
        const NODE_TYPES = topologyData.node_types || {{}};
        const nodes = new vis.DataSet(topologyData.nodes);
        const edges = new vis.DataSet(topologyData.edges);
        const container = document.getElementById('network');
        const options = {{
            layout: {{
                improvedLayout: true
            }},
            interaction: {{
                hover: true,
                tooltipDelay: 200
            }},
            physics: {{
                solver: 'forceAtlas2Based',
                stabilization: {{
                    enabled: true,
                    iterations: 200
                }},
                forceAtlas2Based: {{
                    gravitationalConstant: -60,
                    centralGravity: 0.012,
                    springLength: 150,
                    damping: 0.82
                }}
            }},
            nodes: {{
                borderWidth: 0,
                shadow: true
            }},
            edges: {{
                arrows: {{
                    to: {{ enabled: false }}
                }},
                color: {{ color: '#64748b', highlight: '#38bdf8' }},
                width: 1.5,
                smooth: {{
                    enabled: true,
                    type: 'continuous',
                    roundness: 0.45
                }}
            }}
        }};
        const network = new vis.Network(container, {{ nodes, edges }}, options);

        const statusEl = document.getElementById('editor-status');
        const labelInput = document.getElementById('node-label');
        const typeSelect = document.getElementById('node-type');
        const updateBtn = document.getElementById('update-node');
        const deleteBtn = document.getElementById('delete-node');
        let selectedNodeId = null;
        let currentNodeType = null;
<<<<<<< ours
        let simplifiedView = false;
        const baseEdgeIds = new Set(edges.getIds());
        const summaryEdgeIds = new Set();
=======
>>>>>>> theirs

        function populateTypeOptions() {{
            typeSelect.innerHTML = '<option value=\"\">-- Choisir --</option>';
            Object.keys(NODE_TYPES).forEach((kind) => {{
                const option = document.createElement('option');
                option.value = kind;
                option.textContent = NODE_TYPES[kind].display || kind;
                typeSelect.appendChild(option);
            }});
        }}
        populateTypeOptions();

        function setEditorEnabled(enabled) {{
            labelInput.disabled = !enabled;
            typeSelect.disabled = !enabled;
            updateBtn.disabled = !enabled;
            deleteBtn.disabled = !enabled;
        }}

        function loadNodeData(nodeId) {{
            const node = nodes.get(nodeId);
            labelInput.value = node.label || nodeId;
            const nodeType = node.node_type || node.group || 'unknown';
            typeSelect.value = nodeType;
            currentNodeType = nodeType;
            statusEl.textContent = 'Noeud sélectionné : ' + (node.label || nodeId);
            setEditorEnabled(true);
        }}

        network.on('selectNode', (params) => {{
            selectedNodeId = params.nodes[0];
            loadNodeData(selectedNodeId);
        }});

        network.on('deselectNode', () => {{
            selectedNodeId = null;
            currentNodeType = null;
            statusEl.textContent = 'Sélectionnez un nœud dans le graphe.';
            labelInput.value = '';
            typeSelect.value = '';
            setEditorEnabled(false);
        }});

        function getNodeType(nodeId) {{
            const node = nodes.get(nodeId);
            return node ? (node.node_type || node.group || 'unknown') : 'unknown';
        }}

        updateBtn.addEventListener('click', () => {{
            if (!selectedNodeId) return;
            const newLabel = labelInput.value.trim() || selectedNodeId;
            const newType = typeSelect.value || currentNodeType || 'unknown';
            const style = NODE_TYPES[newType] || NODE_TYPES['unknown'];
            nodes.update({{
                id: selectedNodeId,
                label: newLabel,
                shape: style.shape,
                icon: style.icon,
                color: style.color,
                group: newType,
                node_type: newType,
                level: style.level
            }});
            currentNodeType = newType;
            typeSelect.value = newType;
            statusEl.textContent = 'Noeud mis à jour : ' + newLabel;
        }});

        deleteBtn.addEventListener('click', () => {{
            if (!selectedNodeId) return;
            nodes.remove({{ id: selectedNodeId }});
            selectedNodeId = null;
            currentNodeType = null;
            typeSelect.value = '';
            labelInput.value = '';
            setEditorEnabled(false);
            statusEl.textContent = 'Nœud supprimé. Sélectionnez un autre nœud.';
        }});

        function removeSummaryEdges() {{
            summaryEdgeIds.forEach((edgeId) => edges.remove(edgeId));
            summaryEdgeIds.clear();
        }}

        function createSummaryEdges() {{
            removeSummaryEdges();
            const scannerNode = nodes.get().find((node) => getNodeType(node.id) === 'scanner');
            if (!scannerNode) return;
            nodes.forEach((node) => {{
                const nodeType = getNodeType(node.id);
                if (['scanner', 'gateway', 'network'].includes(nodeType)) return;
                const summaryId = `summary_${{node.id}}`;
                if (edges.get(summaryId)) return;
                edges.add({{
                    id: summaryId,
                    from: scannerNode.id,
                    to: node.id,
                    dashes: true,
                    color: {{ color: '#94a3b8', highlight: '#60a5fa' }}
                }});
                summaryEdgeIds.add(summaryId);
            }});
        }}

        function updateLinkVisibility() {{
            edges.forEach((edge) => {{
                if (!baseEdgeIds.has(edge.id)) return;
                const fromType = getNodeType(edge.from);
                const toType = getNodeType(edge.to);
                const hideEdge = simplifiedView && (fromType === 'gateway' || toType === 'gateway');
                edges.update({{ id: edge.id, hidden: hideEdge }});
            }});
            if (simplifiedView) {{
                createSummaryEdges();
                toggleHopsBtn.textContent = 'Afficher les liens intermédiaires';
            }} else {{
                removeSummaryEdges();
                toggleHopsBtn.textContent = 'Masquer les liens intermédiaires';
            }}
        }}

        toggleHopsBtn.addEventListener('click', () => {{
            simplifiedView = !simplifiedView;
            updateLinkVisibility();
        }});

        updateLinkVisibility();
        setEditorEnabled(false);
    </script>
</body>
</html>"""
        with open(destination, 'w') as f:
            f.write(html_content)
    
    
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
        
        if self.skip_scans:
            if self.config.networks:
                print(f"{Colors.PURPLE}Mode test/topologie : découverte Nmap basique pour trouver les hôtes actifs (ports non scannés).{Colors.RESET}")
                active_hosts = self.discover_hosts()
                if not active_hosts and self.config.hosts:
                    print(f"{Colors.YELLOW}Aucun hôte découvert, repli sur la liste configurée.{Colors.RESET}")
                    active_hosts = set(self.config.hosts)
            elif self.config.hosts:
                print(f"{Colors.PURPLE}Mode test/topologie : aucun réseau fourni, utilisation directe de la liste d'hôtes.{Colors.RESET}")
                active_hosts = set(self.config.hosts)
            else:
                print(f"{Colors.RED}Mode topologie uniquement activé mais ni hôtes ni réseaux ne sont définis dans la configuration.{Colors.RESET}")
                return
        else:
            # Découverte des hôtes
            active_hosts = self.discover_hosts()
        
        if not active_hosts:
            print(f"{Colors.RED}Aucun hôte actif trouvé{Colors.RESET}")
            return
        
        print(f"\n{Colors.GREEN}═══════════════════════════════════════════════════{Colors.RESET}")
        print(f"{Colors.GREEN}HÔTES CIBLÉS : {len(active_hosts)}{Colors.RESET}")
        print(f"{Colors.GREEN}═══════════════════════════════════════════════════{Colors.RESET}")
        for host in sorted(active_hosts):
            print(f"  → {host}")
        print()
        
        scanned_hosts: List[str] = []
        
        if self.skip_scans:
            scanned_hosts = sorted(active_hosts)
        else:
            # Scanner chaque hôte
            for host in sorted(active_hosts):
                try:
                    self.scan_host(host)
                    scanned_hosts.append(host)
                except KeyboardInterrupt:
                    print(f"\n{Colors.YELLOW}Interruption utilisateur{Colors.RESET}")
                    break
                except Exception as e:
                    print(f"{Colors.RED}Erreur lors du scan de {host}: {e}{Colors.RESET}")
                    continue
        
        # Vue topologique interactive
        if self.config.enable_topology:
            self.generate_topology_view(scanned_hosts)
        
        print(f"\n{Colors.GREEN}╔═══════════════════════════════════════════════════╗{Colors.RESET}")
        if self.skip_scans:
            print(f"{Colors.GREEN}║ Mode topologie exécuté (aucun scan de ports)      ║{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}║           SCAN TERMINÉ AVEC SUCCÈS                ║{Colors.RESET}")
        print(f"{Colors.GREEN}╚═══════════════════════════════════════════════════╝{Colors.RESET}")
        print(f"\n{Colors.YELLOW}Les résultats sont disponibles dans : {self.output_dir}{Colors.RESET}\n")


def parse_args():
    parser = argparse.ArgumentParser(description="Scanner réseau automatisé + génération de topologie.")
    parser.add_argument('-c', '--config', default='config.xml', help='Chemin vers le fichier de configuration XML')
    parser.add_argument('--topology-only', action='store_true', help='Saute les scans réseau profonds et génère uniquement la topologie (utilise les hôtes listés ou lance une découverte rapide des réseaux)')
    return parser.parse_args()


def main():
    """Point d'entrée principal"""
    # Vérifier si le script est exécuté en tant que root
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}Attention: Certaines fonctionnalités nécessitent les privilèges root{Colors.RESET}")
        print(f"{Colors.YELLOW}Exécutez avec sudo pour de meilleurs résultats{Colors.RESET}\n")
    
    args = parse_args()
    
    try:
        config = Config(args.config)
        skip_mode = args.topology_only or config.topology_only
        if skip_mode:
            config.enable_topology = True
        scanner = NetworkScanner(config, skip_scans=skip_mode)
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Programme interrompu par l'utilisateur{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Erreur: {e}{Colors.RESET}")
        sys.exit(1)


if __name__ == '__main__':
    main()
