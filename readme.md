# Projet Tutore — Audit automatisé d'entreprises

## THINK DUMB

1. Rajouté la partie pour faire le venv.
2. Ameilloré le script nmap pour qu'il detecte les machine windows avec pare-feu ON
3. Ajouté les nouvelles librairies python nécessaires à Installer

## Description

Ce projet a pour objectif de réaliser un audit automatisé d'entreprises afin de se rapprocher des pratiques actuelles du marché en matière de cybersécurité.  
Le but est d’automatiser les scans et de générer des rapports d’audit exploitables sans intervention manuelle.

---

## Fonctionnalités du POC (Proof of Concept)

1. **Scan réseau automatisé**  
   - Analyse des IP d’un réseau donné en excluant certaines plages ou adresses IP spécifiques.  
   - Scan des ports ouverts avec Nmap, et rescan détaillé (versions, OS) sur les ports détectés.  
   - Scans complémentaires avec des outils comme enum4linux (Samba), WhatWeb (HTTP) et Nikto (vulnérabilités web).  
   - Recherche d'exploits connus à partir des résultats Nmap via `searchsploit`.

2. **Gestion des exclusions**  
   - Supporte l’exclusion d’IPs individuelles ou de plages d’IPs (format `192.168.0.1-150` ou listes séparées par virgules).  
   - Ces exclusions sont configurables via un fichier YAML.

3. **Audit Lynis sur machines Linux distantes via SSH**  
   - Transfert automatisé du dossier `lynis` sur la machine distante.  
   - Exécution d’un audit Lynis avec des droits sudo, en mode forensics (configurable).  
   - Récupération des logs et rapports Lynis produits, puis nettoyage du dossier temporaire distant.  
   - Gestion des connexions SSH avec authentification via fichier de credentials.

---

## Structure du projet

- `Scanner.py` : Script principal de scan réseau et audit local (Nmap, enum4linux, WhatWeb, Nikto, searchsploit).  
- `audit_ssh_lynis.py` : Script pour audit Lynis automatisé sur machines Linux distantes via SSH.  
- `config.yaml` : Fichier de configuration pour définir le réseau à scanner, les exclusions, les options des outils, etc.  
- `ssh_credentials.txt` : Fichier (non versionné) contenant les accès SSH pour les machines distantes à auditer (format : `host;username;password`).

---

## Prérequis

- Python 3.x  
- Modules Python : `paramiko`, `PyYAML`  , `Networkx`
- Outils en ligne de commande installés :  
  - `nmap`  
  - `enum4linux`  
  - `whatweb`  
  - `nikto`  
  - `searchsploit`  
- Dossier `lynis` contenant l’outil Lynis dans le même répertoire que `audit_ssh_lynis.py`.  

---

## Installation

1. Cloner le dépôt :

```bash
git clone https://gricad-gitlab.univ-grenoble-alpes.fr/mclement/projet-tutore.git
cd projet-tutore
````

2. Installer les dépendances Python :

```bash
pip install paramiko pyyaml networkx
```

3. Installer les outils système requis (exemple Debian/Ubuntu) :

```bash
sudo apt-get install nmap enum4linux whatweb nikto exploitdb
```

4. Préparer les fichiers de configuration :

* Modifier `config.yaml` selon ton réseau et besoins.
* Créer `ssh_credentials.txt` avec la liste des machines distantes à auditer (format : `host;username;password` par ligne).

---

## Utilisation

### Scan réseau local

Lancer le script principal :

```bash
python3 Scanner.py
```

Les rapports seront générés dans le dossier `reports/`.

### Audit Lynis sur machines distantes

Lancer le script Lynis :

```bash
python3 audit_ssh_lynis.py
```

---

## Fonctionnement détaillé

* **Exclusions IP**
  Le fichier `config.yaml` permet de définir des plages ou listes d’IPs à exclure du scan.

* **Scan Nmap**
  Le script effectue un scan complet des ports ouverts (`-p- --open`), puis un rescan plus précis avec détection de versions, scripts, et OS.

* **Recherche d’exploits**
  Les résultats Nmap XML sont analysés par `searchsploit` pour détecter des vulnérabilités connues.

* **Audit Lynis**
  Le script `audit_ssh_lynis.py` utilise Paramiko pour transférer et exécuter Lynis en SSH, récupérer les logs et nettoyer la machine distante.

---

## Améliorations possibles

* Génération d’un rapport global consolidé.
* Analyse automatique des risques à partir des logs.
* Interface web ou console interactive.
* Gestion sécurisée des credentials (clés SSH, vault).
* Support d’autres OS pour l’audit distant.

---

## Licence

La licence reste à définir pour l'équipe PANOPTIS

---

## Contact

Pour toute question ou contribution, contacter l’équipe projet.

Matthias Devouassoud

Nils Jaillette

Clement Martin

Dylan Drevot

Arthur Grossi
