# PingCastle Remote Execution Tool

Outil automatisé pour exécuter PingCastle sur un Domain Controller distant depuis Kali Linux.

## Installation

```bash
# Rendre le script d'installation exécutable
chmod +x install_dependencies.sh

# Exécuter ce fichier pour l'installationdes dépendances
sudo ./install_dependencies.sh
```

## Configuration

Éditer le fichier `pingcastle_config.yaml` avec les paramètres :

```yaml
target:
  dc_ip: "10.0.10.50"              # IP de ton DC
  dc_name: "DC01"                     # Nom NetBIOS du DC
  domain: "panoptis.lan"                 # Nom du domaine

credentials:
  username: "Administrateur"
  password: "P@ssw0rd123"

pingcastle:
  local_path: "/home/panoptis/pingcastle/PingCastle.zip"
  remote_path: "C:\\Temp\\PingCastle"
  options:
    - "--healthcheck"
```

## Utilisation

```bash
# Rendre le script principal exécutable
chmod +x pingcastle_remote.py

# Exécuter l'analyse de pingcastle
sudo python3 pingcastle_remote.py pingcastle_config.yaml
```

## Fonctionnement

Le script effectue automatiquement :

1. Vérification des dépendances
2. Extraction de PingCastle depuis le ZIP
3. Montage du partage SMB du DC
4. opie de PingCastle sur le DC
5. Exécution de PingCastle à distance
6. Récupération des résultats (HTML/XML)
7. Nettoyage optionnel

## Résultats

Les rapports sont sauvegardés dans : `/home/panoptis/pingcastle/results/pingcastle_YYYYMMDD_HHMMSS/`

## Options PingCastle

Modifier la section `options` dans le YAML :

```yaml
options:
  - "--healthcheck"                 # Audit complet
  - "--scanner aclcheck"            # Scanner les ACLs
  - "--scanner antivirus"           # Check antivirus
  - "--no-enum-limit"               # Pas de limite d'énumération
  - "--level Full"                  # Niveau de détail
```

## Méthodes d'exécution

Dans le fichier YAML, tu peux choisir :

- `wmiexec` : Via WMI (recommandé)
- `psexec` : Via PSExec (Fonctionne)
- `smbexec` : Via SMB (En cours de dev)
- `evil-winrm` : Via Winrm (En cours de dev)

## Troubleshooting

### Erreur de montage SMB
```bash
# Vérifier la connectivité
ping <DC_IP>
smbclient -L //<DC_IP> -U <domain>/<user>
```

### Timeout
Augmenter le timeout dans le YAML :
```yaml
execution:
  timeout: 1200  # 20 minutes
```

### Permissions insuffisantes
Assurer que l'utilisateur a :
- Droits administrateur sur le DC
- Accès au partage C$

## Sécurité

⚠️ **Attention** : Le fichier YAML contient des identifiants en clair

Options sécurisées :
1. Utiliser un hash NTLM au lieu du mot de passe
2. Supprimer le fichier après utilisation
3. Utiliser des variables d'environnement

## Support

Pour plus d'infos sur PingCastle : https://www.pingcastle.com/documentation/
