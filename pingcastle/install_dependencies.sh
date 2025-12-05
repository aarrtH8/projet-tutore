#!/bin/bash
# Installation des dépendances pour PingCastle Remote

echo "[*] Installation des dépendances..."

# Mise à jour
apt update

# Installation des packages
apt install -y \
    python3 \
    python3-pip \
    impacket-scripts \
    smbclient \
    cifs-utils \
    unzip

# Installation des modules Python
pip3 install pyyaml

echo "[+] Installation terminée!"
echo ""
echo "Utilisation:"
echo "  1. Éditer pingcastle_config.yaml avec de nouveau paramètres"
echo "  2. Exécuter: python3 pingcastle_remote.py pingcastle_config.yaml"
