#!/bin/bash

echo "==============================="
echo "📦 INSTALLATION D'OUTILS KALI"
echo "==============================="

# 1. Mise à jour du système
echo "[*] Mise à jour des paquets..."
sudo apt update --allow-releaseinfo-change
sudo apt full-upgrade -y
sudo apt install -f -y
sudo apt autoremove -y

# 2. Installation des outils APT
echo "[*] Installation des paquets système (via APT)..."
sudo apt install -y \
    paramspider \
    sqlmc \
    hydra \
    docker.io \
    geoip-bin \
    seclists \
    nuclei \
    subfinder \
    chromium \
    chromium-driver \
    git \
    curl \
    python3-pip

# 3. Suppression du verrou pip (Python 3.13)
echo "[*] Déverrouillage pip (Python 3.13)..."
sudo mv /usr/lib/python3.13/EXTERNALLY-MANAGED /usr/lib/python3.13/EXTERNALLY-MANAGED.old 2>/dev/null

# 4. Installation des modules Python requis
echo "[*] Installation des modules Python (via pip3)..."
sudo pip3 install --ignore-installed \
    python-nmap \
    selenium \
    webtech \
    requests \
    zxcvbn \
    urllib3 \
    trio \
    trio-websocket \
    typing_extensions \
    certifi \
    outcome \
    PyJWT \
    beautifulsoup4

# 5. Activation de Docker
echo "[*] Activation de Docker..."
sudo systemctl enable docker --now
sudo usermod -aG docker "$USER"

# 6. Vérification post-installation
echo ""
echo "==============================="
echo "🧪 VÉRIFICATION DES OUTILS"
echo "==============================="

declare -a tools=("paramspider" "sqlmc" "hydra" "docker" "nuclei" "subfinder" "chromium" "python3" "pip3")

for tool in "${tools[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo "✅ $tool disponible"
    else
        echo "❌ $tool non trouvé"
    fi
done

echo ""
echo "[✓] Installation terminée."
