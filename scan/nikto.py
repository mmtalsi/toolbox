import subprocess
import argparse
import requests
import sys
import re
import nmap
import socket
from urllib.parse import urlparse
from urllib.parse import urljoin, urlparse
import os


# Stocke les URLs trouvées
found_urls = set()

def scan_vulnerabilities():



    print("Analyse des vulnérabilités")


    url = input("\nEntrez l'URL à scanner : ")
    check_server(url)
    scan_all_ports(url)
    run_dirb(url)
    
    run_nikto(url)
    
    
def check_server(url):
    """ Vérifie les informations sur le serveur web """

    print("\nmAnalyse du serveur Web")
    try:
        response = requests.get(url)
        # print(response.headers)
        server = response.headers.get("Server", "Non disponible")
        x_powered_by = response.headers.get("X-Powered-By", "Non disponible")
        content_encoding = response.headers.get("Content-Encoding", "Non supporté")
        print(f" Serveur Web : {server}")
        print(f" Propulsé par : {x_powered_by}")
        print(f"  Support de la compression : {content_encoding}")

        #process = subprocess.Popen(["dirb", url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        check_redirection(url)
        #check_basic_auth(response)
        check_basic_auth(url)
        check_security_headers(url)
    except requests.exceptions.RequestException as e:
        print(f"[-] Erreur lors de la requête : {e}")
        sys.exit(1)
        
def check_redirection(url):
    """ Vérifie si l'URL cible redirige vers une autre URL """
# Exécuter dirb sans grep

    process = subprocess.Popen(["dirb", url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    for line in process.stdout:
        if "CODE:301" in line:
            print("\n [!] Redirection détectée \n")
            print(line.strip())  # Affiche uniquement les lignes contenant "CODE:401"

    process = subprocess.Popen(["dirb", url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    for line in process.stdout:
        if "CODE:302" in line:
            print("\n [!] Redirection détectée \n")
            print(line.strip())  # Affiche uniquement les lignes contenant "CODE:401"        
        #print("[✔] Succès : Page accessible")
    #elif response.status_code in [301, 302]:
        #print(f"[!] Redirection détectée vers : {response.headers.get('Location')}")

def check_basic_auth(url):
    """ Vérifie si l'URL cible est protégée par une authentification basique HTTP """
    process = subprocess.Popen(["dirb", url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)    

    for line in process.stdout:
        if "CODE:401" in line:
            print("\n [!] Portal d'authentification détecté \n")
            print(line.strip())  # Affiche uniquement les lignes contenant "CODE:401"
            
    #if response.status_code == 401:
        #print(f" URL protégée par une authentification basique HTTP")
    #else:
        #print(" Pas d'authentification basique détectée")


def check_security_headers(url):
    """ Vérifie la présence d'en-têtes de sécurité courants """

    headers = {
        "X-Frame-Options": "anti-clickjacking",
        "X-XSS-Protection": "XSS protection",
        "X-Content-Type-Options": "MIME-sniffing"
    }
    
    print("\nVérification des en-têtes de sécurité\n")
    
    try:
        response = requests.get(url, headers=headers)
        for header, description in headers.items():
            if header not in response.headers:
                print(f"\nAbsence de l'en-tête {description} :\n")
            else:
                print(f"\nPrésence de l'en-tête {description} : \n")
    except requests.exceptions.RequestException as e:
        print(f"\nErreur lors de la vérification des en-têtes de sécurité :\n")

def run_nikto(target):
    """Exécute Nikto sur la cible spécifiée"""
    try:
        print(f"\nLancement de Nikto sur {target}...\n")
        command = ["nikto", "-h", target]
        process = subprocess.run(command, text=True, capture_output=True)
        
        # Affichage du résultat
        print("Résultats de Nikto :\n")
        print(process.stdout)

        if process.stderr:
            print("Erreurs :\n", process.stderr)

    except FileNotFoundError:
        print("Erreur : Nikto n'est pas installé ou introuvable sur votre système.")


def scan_all_ports(url):
    """
    Scanne tous les ports (1-65535) sur une adresse IP donnée.
    
    :param ip: Adresse IP cible (ex: "192.168.202.149").
    :return: Un dictionnaire avec les ports ouverts et leur état.
    """
    ip=get_ip_from_url(url)
    nm = nmap.PortScanner()
    
    print(f"Scanning all ports on {ip}...")
    
    # Exécute le scan sur tous les ports
    nm.scan(ip, ports="1-65535")

    # Vérifie si l'hôte a répondu
    if ip not in nm.all_hosts():
        print("No response from target.")
        return None

    # Récupérer les ports ouverts
    open_ports = {}
    if 'tcp' in nm[ip]:
        for port in nm[ip]['tcp']:
            state = nm[ip]['tcp'][port]['state']
            service = nm[ip]['tcp'][port].get('name', 'Unknown')
            open_ports[port] = {"state": state, "service": service}
        
    print(f"les ports ouverts de {ip} est {open_ports}")
    return open_ports

def get_ip_from_url(url):
    """
    Extrait l'adresse IP d'une URL donnée.
    
    :param url: URL complète (ex: "http://127.0.0.1:8787" ou "http://example.com").
    :return: L'adresse IP de l'hôte.
    """
    try:
        # Extraire l'hôte (nom de domaine ou IP) depuis l'URL
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname  # Récupère "127.0.0.1" ou "example.com"

        # Résolution DNS (convertit un nom de domaine en IP)
        ip_address = socket.gethostbyname(hostname)

        return ip_address
    except Exception as e:
        return f"Erreur : {e}"

def run_dirb(target):
    # Wordlist 
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    """ Exécute DIRB et récupère les URLs trouvées """
    print(f"[+] Lancement de DIRB sur {target}...")
    
    try:
        # Exécuter la commande dirb
        result = subprocess.run(
            ["dirb", target, wordlist, "-r"],
            capture_output=True,
            text=True
        )
        output = result.stdout

        # Extraire les URLs de la sortie de DIRB
        for line in output.split("\n"):
            match = re.search(r'^\+ (http[^\s]+)', line)  # Cherche une URL après le "+ "
            if match:
                url = match.group(1)  # Récupère l'URL trouvée
                found_urls.add(url)


        
        print(f"[+] DIRB a trouvé {len(found_urls)} pages à tester.")
        scan_xss(url)
    except Exception as e:
        print(f"[-] Erreur lors de l'exécution de DIRB : {e}")



def scan_xss(url):
    """ Lance le scan XSS sur toutes les pages trouvées """
    for url in found_urls:
        lancer_scan_pwnxss(url)
        #print(scanner_xss(url))
        
        

def lancer_scan_pwnxss(url):
    """Exécute PwnXSS sur une URL et affiche les résultats en temps réel."""
    print(f"\n [TEST] Analyse de : {url}")
    
    # Définition de la commande PwnXSS
    commande = ["python3", "PwnXSS/pwnxss.py", "-u", url, "-o", "temp_pwnxss.json"]
    


    try:
        # Exécution de la commande
        result = subprocess.run(commande, capture_output=True, text=True)

        # Vérification si PwnXSS a généré des résultats
        if os.path.exists("temp_pwnxss.json"):
            with open("temp_pwnxss.json", "r") as f:
                scan_results = json.load(f)
        else:
            scan_results = {"status": "No XSS Found"}

        # Affichage des résultats immédiatement
        if "No XSS Found" in result.stdout or scan_results == {"status": "No XSS Found"}:
            print("❌ Aucune vulnérabilité XSS détectée.")
        else:
            print("✅ Vulnérabilité XSS détectée !")
            print(json.dumps(scan_results, indent=4))

        # Retourner les résultats
        return {url: scan_results}

    except FileNotFoundError:
        print("[!] Erreur : PwnXSS n'est pas installé.")
    except Exception as e:
        print(f"[!] Erreur lors du scan : {e}")

    return {url: "Scan Failed"}


if __name__ == "__main__":

    scan_vulnerabilities()
    #run_nikto(args.target)
