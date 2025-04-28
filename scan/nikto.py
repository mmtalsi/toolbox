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
import json
from bs4 import BeautifulSoup

# Stocke les URLs trouvées
found_urls = set()
seclists_wordlist = "/usr/share/seclists/Discovery/Web-Content/Logins.fuzz.txt"

def scan_redirections_with_dirb(target):
    """Scan uniquement pour trouver les redirections (301/302) via dirb."""
    wordlist = "/usr/share/wordlists/dirb/small.txt"

    print(f"\n[+] Lancement du scan de redirections avec DIRB sur {target}...\n")

    try:
        cmd = ["dirb", target, wordlist, "-r", "-v"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        for line in process.stdout:
            if "(CODE:30" in line:
                print(f"[REDIRECTION] {line.strip()}")

        process.wait()
        print("\n[+] Scan de redirection terminé.\n")

    except FileNotFoundError:
        print("[!] Erreur : DIRB n'est pas installé ou introuvable.")
    except Exception as e:
        print(f"[!] Erreur pendant le scan de redirection : {e}")
def scan_vulnerabilities():
    print("Analyse des vulnérabilités")
    url = input("\nEntrez l'URL à scanner : ")
    check_server(url)
    #scan_all_ports(url)
    run_dirb(url)
    scan_redirections_with_dirb(url)
    run_nikto(url)
    #detect_login_pages()

def check_server(url):
    print("\nmAnalyse du serveur Web")
    try:
        response = requests.get(url)
        server = response.headers.get("Server", "Non disponible")
        x_powered_by = response.headers.get("X-Powered-By", "Non disponible")
        content_encoding = response.headers.get("Content-Encoding", "Non supporté")
        print(f" Serveur Web : {server}")
        print(f" Propulsé par : {x_powered_by}")
        print(f"  Support de la compression : {content_encoding}")

        #check_redirection(url)
        #check_basic_auth(url)
        check_security_headers(url)
    except requests.exceptions.RequestException as e:
        print(f"[-] Erreur lors de la requête : {e}")
        sys.exit(1)

def check_redirection(url):
    process = subprocess.Popen(["dirb", url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for line in process.stdout:
        if "CODE:301" in line:
            print("\n [!] Redirection détectée \n")
            print(line.strip())
    process = subprocess.Popen(["dirb", url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for line in process.stdout:
        if "CODE:302" in line:
            print("\n [!] Redirection détectée \n")
            print(line.strip())

def check_basic_auth(url):
    process = subprocess.Popen(["dirb", url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for line in process.stdout:
        if "CODE:401" in line:
            print("\n [!] Portal d'authentification détecté \n")
            print(line.strip())

def check_security_headers(url):
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
    try:
        print(f"\nLancement de Nikto sur {target}...\n")
        command = ["nikto", "-h", target]
        process = subprocess.run(command, text=True, capture_output=True)
        print("Résultats de Nikto :\n")
        print(process.stdout)
        if process.stderr:
            print("Erreurs :\n", process.stderr)
    except FileNotFoundError:
        print("Erreur : Nikto n'est pas installé ou introuvable sur votre système.")

def scan_all_ports(url):
    """
    Scanne rapidement les ports ouverts puis détecte les services.
    """
    ip = get_ip_from_url(url)
    nm = nmap.PortScanner()

    print(f"Scanning all ports quickly on {ip}...")

    # 1ere passe : scan rapide
    nm.scan(hosts=ip, arguments="-p- -T4 --min-rate 500")
    
    if ip not in nm.all_hosts():
        print("No response from target.")
        return None

    open_ports = []
    if 'tcp' in nm[ip]:
        for port in nm[ip]['tcp']:
            if nm[ip]['tcp'][port]['state'] == 'open':
                open_ports.append(str(port))

    print(f"Ports ouverts trouvés : {open_ports}")

    if open_ports:
        # 2e passe : détection des services sur ports ouverts
        ports_str = ",".join(open_ports)
        print(f"Scanning services on open ports: {ports_str}")
        nm.scan(hosts=ip, ports=ports_str, arguments="-sV -T4")

        services = {}
        for port in nm[ip]['tcp']:
            service = nm[ip]['tcp'][port].get('name', 'Unknown')
            state = nm[ip]['tcp'][port]['state']
            services[port] = {"state": state, "service": service}
        
        print(f"Services détectés: {services}")
        return services
    else:
        print("Aucun port ouvert détecté.")
        return {}

def get_ip_from_url(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        return f"Erreur : {e}"

def is_login_page(url):
    """ Détecte si une page est une page de login """
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 404:
            return False  # Ignore les 404
        soup = BeautifulSoup(response.text, 'html.parser')

        if soup.find('input', {'type': 'password'}):
            return True

        keywords = ["login", "connexion", "sign in", "authentification", "mot de passe"]
        page_text = soup.get_text().lower()
        if any(keyword in page_text for keyword in keywords):
            return True

        return False
    except Exception as e:
        print(f"[!] Erreur lors de la vérification de {url}: {e}")
        return False
        
        

def run_dirb(target):
    """Scan rapide sans afficher les 404"""
    extensions = ['php', 'html']
    found_urls = set()

    if not os.path.exists(seclists_wordlist):
        print(f"[!] Wordlist SecLists non trouvée: {seclists_wordlist}")
        return found_urls

    print(f"[+] Scan de {target} avec petite wordlist SecLists : {seclists_wordlist}\n")

    try:
        with open(seclists_wordlist, 'r') as f:
            words = f.read().splitlines()

        for word in words:
            for ext in extensions:
                url = f"{target.rstrip('/')}/{word}.{ext}"
                try:
                    response = requests.get(url, timeout=3)
                    if response.status_code != 404:
                        found_urls.add(url)
                        if is_login_page(url):
                            print(f"[LOGIN PAGE] {url} -> Status {response.status_code}")
                        else:
                            print(f"[FOUND] {url} -> Status {response.status_code}")
                    # else:  # On ne fait plus rien si c'est 404
                        # print(f"[SKIP] {url} -> 404")  # Ne plus afficher
                except requests.RequestException:
                    print(f"[SKIP] {url} -> No response")

        print(f"\n[+] Scan terminé. {len(found_urls)} pages détectées.\n")
    except Exception as e:
        print(f"[!] Erreur pendant le scan : {e}")

    return found_urls


if __name__ == "__main__":
    scan_vulnerabilities()
