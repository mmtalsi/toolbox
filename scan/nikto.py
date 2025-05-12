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
import ipaddress

# Stocke les URLs trouvées
found_urls = set()
seclists_wordlist = "/usr/share/seclists/Discovery/Web-Content/Logins.fuzz.txt"

def scan_redirections_with_dirb(target, output_file=None):
    """Scan uniquement pour trouver les redirections (301/302) via dirb."""
    wordlist = "/usr/share/wordlists/dirb/small.txt"
    results = []

    print(f"\n[+] Lancement du scan de redirections avec DIRB sur {target}...\n")

    try:
        cmd = ["dirb", target, wordlist, "-r", "-v"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        for line in process.stdout:
            if "(CODE:30" in line:
                line_clean = f"[REDIRECTION] {line.strip()}"
                print(line_clean)
                results.append(line_clean)

        process.wait()
        results.append("\n[+] Scan de redirection terminé.\n")

    except FileNotFoundError:
        error = "[!] Erreur : DIRB n'est pas installé ou introuvable."
        print(error)
        results.append(error)
    except Exception as e:
        error = f"[!] Erreur pendant le scan de redirection : {e}"
        print(error)
        results.append(error)

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(results))
        
def scan_vulnerabilities():
    print("Analyse des vulnérabilités")
    url = input("\nEntrez l'URL à scanner : ")
    check_server(url)
    #scan_all_ports(url)
    run_dirb(url)
    scan_redirections_with_dirb(url)
    run_nikto(url)
    #detect_login_pages()
    reconnaissance_domain(target_domain)

def check_server(url, output_file=None):
    print("\nAnalyse du serveur Web")
    try:
        response = requests.get(url)
        server = response.headers.get("Server", "Non disponible")
        x_powered_by = response.headers.get("X-Powered-By", "Non disponible")
        content_encoding = response.headers.get("Content-Encoding", "Non supporté")
        
        results = (
            f"Serveur Web : {server}\n"
            f"Propulsé par : {x_powered_by}\n"
            f"Support de la compression : {content_encoding}\n"
        )
        
        print(results)
        
        # Si output_file est spécifié, écrire les résultats dedans
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(results)
        
        check_security_headers(url, output_file)
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

def check_security_headers(url, output_file=None):
    headers = {
        "X-Frame-Options": "anti-clickjacking",
        "X-XSS-Protection": "XSS protection",
        "X-Content-Type-Options": "MIME-sniffing"
    }
    print("\nVérification des en-têtes de sécurité\n")
    
    security_results = ""
    try:
        response = requests.get(url)
        for header, description in headers.items():
            if header not in response.headers:
                result = f"Absence de l'en-tête {description}\n"
            else:
                result = f"Présence de l'en-tête {description}\n"
            print(result)
            security_results += result
        
        # Si output_file est spécifié, ajouter les résultats
        if output_file:
            with open(output_file, "a", encoding="utf-8") as f:
                f.write("\nVérification des en-têtes de sécurité:\n")
                f.write(security_results)
                
    except requests.exceptions.RequestException as e:
        print(f"\nErreur lors de la vérification des en-têtes de sécurité :\n")
def get_ip_from_url(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        return f"Erreur : {e}"
        
def run_nikto(target, output_file=None):
    try:
        print(f"\nLancement de Nikto sur {target}...\n")
        command = ["nikto", "-h", target]
        process = subprocess.run(command, text=True, capture_output=True)
        result = "Résultats de Nikto :\n" + process.stdout
        if process.stderr:
            result += "\nErreurs :\n" + process.stderr

        print(result)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result)
    except FileNotFoundError:
        print("Erreur : Nikto n'est pas installé ou introuvable.")

def scan_all_ports(url, output_file=None):
    ip = get_ip_from_url(url)
    nm = nmap.PortScanner()

    print(f"Scanning all ports quickly on {ip}...")

    nm.scan(hosts=ip, arguments="-p- -T4 --min-rate 500")
    
    if ip not in nm.all_hosts():
        print("No response from target.")
        return None

    open_ports = []
    if 'tcp' in nm[ip]:
        for port in nm[ip]['tcp']:
            if nm[ip]['tcp'][port]['state'] == 'open':
                open_ports.append(str(port))

    result = f"Ports ouverts trouvés sur {ip} : {open_ports}\n"

    if open_ports:
        ports_str = ",".join(open_ports)
        result += f"Scanning services on open ports: {ports_str}\n"
        nm.scan(hosts=ip, ports=ports_str, arguments="-sV -T4")

        for port in nm[ip]['tcp']:
            service = nm[ip]['tcp'][port].get('name', 'Unknown')
            state = nm[ip]['tcp'][port]['state']
            result += f"Port {port} : {service} ({state})\n"
    else:
        result += "Aucun port ouvert détecté.\n"

    print(result)
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(result)

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
        
        

def run_dirb(target, output_file=None):
    """Scan rapide sans afficher les 404"""
    extensions = ['php', 'html']
    found_urls = set()
    results = []

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
                            line = f"[LOGIN PAGE] {url} -> Status {response.status_code}"
                        else:
                            line = f"[FOUND] {url} -> Status {response.status_code}"
                        print(line)
                        results.append(line)
                except requests.RequestException:
                    line = f"[SKIP] {url} -> No response"
                    print(line)
                    results.append(line)

        print(f"\n[+] Scan terminé. {len(found_urls)} pages détectées.\n")
        results.append(f"\nTotal détecté : {len(found_urls)}")
    except Exception as e:
        results.append(f"[!] Erreur pendant le scan : {e}")
        print(results[-1])

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(results))

    return found_urls

def run_command(command, log_file):
    print(f"\n[+] Running: {command}")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = strip_ansi(result.stdout)
        error = strip_ansi(result.stderr)

        if output:
            print(output)
            log_file.write(output + '\n')

        if error:
            print(f"[!] Error:\n{error}")
            log_file.write(f"\n[!] Error:\n{error}\n")

    except Exception as e:
        error_msg = f"[!] Exception while running command: {e}"
        print(error_msg)
        log_file.write(f"{error_msg}\n")

def strip_ansi(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def clean_domain(domain):
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.strip('/')
    domain = domain[4:] if domain.startswith('www.') else domain
    return domain.lower()

def resolve_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] Résolution DNS : {domain} → {ip}")
        return ip
    except Exception as e:
        print(f"[!] Erreur de résolution DNS pour {domain} : {e}")
        return None

def is_rfc1918(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def reconnaissance_domain(domain):
    subs_file = "subs.txt"
    domain = clean_domain(domain)
    ip = resolve_ip(domain)

    if ip is None:
        print("[!] Impossible de résoudre l'IP. Arrêt du script.")
        sys.exit(1)

    if is_rfc1918(ip):
        print(f"[!] L'adresse IP résolue ({ip}) est privée (RFC1918). Script interrompu.")
        sys.exit(1)

    output_file = f"result_{domain}.txt"

    with open(output_file, "w") as log:
        log.write(f"===== Domain Analysis Report for {domain} ({ip}) =====\n\n")

        log.write("=== [1] Subfinder ===\n")
        run_command(f"subfinder -d {domain} -o {subs_file}", log)

        log.write(f"\n\n=== [2] Analysis for {domain} ===\n")

        log.write("\n--- WebTech ---\n")
        run_command(f"webtech -u http://{domain}", log)

        log.write("\n--- WHOIS ---\n")
        run_command(f"whois {domain}", log)

        log.write("\n--- GeoIPLookup ---\n")
        run_command(f"geoiplookup {domain}", log)

    if os.path.exists(subs_file):
        os.remove(subs_file)
        print(f"\n[+] Deleted {subs_file}")

    print(f"\n✅ Analyse terminée. Résultats enregistrés dans : {output_file}")

if __name__ == "__main__":
    scan_vulnerabilities()
