
import subprocess
import os
import glob
import sys

from password.password_security import PasswordSecurity
#rom password.password_security import analyze_password_security
from scan.nikto import scan_vulnerabilities
from scan.nikto import check_server
from scan.nikto import scan_all_ports
from scan.nikto import run_nikto
from scan.nikto import run_dirb
from scan.nikto import scan_redirections_with_dirb
from scan.nikto import reconnaissance_domain
from demonstration.CVE_2024_38473 import lancer_conteneur_docker_CVE_2024_38473
from demonstration.CVE_2024_38473 import lancer_conteneur_docker_CVE_2021_41773
from demonstration.CVE_2024_38473 import check_cve_2021_41773
from demonstration.CVE_2024_38473 import check_cve_2024_38473
from demonstration.CVE_2024_38473 import get_cves
from demonstration.CVE_2024_38473 import display_cve_results
from demonstration.Destruction import tuer_tous_les_conteneurs
from scan.XSS import lancer_paramspider
from scan.XSS import scan_XSS
from scan.XSS import test_xss_redirection
from scan.sqlmc import run_main
from scan.sqlmap import sqlmap
from urllib.parse import urlparse
from rapport_complet import rapport

import re
from urllib.parse import urlparse

def url_valide(url: str) -> bool:
    """
    Vérifie que l'URL :
      - commence par http:// ou https://
      - contient un domaine de type "mon-site.com" ou "sous.domaine.fr"
      - se termine par un slash "/" OBLIGATOIRE
      - n'a pas de chemin autre qu'un slash final
    Renvoie True si l'URL est au format "http(s)://domaine.tld/", False sinon.
    """

    # 1) Vérification de la structure générale via urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        # Schéma invalide (ni http ni https)
        return False

    if not parsed.netloc:
        # Il n’y a pas de domaine
        return False

    # Le chemin doit être exactement "/"
    if parsed.path != "/":
        return False

    # Pas de params, query ou fragment autorisés
    if parsed.params or parsed.query or parsed.fragment:
        return False

    # 2) Vérification stricte avec une regex :
    #    - http:// ou https:// en début
    #    - un nom de domaine avec au moins un point (ex.: example.com)
    #    - OBLIGATOIREMENT un slash final
    regex = re.compile(
        r"^https?://"               # "http://" ou "https://"
        r"[A-Za-z0-9\-]+\."         # segment de domaine + point (ex. "mon-site.")
        r"[A-Za-z0-9\-\.]*[A-Za-z0-9\-]"  # reste du domaine (ex. "domaine" ou "sous.domaine")
        r"/$"                        # slash final obligatoire et fin de chaîne
    )
    return bool(regex.match(url))
    
def generer_rapport(url):
    """Génère un rapport consolidé des différents scans effectués"""
    import os
    import datetime
    from glob import glob
    
    # Créer le dossier reports s'il n'existe pas
    if not os.path.exists('reports'):
        os.makedirs('reports')
    
    # Nom du fichier de rapport avec timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    rapport_filename = f"reports/security_report_{timestamp}.txt"
    
    # Fonction pour lire le contenu d'un fichier
    def lire_fichier(chemin):
        if os.path.exists(chemin):
            with open(chemin, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        return "Aucun résultat trouvé pour ce scan.\n"
    
    # Collecter les résultats des différents scans
    contenu_rapport = []
    contenu_rapport.append("="*60)
    contenu_rapport.append(f"       RAPPORT DE SÉCURITÉ - {timestamp}")
    contenu_rapport.append("="*60)
    contenu_rapport.append("\n")
    
    # 1. Résultats Nikto
    contenu_rapport.append("==================== SCAN NIKTO ====================")
    domain = get_domain(url)
    fichiers_nikto = glob(f'results/nikto_{domain}.txt')
    if fichiers_nikto:
        for fichier in fichiers_nikto:
            contenu_rapport.append(f"Fichier: {fichier}")
            contenu_rapport.append(lire_fichier(fichier))
    else:
        contenu_rapport.append("L'outil Nikto non executé")
    contenu_rapport.append("\n")
    # On suppose que Nikto affiche ses résultats directement dans la console
    contenu_rapport.append("Les résultats de Nikto sont affichés dans la console lors du scan.")
    contenu_rapport.append("\n")
    
    # 2. Résultats DIRB

    contenu_rapport.append("==================== DETECTE LOGIN PAGE ====================")
    fichiers_dirb = glob(f'results/dirb_{domain}.txt')
    if fichiers_dirb:
        for fichier in fichiers_dirb:
            contenu_rapport.append(f"Fichier: {fichier}")
            contenu_rapport.append(lire_fichier(fichier))
    else:
        contenu_rapport.append("L'outil DIRB non executé.")
    contenu_rapport.append("\n")
    
    # Redirections détectées
    contenu_rapport.append("==================== REDIRECTIONS DETECTÉES ====================")
    fichiers_redir = glob(f'results/redirections_{domain}.txt')
    if fichiers_redir:
        for fichier in fichiers_redir:
            contenu_rapport.append(f"Fichier: {fichier}")
            contenu_rapport.append(lire_fichier(fichier))
    else:
        contenu_rapport.append("Aucune redirection détectée.")
    contenu_rapport.append("\n")
    # . Résultats Reconnaissance Domaine
    contenu_rapport.append("==================== SCAN Reconnaissance Domaine ====================")
    fichiers_domaine = glob(f'results/result_recon_{domain}.txt')
    if fichiers_domaine:
        for fichier in fichiers_domaine:
            contenu_rapport.append(f"Fichier: {fichier}")
            contenu_rapport.append(lire_fichier(fichier))
    else:
        contenu_rapport.append("L'outil de scan SQL non executé.")
    contenu_rapport.append("\n")
    # DIRB affiche aussi ses résultats dans la console
    contenu_rapport.append("Les résultats de DIRB sont affichés dans la console lors du scan.")
    contenu_rapport.append("\n")
    
    # 3. Résultats XSS
    contenu_rapport.append("==================== SCAN XSS ====================")
    fichiers_xss = glob('results/*_result.txt')
    if fichiers_xss:
        for fichier in fichiers_xss:
            contenu_rapport.append(f"Fichier: {fichier}")
            contenu_rapport.append(lire_fichier(fichier))
    else:
        contenu_rapport.append("L'outil de scan XSS non executé.")
    contenu_rapport.append("\n")
    
    # 4. Résultats SQL Injection
    contenu_rapport.append("==================== SCAN INJECTION SQL ====================") 
    fichiers_sql = glob('results/rapport_SQL.txt')
    if fichiers_sql:
        for fichier in fichiers_sql:
            contenu_rapport.append(f"Fichier: {fichier}")
            contenu = lire_fichier(fichier)
            contenu_rapport.append(contenu)
            if "Aucune URL vulnérable détectée" in contenu:
               contenu_rapport.append("Aucune vulnérabilité SQL détectée.\n")
    else:
       contenu_rapport.append("L'outil de scan SQL non executé.")
    contenu_rapport.append("\n")
    #contenu_rapport.append("==================== SCAN INJECTION SQL ====================")
    #fichiers_sql = glob('results/rapport_SQL.txt')
    #if fichiers_sql:
        #for fichier in fichiers_sql:
            #contenu_rapport.append(f"Fichier: {fichier}")
            #contenu_rapport.append(lire_fichier(fichier))
    #else:
        #contenu_rapport.append("L'outil de scan SQL non executé.")
    #contenu_rapport.append("\n")
    
    # 5. Informations sur les conteneurs Docker
    contenu_rapport.append("==================== CONTENEURS DOCKER ====================")
    try:
        result = subprocess.run(['docker', 'ps'], capture_output=True, text=True)
        contenu_rapport.append(result.stdout if result.stdout else "Aucun conteneur en cours d'exécution.")
    except:
        contenu_rapport.append("Impossible de récupérer l'état des conteneurs Docker.")
    contenu_rapport.append("\n")
    
    # 6. En-têtes de sécurité + infos serveur
    contenu_rapport.append("==================== INFORMATIONS SERVEUR ET EN-TÊTES DE SÉCURITÉ ====================")
    domain = get_domain(url)
    output_file = f"results/check_server_{domain}.txt"
    fichiers_check = glob(output_file)
    if fichiers_check:
        for fichier in fichiers_check:
            contenu_rapport.append(f"Fichier: {fichier}")
            contenu_rapport.append(lire_fichier(fichier))
    else:
        contenu_rapport.append("Le scan des informations serveur et des en-têtes de sécurité n’a pas été effectué.")
    contenu_rapport.append("\n")
    
# 7. Résultats des ports et services
    contenu_rapport.append("==================== PORTS OUVERTS ET SERVICES ====================")
    domain = get_domain(url)
    fichiers_ports = glob(f'results/ports_{domain}.txt')
    if fichiers_ports:
        for fichier in fichiers_ports:
            contenu_rapport.append(f"Fichier: {fichier}")
            contenu_rapport.append(lire_fichier(fichier))
    else:
        contenu_rapport.append("Le scan de ports n'a pas été effectué.")
    contenu_rapport.append("\n")
    # Ces informations sont aussi affichées lors du scan initial
    contenu_rapport.append("Vérifiez les ports ouverts et services dans les résultats du scan initial.")
    contenu_rapport.append("\n")
    
    # Écrire le rapport dans le fichier
    with open(rapport_filename, 'w', encoding='utf-8') as f:
        f.write("\n".join(contenu_rapport))
    
    print(f"\n[+] Rapport généré avec succès: {rapport_filename}")
    input("Appuyez sur entrer pour retourner au menu")

def get_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    # Supprimer "www." si présent
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def menu(url):
    # Affiche le menu
    
    print("\n     Menu toolbox :\n")
    
    print("             [1] - Scan de vulnérabilité")
    print("             [2] - Page d'authentification et de redirection")
    print("             [3] - Scan et Injection XSS")
    print("             [4] - Scan et Injection SQL")
    print("             [5] - Détection de CVE_2024_38473")
    print("             [6] - Détection de CVE_2021_41773")
    print("             [7] - Deployer les machines de démo")
    print("             [8] - Infos CVE")
    print("             [9] - Destruction")
    print("             [10] - Force du Password\n")
    print("         [Q] - Quitter\n")

    choix = input("Veuillez choisir une option: ")

    # Vérifie le choix de l'utilisateur

    if choix == "1":
        #scan_vulnerabilities()
        #url = input("\nEntrez l'URL à scanner : ")
        domain = get_domain(url)
        check_file = f"results/check_server_{domain}.txt"
        ports_file = f"results/ports_{domain}.txt"
        nikto_file = f"results/nikto_{domain}.txt"

        check_server(url, check_file)
        scan_all_ports(url, ports_file)
        run_nikto(url, nikto_file)
        reconnaissance_domain(url)
        input("Appuyez sur entrer pour retourner au menu")
        menu(url)
    elif choix == "2":
        #url = input("\nEntrez l'URL à scanner : ")
        domain = get_domain(url)
        dirb_file = f"results/dirb_{domain}.txt"
        redir_file = f"results/redirections_{domain}.txt"

        run_dirb(url, dirb_file)
        scan_redirections_with_dirb(url, redir_file)
        input("Appuyez sur entrer pour retourner au menu")
        menu(url)
    elif choix == "3":
        #url = input("Entrez l'URL (domaine) cible (ex: example.com) : ").strip()
        domain=get_domain(url)
        print(f"Le domaine est : {domain}")
        lancer_paramspider(domain)
        scan_XSS(domain)
        test_xss_redirection(url) 
        input("Appuyez sur entrer pour retourner au menu")
        menu(url)
    elif choix == "4":
        url_vulnerable = run_main(url)
        if url_vulnerable:
            sqlmap(url_vulnerable)
        else:
            print("❌ Aucune URL vulnérable sélectionnée.")

        input("Appuyez sur entrer pour retourner au menu")
        menu(url)
    elif choix == "5":
        check_cve_2024_38473(url)
        input("Appuyez sur entrer pour retourner au menu")
        menu(url)
    elif choix == "6":
        check_cve_2021_41773(url)
        input("Appuyez sur entrer pour retourner au menu")
        menu(url)
    elif choix == "7":
        lancer_conteneur_docker_CVE_2024_38473()
        lancer_conteneur_docker_CVE_2021_41773("blueteamsteve/cve-2021-41773:no-cgid", "8080:80")
        input("Appuyez sur entrer pour retourner au menu")
        menu(url)
    elif choix == "8":
        # Liste des CVE à rechercher
        cves = ["CVE-2024-38473", "CVE-2021-41773"]
    
        # Récupération en parallèle
        results = get_cves(cves)
    
        # Affichage des résultats
        display_cve_results(results)
    
        input("Appuyez sur entrer pour retourner au menu")
        menu(url)
    elif choix == "9":
        tuer_tous_les_conteneurs()
        input("Appuyez sur entrer pour retourner au menu")
        menu(url)
    elif choix == "10":
        ps = PasswordSecurity()
        ps.analyze_password_security()
        input("Appuyez sur entrer pour retourner au menu")
        menu(url)
    elif choix.upper() == "Q":
        print("Script terminé")
        generer_rapport(url)
        rapport()
        fichiers_a_supprimer = glob.glob('results/*')
        for chemin in fichiers_a_supprimer:
            if os.path.isdir(chemin):
                print(f"[-] Ignoré (dossier) : {chemin}")
                continue
            try:
                os.remove(chemin)
                print(f"[+] Fichier supprimé : {chemin}")
            except Exception as e:  
                print(f"[!] Erreur lors de la suppression de {chemin} : {e}")
        sys.exit()
    else:
        print("Option non valide.")
        menu(url)


if __name__ == "__main__":
    url = input("Entrez l'URL à scanner : ").strip()
    if not url_valide(url):
        print(" URL incorrecte. Format attendu : http://domaine.tld/ ou https://domaine.tld/ (slash final OBLIGATOIRE).")
        sys.exit(1)

    # Si on arrive ici, l’URL est valide (avec slash final)
    print("URL valide :", url)
    menu(url)  # ou tout autre traitement
