
import subprocess

import sys

from scan.nikto import scan_vulnerabilities
from scan.nikto import check_server
from scan.nikto import scan_all_ports
from scan.nikto import run_nikto
from scan.nikto import run_dirb
from scan.nikto import scan_redirections_with_dirb
from demo.CVE_2024_38473 import lancer_conteneur_docker_CVE_2024_38473
from demo.Destruction import tuer_tous_les_conteneurs
from scan.XSS import lancer_paramspider
from scan.XSS import scan_XSS
from scan.XSS import test_xss_redirection
from scan.sqlmc import run_main
from urllib.parse import urlparse

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
    print("             [5] - Analyse de la sécurité des mots de passe")
    print("             [6] - Générer un rapport")
    print("             [7] - Deployer les machines de démo")
    print("             [9] - Destruction\n")
    print("         [Q] - Quitter\n")

    choix = input("Veuillez choisir une option: ")

    # Vérifie le choix de l'utilisateur

    if choix == "1":
        #scan_vulnerabilities()
        #url = input("\nEntrez l'URL à scanner : ")
        check_server(url)
        scan_all_ports(url)
        run_nikto(url)
        input("Appuyez sur entrer pour retourner au menu")
        menu()
    elif choix == "2":
        #url = input("\nEntrez l'URL à scanner : ")
        run_dirb(url)
        scan_redirections_with_dirb(url)
        input("Appuyez sur entrer pour retourner au menu")
        menu()
    elif choix == "3":
        #url = input("Entrez l'URL (domaine) cible (ex: example.com) : ").strip()
        domain=get_domain(url)
        print(f"Le domaine est : {domain}")
        lancer_paramspider(domain)
        scan_XSS(domain)
        test_xss_redirection() 
        input("Appuyez sur entrer pour retourner au menu")
        menu()
    elif choix == "4":
        run_main()
        input("Appuyez sur entrer pour retourner au menu")
        menu()
    elif choix == "5":
        input("Appuyez sur entrer pour retourner au menu")
        menu()
    elif choix == "6":
        input("Appuyez sur entrer pour retourner au menu")
        menu()
    elif choix == "7":
        lancer_conteneur_docker_CVE_2024_38473()
        input("Appuyez sur entrer pour retourner au menu")
        menu()
    elif choix == "9":
        tuer_tous_les_conteneurs()
        input("Appuyez sur entrer pour retourner au menu")
        menu()
    elif choix.upper() == "Q":
        print("Script terminé")
        sys.exit()
    else:
        print("Option non valide.")
        menu()

if __name__ == "__main__":
    url = input("\nEntrez l'URL à scanner : ")
    menu(url)
