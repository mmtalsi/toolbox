
import subprocess

import sys

from scan.nikto import scan_vulnerabilities
from demo.CVE_2024_38473 import lancer_conteneur_docker_CVE_2024_38473
from demo.Destruction import tuer_tous_les_conteneurs
from scan.XSS import lancer_paramspider
from scan.XSS import scan_XSS
from scan.XSS import test_xss_redirection
from scan.sqlmc import run_main

def menu():
    # Affiche le menu
    print("\n     Menu toolbox :\n")
    
    print("             [1] - Reconnaissance")
    print("             [2] - Exploitation de vulnérabilités")
    print("             [3] - Injection XSS")
    print("             [4] - Scan et Injection SQL")
    print("             [5] - Analyse de la sécurité des mots de passe")
    print("             [6] - Générer un rapport")
    print("             [7] - Deployer les machines de démo")
    print("             [9] - Destruction\n")
    print("         [Q] - Quitter\n")

    choix = input("Veuillez choisir une option: ")

    # Vérifie le choix de l'utilisateur

    if choix == "1":
        scan_vulnerabilities()
        input("Appuyez sur entrer pour retourner au menu")
        menu()
    elif choix == "2":
        input("Appuyez sur entrer pour retourner au menu")
        menu()
    elif choix == "3":
        url = input("Entrez l'URL (domaine) cible (ex: example.com) : ").strip()
        lancer_paramspider(url)
        scan_XSS(url)
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

    menu()
