import subprocess
import sys
import tempfile
import os
import re
from urllib.parse import urlparse
from colorama import init, Fore, Style
from datetime import datetime

# Initialisation
init(autoreset=True)

def nettoyer_ligne(ligne):
    """Nettoie les codes ANSI et caractères spéciaux"""
    return re.sub(r'(\[\d+m)|\[g\]|\[[0-9;]+[mK]?|\[\d+;\d+;\d+m', '', ligne)

def afficher_banniere():
    print(Fore.CYAN + "="*60)
    print(Fore.GREEN + "        Lanceur SQLMC - Rapport Complet")
    print(Fore.CYAN + "="*60)

def choisir_profondeur():
    print(Fore.YELLOW + "\n[+] Choisissez le niveau de scan :")
    print("    1. Léger  (profondeur 1)")
    print("    2. Moyen  (profondeur 2)")
    print("    3. Fort   (profondeur 3)")
    choix = input(Fore.YELLOW + "[?] Votre choix (1/2/3) : ").strip()
    return {'1': 1, '2': 2, '3': 3}.get(choix, 1)

def preparer_dossier_resultats():
    dossier = os.path.join(os.getcwd(), 'results')
    if not os.path.exists(dossier):
        os.makedirs(dossier)
        print(Fore.YELLOW + f"[+] Dossier créé : {dossier}")
    return dossier

def analyser_resultats(fichier_sortie, domaine, url_cible, profondeur_scan):
    try:
        with open(fichier_sortie, 'r', encoding='utf-8', errors='ignore') as f:
            lignes = [nettoyer_ligne(l) for l in f.readlines()]
    except FileNotFoundError:
        print(Fore.RED + f"[-] Fichier de résultats introuvable : {fichier_sortie}")
        return

    vulnérables = []
    non_vulnérables = []
    current_url = None

    for ligne in lignes:
        ligne = ligne.strip()
        if ligne.startswith(('http://', 'https://')):
            current_url = ligne
        elif current_url and 'Vulnerable:' in ligne:
            if 'Not Vulnerable' in ligne:
                if current_url not in non_vulnérables:
                    non_vulnérables.append(current_url)
            else:
                if current_url not in vulnérables:
                    vulnérables.append(current_url)
            current_url = None

    dossier_results = preparer_dossier_resultats()
    nom_rapport = f"rapport_sqlmc_{domaine}.txt"
    chemin_rapport = os.path.join(dossier_results, nom_rapport)

    print(Fore.GREEN + "\n[✔] Résumé des résultats :")
    print(Fore.CYAN + "-"*60)
    print(Fore.YELLOW + f"[→] Rapport sera enregistré dans : {chemin_rapport}")
    
    if vulnérables:
        print(Fore.RED + f"[!] {len(vulnérables)} URL(s) VULNÉRABLE(S) :")
        for i, url in enumerate(vulnérables, 1):
            print(Fore.RED + f"   {i}. {url}")
    else:
        print(Fore.GREEN + "[✓] Aucune URL vulnérable détectée.")
    
    if non_vulnérables:
        print(Fore.BLUE + f"\n[↓] {len(non_vulnérables)} URL(s) NON VULNÉRABLE(S) :")
        for i, url in enumerate(non_vulnérables, 1):
            print(Fore.BLUE + f"   {i}. {url}")

    with open(chemin_rapport, 'w', encoding='utf-8') as f:
        f.write(f"URL cible: {url_cible}\n")
        f.write(f"Profondeur de scan: {profondeur_scan}\n")
        f.write(f"Généré le: {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}\n\n")
        
        f.write("=== URL(s) VULNÉRABLE(S) ===\n")
        if vulnérables:
            for url in vulnérables:
                f.write(f"- {url}\n")
        else:
            f.write("Aucune URL vulnérable détectée.\n")
        
        f.write("\n=== URL(s) NON VULNÉRABLES ===\n")
        if non_vulnérables:
            for url in non_vulnérables:
                f.write(f"- {url}\n")

    # Copie vers rapport_SQL.txt si aucune URL vulnérable
    if not vulnérables:
        chemin_global = os.path.join(dossier_results, "rapport_SQL.txt")
        with open(chemin_rapport, 'r', encoding='utf-8') as src, \
             open(chemin_global, 'w', encoding='utf-8') as dst:
            dst.write(src.read())
        print(Fore.YELLOW + f"[i] Aucun URL vulnérable – contenu copié dans : {chemin_global}")

    # Menu de sélection d’URL vulnérable
    url_choisie = None
    if vulnérables:
        print(Fore.MAGENTA + "\n[+] Sélectionnez une URL vulnérable à utiliser :")
        for i, url in enumerate(vulnérables, 1):
            print(Fore.MAGENTA + f"   {i}. {url}")

        while True:
            try:
                choix = int(input(Fore.YELLOW + "[?] Entrez le numéro de l'URL : "))
                if 1 <= choix <= len(vulnérables):
                    url_choisie = vulnérables[choix - 1]
                    print(Fore.GREEN + f"\n[✓] URL sélectionnée : {url_choisie}")
                    break
                else:
                    print(Fore.RED + "[!] Numéro invalide, réessayez.")
            except ValueError:
                print(Fore.RED + "[!] Entrée non valide, veuillez entrer un nombre.")
    else:
        print(Fore.CYAN + "[i] Pas d’URL vulnérable à sélectionner.")

    return url_choisie

def run_main(url_cible=None):
    afficher_banniere()
    
    if url_cible is None:
        url_cible = input(Fore.YELLOW + "[+] URL cible (ex: http://site.com): ").strip()
    
    if not url_cible.startswith(('http://', 'https://')):
        print(Fore.RED + "[-] URL doit commencer par http:// ou https://")
        sys.exit(1)

    profondeur = choisir_profondeur()
    domaine = urlparse(url_cible).netloc.replace(':', '_').replace('/', '_')

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        fichier_sortie = tmp.name

    print(Fore.CYAN + f"\n[~] Lancement du scan (profondeur {profondeur})...")
    try:
        subprocess.run(['sqlmc', '-u', url_cible, '-d', str(profondeur), '-o', fichier_sortie], check=True)
        url_choisie = analyser_resultats(fichier_sortie, domaine, url_cible, profondeur)
        if url_choisie:
            print(Fore.YELLOW + f"\n[✔] URL vulnérable sélectionnée pour traitement : {url_choisie}")
        else:
            print(Fore.YELLOW + "\n[!] Aucune URL vulnérable sélectionnée.")
    except subprocess.CalledProcessError:
        print(Fore.RED + "\n[!] Erreur lors de l'exécution de SQLMC")
    finally:
        if os.path.exists(fichier_sortie):
            try:
                os.remove(fichier_sortie)
            except:
                pass
    return url_choisie

if __name__ == "__main__":
    try:
        run_main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrompu")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"\n[!] Erreur: {str(e)}")
        sys.exit(1)
