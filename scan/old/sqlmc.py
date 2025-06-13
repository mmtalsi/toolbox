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
    """Crée le dossier results s'il n'existe pas et retourne le chemin"""
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
    nom_rapport = f"rapport_{domaine}.txt"
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
        f.write(f"=== RAPPORT SQLMC - {datetime.now().strftime('%d/%m/%Y %H:%M:%S')} ===\n\n")
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
        
        f.write("\n=== LOGS COMPLETS ===\n")
        f.write("\n".join(lignes))

    print(Fore.CYAN + "-"*60)
    print(Fore.GREEN + f"\n[✓] Rapport enregistré :")
    print(Fore.YELLOW + f"    Nom : {nom_rapport}")
    print(Fore.YELLOW + f"    Dossier : {os.path.abspath(dossier_results)}")
    print(Fore.CYAN + "="*60)

def run_main():
    """Fonction principale qui encapsule la logique du programme"""
    afficher_banniere()
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
        analyser_resultats(fichier_sortie, domaine, url_cible, profondeur)
    except subprocess.CalledProcessError:
        print(Fore.RED + "\n[!] Erreur lors de l'exécution de SQLMC")
    finally:
        if os.path.exists(fichier_sortie):
            try:
                os.remove(fichier_sortie)
            except:
                pass

if __name__ == "__main__":
    try:
        run_main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrompu")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"\n[!] Erreur: {str(e)}")
        sys.exit(1)
