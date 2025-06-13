import subprocess
import os
import tkinter as tk
from bs4 import BeautifulSoup
import requests
import concurrent.futures

def lancer_conteneur_docker_CVE_2024_38473():
    repertoire_actuel = os.getcwd()
    chemin_webroot = os.path.join(repertoire_actuel, "test-env-webroot")
    if not os.path.isdir(chemin_webroot):
        print(f"Répertoire introuvable : {chemin_webroot}")
        return

    # Mode détaché (-d)
    commande_docker = (
        'docker run -d '
        '-p 8787:80 '
        f'-v "{chemin_webroot}:/app" '
        'webdevops/php-apache:7.1'
    )

    try:
        # Pour plus de simplicité, on exécute directement dans le shell courant
        result = subprocess.run(commande_docker, shell=True, check=True, capture_output=True)
        container_id = result.stdout.decode().strip()
        print(f"Conteneur démarré avec l’ID : {container_id}")
        print("Vérifiez avec : docker ps")
    except subprocess.CalledProcessError as e:
        print("Échec du lancement du conteneur :")
        print(e.stderr.decode())

def lancer_conteneur_docker_CVE_2021_41773(image_name: str, port_mapping: str, chemin_dossier: str = "cve_2021_41773"):
    try:
        # Étape 1 : Build local de l'image Docker
        print(f"[+] Construction de l'image Docker '{image_name}' depuis {chemin_dossier}...")
        build_result = subprocess.run(
            ["docker", "build", "-t", image_name, "."],
            cwd=chemin_dossier,
            capture_output=True,
            text=True,
            check=True
        )
        print(f"[✔] Image '{image_name}' construite avec succès.")

        # Étape 2 : Lancement du conteneur
        run_result = subprocess.run(
            ["docker", "run", "-dit", "-p", port_mapping, image_name],
            capture_output=True,
            text=True,
            check=True
        )
        container_id = run_result.stdout.strip()
        print(f"[✔] Conteneur lancé avec succès (ID: {container_id})")
        return container_id

    except subprocess.CalledProcessError as e:
        print(f"[✖] Une erreur est survenue :\n{e.stderr}")
        return None

import requests

def check_cve_2021_41773(url):
    template = "cves/2021/CVE-2021-41773.yaml"

    print(f"[+] Scanning {url} for CVE-2021-41773...\n")

    try:
        # Affiche comme en ligne de commande (stdout/stderr natifs)
        subprocess.run(
            ["nuclei", "-u", url, "-t", template],
            check=True
        )
    except subprocess.CalledProcessError as e:
        print("[-] Scan failed.")
    except FileNotFoundError:
        print("[-] Nuclei not found. Make sure it is installed and in your PATH.")

def check_cve_2024_38473(base_url: str):
    """
    Teste les chemins pour la CVE-2024-38473 en ajoutant %3fooo.php à chaque fichier du fichier txt.

    :param base_url: URL de base (ex: "http://example.com/")
    """
    if not base_url.endswith('/'):
        base_url += '/'

    try:
        with open("demonstration/wordlists/potential_protected_php_files_10.txt", "r") as f:
            paths = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Fichier 'potential_protected_php_files_10.txt' introuvable.")
        return

    for path in paths:
        full_url = f"{base_url}{path}%3fooo.php"
        try:
            response = requests.get(full_url, timeout=5)
            print(f"[{response.status_code}] {full_url}")
            if response.status_code == 200 and "php" in response.text.lower():
                print(f"--> POSSIBLE VULNERABILITY at {full_url}")
        except requests.RequestException as e:
            print(f"[ERROR] {full_url} -> {e}")

def fetch_cve(cve_id):
    """Récupère rapidement les infos essentielles d'une CVE"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if data['totalResults'] == 0:
            return {cve_id: "Non trouvée"}
        
        cve = data['vulnerabilities'][0]['cve']
        
        # Extraction des données essentielles seulement
        return {
            cve_id: {
                "description": next(d['value'] for d in cve['descriptions'] if d['lang'] == 'en'),
                "severity": cve['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'] 
                           if 'metrics' in cve and 'cvssMetricV31' in cve['metrics'] 
                           else "Non spécifiée",
                "score": cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'] 
                         if 'metrics' in cve and 'cvssMetricV31' in cve['metrics'] 
                         else "N/A",
                "published": cve['published'],
                "references": [ref['url'] for ref in cve.get('references', [])][:3]  # 3 premières refs seulement
            }
        }
    except Exception as e:
        return {cve_id: f"Erreur: {str(e)}"}

def fetch_cve(cve_id):
    """Récupère rapidement les infos essentielles d'une CVE"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if data['totalResults'] == 0:
            return {cve_id: "Non trouvée"}
        
        cve = data['vulnerabilities'][0]['cve']
        
        # Extraction des données essentielles seulement
        return {
            cve_id: {
                "description": next(d['value'] for d in cve['descriptions'] if d['lang'] == 'en'),
                "severity": cve['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'] 
                           if 'metrics' in cve and 'cvssMetricV31' in cve['metrics'] 
                           else "Non spécifiée",
                "score": cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'] 
                         if 'metrics' in cve and 'cvssMetricV31' in cve['metrics'] 
                         else "N/A",
                "published": cve['published'],
                "references": [ref['url'] for ref in cve.get('references', [])][:3]  # 3 premières refs seulement
            }
        }
    except Exception as e:
        return {cve_id: f"Erreur: {str(e)}"}

def get_cves(cve_list):
    """Récupère plusieurs CVE en parallèle"""
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(fetch_cve, cve_list))
    return results

def display_cve_results(results):
    """Affiche les résultats des CVE de manière formatée"""
    for result in results:
        for cve_id, data in result.items():
            print(f"\n\033[1m{cve_id}\033[0m")
            if isinstance(data, str):
                print(data)
            else:
                print(f"Description: {data['description']}")
                print(f"Sévérité: {data['severity']} (Score: {data['score']})")
                print(f"Publiée le: {data['published']}")
                print("Références:")
                for ref in data['references']:
                    print(f"- {ref}")


def arreter_conteneur_docker():
    global process
    if process:
        process.terminate()  # Termine proprement
        process.wait()
        print("Le conteneur a été arrêté.")

def creer_interface():
    root = tk.Tk()
    root.title("Gestion du Conteneur Docker")
    
    btn_quitter = tk.Button(root, text="Quitter", command=arreter_conteneur_docker, font=("Arial", 14), bg="red", fg="white")
    btn_quitter.pack(pady=20)
    
    root.protocol("WM_DELETE_WINDOW", arreter_conteneur_docker)
    root.mainloop()
if __name__ == "__main__":
    lancer_conteneur_docker_CVE_2024_38473()
    lancer_conteneur_docker_CVE_2021_41773("blueteamsteve/cve-2021-41773:with-cgid", "8080:80")
    #creer_interface()
