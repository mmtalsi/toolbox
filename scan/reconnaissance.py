import subprocess
import argparse
from halo import Halo

def run_nikto(url):
    print("\n[╦] \033[1;36mLancement du scan Nikto\033[0m")
    spinner = Halo(text='Scan Nikto en cours...', spinner='dots')
    spinner.start()  # Démarrer le loader

    try:
        nikto_command = f"nikto -h {url}"
        process = subprocess.Popen(nikto_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        
        spinner.stop()  # Arrêter le loader après le scan

        if output:
            print(f" ╠═[-] Résultats de Nikto :\n{output.decode('utf-8')}")
            print("[╩]\n")
        if error:
            print(f"{Fore.RED}>>> [-] Erreur Nikto : {error.decode('utf-8')}{Style.RESET_ALL}")
    except Exception as e:
        spinner.stop()  # Arrêter le loader en cas d'erreur
        print(f"{Fore.RED}>>> [-] Erreur lors de l'exécution de Nikto : {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lancer un scan Nikto sur une URL cible")
    parser.add_argument("target", help="URL ou IP du serveur à scanner")
    args = parser.parse_args()

    run_nikto(args.target)
