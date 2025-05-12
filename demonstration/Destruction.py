import subprocess

def tuer_tous_les_conteneurs():
    try:
        # Récupère les IDs de tous les conteneurs en cours d'exécution
        process = subprocess.run("docker ps -q", shell=True, capture_output=True, text=True)
        container_ids = process.stdout.strip()

        if container_ids:
            # Tue tous les conteneurs
            subprocess.run(f"docker kill {container_ids}", shell=True, check=True)
            print("Tous les conteneurs Docker ont été tués.")
        else:
            print("Aucun conteneur en cours d'exécution.")

    except subprocess.SubprocessError as e:
        print(f"Erreur lors de l'arrêt des conteneurs : {e}")
