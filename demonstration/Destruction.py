import subprocess

def tuer_tous_les_conteneurs():
    try:
        # Récupère les IDs de tous les conteneurs en cours d'exécution
        result = subprocess.run("docker ps -q", shell=True, capture_output=True, text=True, check=True)
        # Découpe la sortie en lignes et filtre les vides
        container_ids = [cid for cid in result.stdout.splitlines() if cid.strip()]

        if container_ids:
            # Construit la commande avec les IDs séparés par des espaces
            cmd = ["docker", "kill"] + container_ids
            subprocess.run(cmd, check=True)
            print("✅ Tous les conteneurs Docker ont été tués.")
        else:
            print("ℹ️ Aucun conteneur en cours d'exécution.")

    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur lors de l'arrêt des conteneurs (exit {e.returncode}) : {e}")
