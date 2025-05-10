import os
import subprocess

# Dossier contenant les fichiers
results_dir = "results"
global_output_file = "all_dalfox_results.txt"

# On vide le fichier global au début
with open(global_output_file, "w") as global_out:
    global_out.write("")

# Parcours des fichiers dans le dossier results/
for filename in os.listdir(results_dir):
    if "vulnweb" in filename:
        filepath = os.path.join(results_dir, filename)

        if os.path.isfile(filepath):
            print(f"[*] Scanning: {filepath} with Dalfox...")

            individual_output_file = f"{filepath}_dalfox.txt"

            try:
                # Lancer Dalfox en mode fichier
                result = subprocess.run(
                    ["dalfox", "file", filepath, "--silence", "--no-color"],
                    capture_output=True,
                    text=True,
                    check=True
                )

                # Écrire dans le fichier individuel
                with open(individual_output_file, "w") as f:
                    f.write(result.stdout)

                # Ajouter au fichier global
                with open(global_output_file, "a") as global_out:
                    global_out.write(f"\n--- Results for {filename} ---\n")
                    global_out.write(result.stdout)

            except subprocess.CalledProcessError as e:
                print(f"[!] Error with {filename}: {e}")

print("\n[✓] Scan terminé. Résultats globaux dans :", global_output_file)
