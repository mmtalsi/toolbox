import subprocess

def scan_cve_2021_41773():
    url = "http://127.0.0.1:8080"
    template = "cves/2021/CVE-2021-41773.yaml"

    print(f"[+] Scanning {url} for CVE-2021-41773...\n")

    try:
        # Affiche comme en ligne de commande (stdout/stderr natifs)
        subprocess.run(
            ["nuclei", "-u", url, "-t", template],
            check=True
        )
    except subprocess.CalledProcessError as e:
        print("[-] Scan failed.")
    except FileNotFoundError:
        print("[-] Nuclei not found. Make sure it is installed and in your PATH.")

if __name__ == "__main__":
    scan_cve_2021_41773()

