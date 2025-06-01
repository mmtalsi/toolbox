#!/usr/bin/env python3
import glob
import re
from bs4 import BeautifulSoup
import datetime
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / 'reports'
COMPLETE_REPORT_PATH = BASE_DIR / 'rapport_complet.html'

SECTIONS = {
    '[LOGIN PAGE]': (
        'page de connexion',
        [   
            'Blocage en cas d’échecs répétés',
            'Authentification multifacteur (MFA)',
            'Politiques de mot de passe robuste',
            'Vérification en deux facteurs (2FA/MFA)',
            'Filtrer accès au seul utilisateur ou partener ayant le droit d"accès',
            'Mises à jour régulières de votre serveur web',
            'Protection contre le bruteforce'
        ]
    ),
    'URL:': (
        'Vulnérabilité XSS',
        [
            'Validation et assainissement des données entrantes',
            'Headers HTTP complémentaires(X-Content-Type-Options: nosniff,X-Frame-Options:DENY,Set-Cookie HttpOnly; Secure)',
        ]
    ),
    'URL(s) VULNÉRABLE(S)': (
        'Vulnérabilité SQL',
        [
            'Ne renvoyez jamais une trace de la base de données ou le message d’erreur complet à l’utilisateur.Fournissez des messages génériques et consignez le détail dans des logs internes.',
            'Déployer un WAF configuré pour détecter et bloquer les patterns typiques d’injection'
        ]
    )
}

def lire_rapport_txt(path):
    """Lit le contenu d'un fichier texte"""
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    return "Aucun contenu disponible."

def extraire_domaine_depuis_rapport(texte):
    """Extrait le nom de domaine du rapport"""
    m = re.search(r"Domain Analysis Report for ([\w\.-]+)", texte)
    return m.group(1) if m else "inconnu.local"

import re


def detecter_outils_executes(texte):
    """Détecte précisément quels outils ont été exécutés dans le rapport."""
    outils = []

    # 1) On repère toutes les sections au format "=== NOM DE SECTION ==="
    pattern_section = re.compile(r"={2,}\s*(.*?)\s*={2,}")
    sections = []  # liste de tuples (nom_section, start_index)
    for match in pattern_section.finditer(texte):
        nom_section = match.group(1).strip()
        debut = match.start()
        sections.append((nom_section, debut))

    # Pour isoler chaque bloc, on recalcule la fin de chaque section
    sections_with_boundaries = []
    for i, (nom, start) in enumerate(sections):
        if i + 1 < len(sections):
            end = sections[i + 1][1]
        else:
            end = len(texte)
        sections_with_boundaries.append((nom, start, end))

    def get_bloc(section_name):
        """
        Renvoie le contenu texte (sous‐chaîne) compris entre l'en‐tête 'section_name'
        et l'en‐tête suivant, ou la fin de texte si c'est la dernière section.
        """
        for nom, start, end in sections_with_boundaries:
            if nom.lower() == section_name.lower():
                return texte[start:end]
        return ""

    def section_executee(section_name, message_non_execute=None):
        """
        Vérifie si la section correspond à une exécution réelle (sans message "non exécuté") :
        - L'en‐tête doit exister.
        - Le message 'message_non_execute' ne doit pas être présent dans le bloc de cette section.
        """
        # 1. L’en‐tête existe‐t‐elle ?
        header_pattern = r"={2,}\s*" + re.escape(section_name) + r"\s*={2,}"
        if not re.search(header_pattern, texte, flags=re.IGNORECASE):
            return False

        # 2. On récupère le bloc correspondant à cette section
        bloc = get_bloc(section_name)

        # 3. Si on a un message "non exécuté", il ne doit PAS figurer dans le bloc
        if message_non_execute and message_non_execute.lower() in bloc.lower():
            return False

        return True

    # ==== Nikto ====
    if section_executee(
        "SCAN NIKTO",
        message_non_execute="Aucun résultat"
    ):
        # On vérifie la présence d'un marqueur typique comme "Target IP"
        bloc_nikto = get_bloc("SCAN NIKTO")
        if "Target IP" in bloc_nikto:
            outils.append("Nikto")

    # ==== DIRB ====
    dirb_execute = False
    if section_executee(
        "DETECTE LOGIN PAGE",
        message_non_execute="L'outil DIRB non executé"
    ):
        bloc_login = get_bloc("DETECTE LOGIN PAGE")
        if "[LOGIN PAGE]" in bloc_login:
            dirb_execute = True

    if section_executee(
        "REDIRECTIONS DETECTÉES",
        message_non_execute="Aucune redirection détectée"
    ):
        bloc_redir = get_bloc("REDIRECTIONS DETECTÉES")
        if "[REDIRECTION]" in bloc_redir:
            dirb_execute = True

    if dirb_execute:
        outils.append("DIRB")

    # ==== Reconnaissance de domaine ====
    if section_executee("SCAN Reconnaissance Domaine"):
        bloc_reco = get_bloc("SCAN Reconnaissance Domaine")
        if "Subfinder" in bloc_reco and "Found" in bloc_reco:
            outils.append("Subfinder")
        if "WebTech" in bloc_reco and "Detected technologies" in bloc_reco:
            outils.append("WebTech")
        if "WHOIS" in bloc_reco and "No match" not in bloc_reco:
            outils.append("WHOIS")

    # ==== XSS (ParamSpider) ====
    if section_executee(
        "SCAN XSS",
        message_non_execute="non executé"
    ):
        bloc_xss = get_bloc("SCAN XSS")
        if "Payload:" in bloc_xss:
            outils.append("ParamSpider / XSS")

    # ==== SQL (SQLMap) ====
    # 1) On vérifie que la section principale existe et n'affiche pas "non executé"
    sql_section_ok = section_executee(
        "SCAN INJECTION SQL",
        message_non_execute="non executé"
    )
    # 2) On cherche ensuite le sous‐titre exact "=== URL(s) VULNÉRABLE(S) ===" quelque part dans tout le texte
    url_vuln_pattern = re.compile(r"={2,}\s*URL\s*\(s\)\s*VULNÉRABLE\s*\(S\)\s*={2,}", flags=re.IGNORECASE)
    if sql_section_ok and re.search(url_vuln_pattern, texte):
        outils.append("SQLMap")

    # ==== Header Check ====
    if section_executee(
        "INFORMATIONS SERVEUR ET EN-TÊTES",
        message_non_execute="Aucune information"
    ):
        bloc_header = get_bloc("INFORMATIONS SERVEUR ET EN-TÊTES")
        if "Serveur Web :" in bloc_header:
            outils.append("Header Check")

    # ==== Nmap ====
    if section_executee(
        "PORTS OUVERTS ET SERVICES",
        message_non_execute="Aucun résultat"
    ):
        bloc_nmap = get_bloc("PORTS OUVERTS ET SERVICES")
        if "Ports ouverts trouvés" in bloc_nmap:
            outils.append("Nmap")

    return outils

def detecter_vulnerabilites(texte):
    """Détecte les vulnérabilités dans le texte du rapport"""
    out = []
    outils_executes = detecter_outils_executes(texte)
    
    # Vulnérabilités génériques basées sur les outils
    if "ParamSpider / XSS" in outils_executes:
        out.append(("XSS potentiel", "Moyenne", 
                   "Tests XSS effectués avec succés - vérifier les résultats spécifiques dans la section  'Détails Techniques' ", 
                   "Filtrer les entrées, implémenter CSP"))
    
    if "SQLMap" in outils_executes:
        out.append(("Injection SQL", "Critique", 
                   "Tests SQL effectués avec succés - vérifier les résultats spécifiques dans la section  'Détails Techniques' - vérifier les résultats spécifiques", 
                   "Requêtes préparées, WAF"))
    
    # Détection des vulnérabilités spécifiques
    for line in texte.splitlines():
        line = line.strip()
        if not line or "===" in line or "non executé" in line.lower():
            continue
            
        if "Injection SQL" in line:
            out.append(("Injection SQL", "Critique", line, "Requêtes préparées"))
        elif "XSS" in line.lower() and "aucun" not in line.lower():
            out.append(("XSS", "Moyenne", line, "Filtrage des entrées"))
        elif "[LOGIN PAGE]" in line:
            out.append(("Page de login", "Info", line, "forcez le TLS (HSTS) pour chiffrer toutes les communications"))
        elif "wildcard" in line:
            out.append(("Crossdomain non restreint", "Moyenne", line, "Restriction des domaines"))
        elif "anti-clickjacking" in line:
            out.append(("Manque X-Frame-Options", "Faible", line, "Ajouter header DENY"))
        elif "XSS protection" in line:
            out.append(("Manque X-XSS-Protection", "Faible", line, "Ajouter header 1; mode=block"))
        elif "MIME-sniffing" in line:
            out.append(("Manque X-Content-Type", "Faible", line, "Ajouter header nosniff"))
    
    # Déduplication
    seen = set()
    return [v for v in out if not (v in seen or seen.add(v))]

def generer_resume_par_outil(texte, domaine):
    """Génère un résumé organisé par outil"""
    sections = {}
    current_section = None
    buffer = []
    
    for line in texte.splitlines():
        line = line.strip()
        if line.startswith('====================') and line.endswith('===================='):
            if current_section:
                sections[current_section] = "\n".join(buffer)
            current_section = line
            buffer = []
        elif current_section:
            buffer.append(line)
    
    if current_section and buffer:
        sections[current_section] = "\n".join(buffer)
    
    return sections

def nettoyer_popup(soup):
    """Nettoie les popups indésirables"""
    for script in soup.find_all('script'):
        if 'alert(' in script.text:
            script.decompose()

def renumeroter_sections(soup):
    """Renumérote les sections correctement"""
    for i, div in enumerate(soup.find_all("div", class_="section"), 1):
        h2 = div.find("h2")
        if h2 and re.match(r"\d+\.", h2.text.strip()):
            h2.string = re.sub(r"^\d+\.", f"{i}.", h2.text)

def ajouter_donnees_au_html(html_src, txt_path, html_out):
    """Génère le rapport HTML final"""
    # Vérifie si le template existe, sinon le crée
    if not os.path.exists(html_src):
        with open(html_src, 'w', encoding='utf-8') as f:
            f.write('''<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <title>Rapport de Pentest</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f4; }
        h1, h2, h3 { color: #2c3e50; }
        .section { background: #fff; padding: 20px; margin-bottom: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        table, th, td { border: 1px solid #ddd; }
        th, td { padding: 12px; text-align: left; }
        th { background-color: #2c3e50; color: white; }
        pre { white-space: pre-wrap; background: #f8f8f8; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Rapport de Test d'Intrusion</h1>
    <div class="section"><h2>1. Introduction</h2><p></p></div>
    <div class="section"><h2>2. Méthodologie</h2><p>Méthodologie OWASP</p></div>
    <div class="section"><h2>3. Résumé Exécutif</h2><p></p></div>
    <div class="section"><h2>4. Vulnérabilités Identifiées</h2>
        <table><tr><th>Nom</th><th>Gravité</th><th>Description</th><th>Recommandation</th></tr></table>
    </div>
</body>
</html>''')

    texte = lire_rapport_txt(txt_path)
    domaine = extraire_domaine_depuis_rapport(texte)
    soup = BeautifulSoup(open(html_src, encoding='utf-8'), 'html.parser')
    
    outils = detecter_outils_executes(texte)
    vulns = detecter_vulnerabilites(texte)
    resumes = generer_resume_par_outil(texte, domaine)
    today = datetime.datetime.now().strftime("%d/%m/%Y")

    # Section 1 - Introduction
    intro = soup.find('h2', string=re.compile(r"1\. Introduction"))
    if intro:
        p = intro.find_next('p')
        if p:
            p.string = f"Rapport de test d'intrusion pour {domaine} - {today}"

    # Section 3 - Résumé exécutif
    resume = soup.find('h2', string=re.compile(r"3\. Résumé Exécutif"))
    if resume:
        p = resume.find_next('p')
        if p:
            p.string = f"Outils utilisés: {', '.join(outils) if outils else 'Aucun outil exécuté'}"

    # Section 4 - Vulnérabilités
    vuln_section = soup.find('h2', string=re.compile(r"4\. Vulnérabilités"))
    if vuln_section:
        table = vuln_section.find_next('table')
        if table:
            for row in table.find_all('tr')[1:]:
                row.decompose()
            for nom, gravite, desc, reco in vulns:
                row = soup.new_tag('tr')
                row.append(soup.new_tag('td', string=nom))
                row.append(soup.new_tag('td', string=gravite))
                row.append(soup.new_tag('td', string=desc))
                row.append(soup.new_tag('td', string=reco))
                table.append(row)

    # Section Détails Techniques
    details = soup.new_tag('div', **{'class': 'section'})
    details.append(soup.new_tag('h2', string="Détails Techniques"))
    content = soup.new_tag('pre')
    content.string = texte
    details.append(content)
    soup.body.append(details)

    nettoyer_popup(soup)
    renumeroter_sections(soup)
    
    with open(html_out, 'w', encoding='utf-8') as f:
        f.write(soup.prettify())
    print(f"Rapport généré: {html_out}")
    
def collect_sections():
    found = []
    for fp in glob.glob(str(REPORTS_DIR / 'security_report*.txt')):
        content = fp and Path(fp).read_text(encoding='utf-8', errors='ignore')
        for key in SECTIONS:
            if key not in found and re.search(re.escape(key), content, re.IGNORECASE):
                found.append(key)
    return found

def inject():
    soup = BeautifulSoup(COMPLETE_REPORT_PATH.read_text(encoding='utf-8'), 'html.parser')
    h2 = soup.find('h2', string=lambda t: t and '5. Recommandations Générales' in t)
    if not h2:
        raise RuntimeError("Section 5 introuvable")

    # récupère ou crée la <ul>
    ul = h2.find_next_sibling('ul') or (h2.insert_after(BeautifulSoup('<ul></ul>', 'html.parser').ul) or h2.find_next_sibling('ul'))

    # on ne tient plus compte des <li> déjà présents : on y ajoute seulement les <h3> manquants
    existing_h3 = {h3.get_text(strip=True) for h3 in ul.find_all('h3')}
    keys = collect_sections()
    for key in keys:
        subtitle, recs = SECTIONS[key]
        # créer le <h3> si nécessaire
        if subtitle not in existing_h3:
            h3 = soup.new_tag('h3', style='color:black;font-weight:bold;')
            h3.string = subtitle
            ul.append(h3)
            existing_h3.add(subtitle)
        else:
            # si le <h3> existe déjà, on le récupère pour insérer juste après
            h3 = next(h for h in ul.find_all('h3') if h.get_text(strip=True) == subtitle)

        # on insère **systématiquement** les <li> juste après ce <h3>
        for rec in recs:
            li = soup.new_tag('li')
            li.string = rec
            h3.insert_after(li)
            # pour la prochaine insertion, on déplace notre pointeur
            h3 = li

    COMPLETE_REPORT_PATH.write_text(str(soup), encoding='utf-8')
    print(f"Injecté les sections pour : {', '.join(keys)}")
def rapport():
# Configuration des chemins
    template_html = "rapport.html"  # Fichier template de base
    output_file = "rapport_complet.html"  # Fichier de sortie
    report_files = glob.glob("reports/security_report_*.txt")  # Fichiers de rapport
    
    if report_files:
        report_files.sort(key=os.path.getmtime, reverse=True)
        ajouter_donnees_au_html(template_html, report_files[0], output_file)
        inject()
    else:
        print("Erreur: Aucun fichier de rapport trouvé dans 'reports/'")
        print("Assurez-vous d'avoir des fichiers security_report_*.txt dans le dossier reports/")

if __name__ == "__main__":
    rapport()
