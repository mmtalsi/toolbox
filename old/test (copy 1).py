#!/usr/bin/env python3
import glob
import re
from bs4 import BeautifulSoup
import datetime
import os

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

def detecter_outils_executes(texte):
    """Détecte précisément quels outils ont été exécutés"""
    outils = []
    
    def section_executee(section, message_non_execute=None, marqueur_execution=None):
        """Vérifie si une section correspond à une exécution réelle"""
        if section in texte:
            if message_non_execute and message_non_execute.lower() in texte.lower():
                return False
            if marqueur_execution and marqueur_execution not in texte:
                return False
            return True
        return False
    
    # Nikto
    if section_executee("SCAN NIKTO", "Aucun résultat", "Target IP"):
        outils.append("Nikto")
    
    # DIRB
    dirb_execute = False
    if section_executee("DETECTE LOGIN PAGE", "L'outil DIRB non executé", "[LOGIN PAGE]"):
        dirb_execute = True
    if section_executee("REDIRECTIONS DÉTECTÉES", "Aucune redirection détectée", "[REDIRECTION]"):
        dirb_execute = True
    if dirb_execute:
        outils.append("DIRB")
    
    # Reconnaissance
    if section_executee("SCAN Reconnaissance Domaine"):
        if "Subfinder" in texte and "Found" in texte:
            outils.append("Subfinder")
        if "WebTech" in texte and "Detected technologies" in texte:
            outils.append("WebTech")
        if "WHOIS" in texte and not "No match" in texte:
            outils.append("WHOIS")
    
    # XSS
    if section_executee("SCAN XSS", "non executé", "Payload:"):
        outils.append("ParamSpider / XSS")
    
    # SQL
    if section_executee("SCAN INJECTION SQL", "non executé", "URL(s) VULNÉRABLE(S)"):
        outils.append("SQLMap")
    
    # Header Check
    if section_executee("INFORMATIONS SERVEUR ET EN-TÊTES", "Aucune information", "Serveur Web :"):
        outils.append("Header Check")
    
    # Nmap
    if section_executee("PORTS OUVERTS ET SERVICES", "Aucun résultat", "Ports ouverts trouvés"):
        outils.append("Nmap")
    
    return outils

def detecter_vulnerabilites(texte):
    """Détecte les vulnérabilités dans le texte du rapport"""
    out = []
    outils_executes = detecter_outils_executes(texte)
    
    # Vulnérabilités génériques basées sur les outils
    if "ParamSpider / XSS" in outils_executes:
        out.append(("XSS potentiel", "Moyenne", 
                   "Tests XSS effectués - vérifier les résultats spécifiques", 
                   "Filtrer les entrées, implémenter CSP"))
    
    if "SQLMap" in outils_executes:
        out.append(("Injection SQL", "Critique", 
                   "Tests SQL effectués - vérifier les résultats spécifiques", 
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
            out.append(("Page de login", "Info", line, "Protection renforcée"))
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

if __name__ == "__main__":
    # Configuration des chemins
    template_html = "rapport.html"  # Fichier template de base
    output_file = "rapport_final.html"  # Fichier de sortie
    report_files = glob.glob("reports/security_report_*.txt")  # Fichiers de rapport
    
    if report_files:
        report_files.sort(key=os.path.getmtime, reverse=True)
        ajouter_donnees_au_html(template_html, report_files[0], output_file)
    else:
        print("Erreur: Aucun fichier de rapport trouvé dans 'reports/'")
        print("Assurez-vous d'avoir des fichiers security_report_*.txt dans le dossier reports/")
