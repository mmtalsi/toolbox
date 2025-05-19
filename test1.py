import glob
import re
from bs4 import BeautifulSoup
import datetime
import os

def lire_rapport_txt(path):
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    return "Aucun contenu disponible."

def extraire_domaine_depuis_rapport(texte):
    m = re.search(r"Domain Analysis Report for ([\w\.-]+)", texte)
    return m.group(1) if m else "inconnu.local"

def detecter_outils_executes(texte):
    outils = []
    def sv(n, excl): return n in texte and excl not in texte
    if sv("SCAN NIKTO", "Aucun résultat"): outils.append("Nikto")
    if sv("DETECTE LOGIN PAGE", "Aucun résultat"): outils.append("DIRB")
    if sv("REDIRECTIONS DÉTECTÉES", "Aucune redirection"): outils.append("DIRB")
    if "SCAN Reconnaissance Domaine" in texte:
        for o in ("Subfinder", "WebTech", "WHOIS"):
            if o in texte: outils.append(o)
    if sv("SCAN XSS", "Aucun résultat"): outils.append("ParamSpider / XSS")
    if sv("SCAN INJECTION SQL", "Aucun résultat"): outils.append("SQLMap")
    if sv("INFORMATIONS SERVEUR ET EN-TÊTES", "Aucune information"): outils.append("Header Check")
    if sv("PORTS OUVERTS ET SERVICES", "Aucun résultat"): outils.append("Nmap")
    return outils

def detecter_sqlmc_urls_vulnerables(texte):
    pattern = re.compile(r"=== URL\(s\) VULNÉRABLE\(S\) ===(.*?)=== URL\(s\) NON VULNÉRABLES ===", re.DOTALL)
    match = pattern.search(texte)
    if not match:
        return False
    bloc = match.group(1)
    return "Aucune URL vulnérable détectée" not in bloc

def detecter_vulnerabilites(texte, outils_executes):
    out = []

    if 'Payload: <script>alert(1)</script>' in texte:
        out.append((
            "XSS potentiel",
            "Moyenne",
            "ParamSpider/XSS a été exécuté - des tests XSS ont réussi (vulnérabilité confirmée)",
            "Filtrer et échapper les entrées utilisateur, implémenter CSP"
        ))

    outils_lower = [o.lower() for o in outils_executes]

    for l in texte.splitlines():
        line = l.strip()
        if not line or "===" in line or "Aucun résultat" in line or "Erreur" in line:
            continue
        if "Injection SQL" in line:
            out.append(("Injection SQL", "Critique", line, "Utiliser des requêtes préparées, valider les entrées, implémenter WAF"))
        elif (
            "XSS" in line
            and "paramspider / xss" in outils_lower
            and not re.search(r"xss.*non.*ex[eé]cut[eé]", line, re.IGNORECASE)
            and "aucun" not in line.lower()
        ):
            out.append(("XSS", "Moyenne", line, "Filtrer et échapper les entrées utilisateur"))
        elif "[LOGIN PAGE]" in line:
            out.append(("Page de Login détectée", "Info", line, "Ajouter des protections"))
        elif "wildcard" in line:
            out.append(("Crossdomain non restreint", "Moyenne", line, "Restreindre domaines XML"))
        elif "anti-clickjacking" in line:
            out.append(("Manque de X-Frame-Options", "Faible", line, "Ajouter header X-Frame-Options"))
        elif "XSS protection" in line:
            out.append(("Manque de X-XSS-Protection", "Faible", line, "Ajouter header X-XSS-Protection"))
        elif "MIME-sniffing" in line:
            out.append(("Manque de X-Content-Type-Options", "Faible", line, "Ajouter header X-Content-Type-Options"))

    seen = set()
    res = []
    for v in out:
        if v not in seen:
            seen.add(v)
            res.append(v)
    return res

def renumeroter_sections(soup):
    for i, div in enumerate(soup.find_all("div", class_="section"), start=1):
        h2 = div.find("h2")
        if h2 and re.match(r"\d+\.", h2.text.strip()):
            h2.string = re.sub(r"^\d+\.", f"{i}.", h2.text)

def ajouter_donnees_au_html(html_src, txt_path, html_out):
    texte = lire_rapport_txt(txt_path)
    domaine = extraire_domaine_depuis_rapport(texte)
    soup = BeautifulSoup(open(html_src, encoding='utf-8'), 'html.parser')

    outils = detecter_outils_executes(texte)
    vulns = detecter_vulnerabilites(texte, outils)
    today = datetime.datetime.now().strftime("%d/%m/%Y")

    sec1 = soup.find('h2', string=re.compile(r"1\. Introduction"))
    if sec1:
        p = sec1.find_next('p')
        if p:
            p.string = f"Ce rapport présente les résultats du test d'intrusion effectué sur l'infrastructure du site {domaine} le {today}."

    sec3 = soup.find('h2', string=re.compile(r"3\. Résumé Exécutif"))
    if sec3:
        p = sec3.find_next('p')
        if outils:
            p.string = f"Le test a permis d'identifier plusieurs vulnérabilités à l'aide des outils suivants : {', '.join(outils)}."
        else:
            p.string = "Aucun outil détecté comme exécuté dans le rapport."

    sec4 = soup.find('h2', string=re.compile(r"4\. Vulnérabilités Identifiées"))
    if sec4:
        tbl = sec4.find_next('table')
        if tbl:
            for tr in tbl.find_all('tr')[1:]:
                tr.decompose()
            for nom, grav, desc, reco in vulns:
                tr = soup.new_tag('tr')
                for v in (nom, grav, desc, reco):
                    td = soup.new_tag('td')
                    td.string = v
                    tr.append(td)
                tbl.append(tr)

            # Ajout spécifique SQLMC
            if detecter_sqlmc_urls_vulnerables(texte):
                tr = soup.new_tag('tr')
                colonnes = (
                    "Injection SQL (SQLMC)", "Critique",
                    "Des URLs vulnérables ont été détectées par SQLMC dans le scan.",
                    "Valider et filtrer toutes les entrées utilisateur, utiliser des ORM ou requêtes préparées."
                )
                for val in colonnes:
                    td = soup.new_tag('td')
                    td.string = val
                    tr.append(td)
                tbl.append(tr)

    # Optionnel : si tu veux quand même conserver les résumés par outil
    # Supprimé ici pour simplifier

    final = soup.new_tag('div', **{'class': 'section'})
    hfin = soup.new_tag('h2')
    hfin.string = "Détails Techniques"
    final.append(hfin)
    pfin = soup.new_tag('p')
    pfin.append(BeautifulSoup(texte.replace('\n', '<br>'), 'html.parser'))
    final.append(pfin)
    soup.body.append(final)

    renumeroter_sections(soup)

    with open(html_out, 'w', encoding='utf-8') as f:
        f.write(soup.prettify())
    print(f"✅ Rapport généré : {html_out}")

if __name__ == "__main__":
    src = "rapport.html"
    out = "rapport_complet.html"
    files = glob.glob("reports/security_report_*.txt")
    if files:
        files.sort(key=os.path.getmtime, reverse=True)
        ajouter_donnees_au_html(src, files[0], out)
    else:
        print("❌ Aucun rapport trouvé dans 'reports/'")
