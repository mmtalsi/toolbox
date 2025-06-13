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
    if sv("SCAN NIKTO", "Aucun résultat"):     outils.append("Nikto")
    if sv("DETECTE LOGIN PAGE", "Aucun résultat"): outils.append("DIRB")
    if sv("REDIRECTIONS DÉTECTÉES", "Aucune redirection"): outils.append("DIRB")
    if "SCAN Reconnaissance Domaine" in texte:
        for o in ("Subfinder","WebTech","WHOIS"):
            if o in texte: outils.append(o)
    if sv("SCAN XSS", "Aucun résultat"):       outils.append("ParamSpider / XSS")
    if sv("SCAN INJECTION SQL", "Aucun résultat"): outils.append("SQLMap")
    if sv("INFORMATIONS SERVEUR ET EN-TÊTES", "Aucune information"): outils.append("Header Check")
    if sv("PORTS OUVERTS ET SERVICES", "Aucun résultat"): outils.append("Nmap")
    return outils

def detecter_vulnerabilites(texte):
    out = []
    for l in texte.splitlines():
        line = l.strip()
        if not line or "===" in line or "Aucun résultat" in line or "Erreur" in line:
            continue
        if "Injection SQL" in line:
            out.append(("Injection SQL","Critique", line, "Utiliser des requêtes préparées"))
        elif "XSS" in line and "aucun" not in line.lower():
            out.append(("XSS","Moyenne", line, "Filtrer et échapper les entrées utilisateur"))
        elif "[LOGIN PAGE]" in line:
            out.append(("Page de Login détectée","Info", line, "Ajouter des protections"))
        elif "wildcard" in line:
            out.append(("Crossdomain non restreint","Moyenne", line, "Restreindre domaines XML"))
        elif "anti-clickjacking" in line:
            out.append(("Manque de X-Frame-Options","Faible", line, "Ajouter header X-Frame-Options"))
        elif "XSS protection" in line:
            out.append(("Manque de X-XSS-Protection","Faible", line, "Ajouter header X-XSS-Protection"))
        elif "MIME-sniffing" in line:
            out.append(("Manque de X-Content-Type-Options","Faible", line, "Ajouter header X-Content-Type-Options"))
    # déduplication
    seen=set(); res=[]
    for v in out:
        if v not in seen:
            seen.add(v); res.append(v)
    return res

def generer_resume_par_outil(texte, domaine):
    lignes = texte.splitlines()
    resume = {}
    current = None
    buffer = []
    nikto_idx = []
    subd, webt, who = [], [], []
    in_sub = in_web = in_who = False

    for idx, l in enumerate(lignes):
        line = l.strip()
        if line.startswith('====================') and line.endswith('===================='):
            # sauvegarde précédente
            if current:
                # Pour les sections SERVER et PORTS : on enlève juste les lignes "Fichier:" et "Vérifiez..."
                if ("INFORMATIONS SERVEUR" in current or "PORTS OUVERTS" in current):
                    filt = [
                        ln for ln in buffer
                        if not (ln.startswith("Fichier:") or ln.startswith("Vérifiez les ports"))
                    ]
                    resume[current] = "\n".join(filt)
                # Nikto (comme avant)
                elif "nikto" in current.lower() and len(nikto_idx)>=2:
                    s,e = nikto_idx[0]+1, nikto_idx[-1]
                    resume["Nikto"] = "\n".join(lignes[s:e])
                # Reconnaissance
                elif "reconnaissance" in current.lower():
                    bloc=[]
                    if subd:
                        bloc.append("🛰️ Subfinder :")
                        bloc += [f"- {d}" for d in subd]
                    if webt:
                        bloc.append("\n🧠 WebTech :")
                        bloc += [f"- {t}" for t in webt]
                    if who:
                        bloc.append("\n📄 WHOIS :")
                        bloc += [f"- {w}" for w in who]
                    else:
                        bloc.append("\n📄 WHOIS :")
                        bloc.append("- Aucune information fournie par WHOIS")
                    resume["Reconnaissance Domaine"] = "\n".join(bloc)
                # Autres sections
                elif buffer:
                    resume[current] = "\n".join(buffer)

            # réinitialisation
            current = line
            buffer = []
            nikto_idx = []
            subd,webt,who = [],[],[]
            in_sub=in_web=in_who=False
            continue

        # traitement des lignes
        if current and "nikto" in current.lower():
            if "----" in line:
                nikto_idx.append(idx)
            buffer.append(line)

        elif current and "reconnaissance" in current.lower():
            if "Subfinder" in line:
                in_sub,in_web,in_who = True,False,False; continue
            if "WebTech" in line:
                in_sub,in_web,in_who = False,True,False; continue
            if "WHOIS" in line:
                in_sub,in_web,in_who = False,False,True; continue

            if in_sub and re.match(r'^[\w\.-]+\.[\w\.-]+$', line) and line.endswith("."+domaine):
                subd.append(line)
            elif in_web and line.startswith("-"):
                webt.append(line.lstrip("- ").strip())
            elif in_who:
                raw = line.lstrip("- ").strip()
                if ":" in raw and not raw.lower().startswith((">>>","to:")):
                    k,v = [p.strip() for p in raw.split(":",1)]
                    if not k.lower().startswith(("notice","terms","by")) and "REDACTED" not in v:
                        who.append(f"{k}: {v}")

        elif current:
            buffer.append(line)

    # dernière section
    if current:
        if ("INFORMATIONS SERVEUR" in current or "PORTS OUVERTS" in current):
            filt = [
                ln for ln in buffer
                if not (ln.startswith("Fichier:") or ln.startswith("Vérifiez les ports"))
            ]
            resume[current] = "\n".join(filt)
        elif "nikto" in current.lower() and len(nikto_idx)>=2:
            s,e = nikto_idx[0]+1,nikto_idx[-1]
            resume["Nikto"] = "\n".join(lignes[s:e])
        elif "reconnaissance" in current.lower():
            bloc=[]
            if subd:
                bloc.append("🛰️ Subfinder :")
                bloc += [f"- {d}" for d in subd]
            if webt:
                bloc.append("\n🧠 WebTech :")
                bloc += [f"- {t}" for t in webt]
            if who:
                bloc.append("\n📄 WHOIS :")
                bloc += [f"- {w}" for w in who]
            else:
                bloc.append("\n📄 WHOIS :")
                bloc.append("- Aucune information fournie par WHOIS")
            resume["Reconnaissance Domaine"] = "\n".join(bloc)
        elif buffer:
            resume[current] = "\n".join(buffer)

    return resume

def renumeroter_sections(soup):
    for i, div in enumerate(soup.find_all("div", class_="section"), start=1):
        h2 = div.find("h2")
        if h2 and re.match(r"\d+\.", h2.text.strip()):
            h2.string = re.sub(r"^\d+\.", f"{i}.", h2.text)

def ajouter_donnees_au_html(html_src, txt_path, html_out):
    texte  = lire_rapport_txt(txt_path)
    domaine= extraire_domaine_depuis_rapport(texte)
    soup   = BeautifulSoup(open(html_src, encoding='utf-8'), 'html.parser')

    outils  = detecter_outils_executes(texte)
    vulns   = detecter_vulnerabilites(texte)
    resumes = generer_resume_par_outil(texte, domaine)
    today   = datetime.datetime.now().strftime("%d/%m/%Y")

    # Section 1 — Introduction
    sec1 = soup.find('h2', string=re.compile(r"1\. Introduction"))
    if sec1:
        p = sec1.find_next('p')
        if p:
            p.string = f"Ce rapport présente les résultats du test d'intrusion effectué sur l'infrastructure du site {domaine} le {today}."

    # Section 3 — Résumé Exécutif
    sec3 = soup.find('h2', string=re.compile(r"3\. Résumé Exécutif"))
    if sec3:
        p = sec3.find_next('p')
        if outils:
            p.string = f"Le test a permis d'identifier plusieurs vulnérabilités à l'aide des outils suivants : {', '.join(outils)}."
        else:
            p.string = "Aucun outil détecté comme exécuté dans le rapport."

    # Section 4 — Vulnérabilités
    sec4 = soup.find('h2', string=re.compile(r"4\. Vulnérabilités Identifiées"))
    if sec4:
        tbl = sec4.find_next('table')
        if tbl:
            for tr in tbl.find_all('tr')[1:]:
                tr.decompose()
            for nom, grav, desc, reco in vulns:
                tr = soup.new_tag('tr')
                for v in (nom, grav, desc, reco):
                    td = soup.new_tag('td'); td.string = v; tr.append(td)
                tbl.append(tr)

    # Section 5 — Résultats détaillés par outil
    sec5 = soup.new_tag('div', **{'class':'section'})
    h5   = soup.new_tag('h2'); h5.string="5. Résultats détaillés par outil"; sec5.append(h5)
    for o,cont in resumes.items():
        h3  = soup.new_tag('h3'); h3.string=f"🔎 {o}"; sec5.append(h3)
        pre = soup.new_tag('pre'); pre.string = cont; sec5.append(pre)
    anchor = soup.find('h2', string=re.compile(r"5\. Recommandations Générales"))
    if anchor:
        anchor.find_parent('div').insert_before(sec5)
    else:
        soup.body.append(sec5)

    # Section finale — Détails Techniques
    final = soup.new_tag('div', **{'class':'section'})
    hfin   = soup.new_tag('h2'); hfin.string="Détails Techniques"; final.append(hfin)
    pfin   = soup.new_tag('p')
    pfin.append(BeautifulSoup(texte.replace('\n','<br>'), 'html.parser'))
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
