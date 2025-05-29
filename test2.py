#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import glob
import re
from pathlib import Path
from bs4 import BeautifulSoup

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

if __name__ == '__main__':
    inject()
