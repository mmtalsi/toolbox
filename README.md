# 🛡️ Web Server Audit Toolbox

**Outil d’audit automatisé de serveurs web basé sur le Top 10 OWASP**  
Scans, détection de vulnérabilités, exploits CVE, génération de rapports, et démonstrations Docker.

📁 Structure du projet

![image](https://github.com/user-attachments/assets/a719faaf-6f97-4e7d-95e0-a3036a280ccf)


🚀 Fonctionnalités  
Module	Description  
🔍 Scan de vulnérabilités	Nikto, reconnaissance domaine, ports ouverts, headers HTTP  
🔐 Page d’authentification	Détection de pages login, test de redirection (DIRB)  
💉 Scan XSS	ParamSpider + script maison pour XSS + redirections  
🧠 Scan SQLi	SQLMap automatisé avec détection préalable  
🧱 CVE-2021-41773	Détection et exploitation dans Apache  
🧱 CVE-2024-38473	Détection et déploiement via Docker  
📦 Démo Docker	Lancement de conteneurs vulnérables pour démonstration  
🔐 JWT Broken Authentication	Analyse d’implémentation et sécurité  
🔑 Analyse de mot de passe	Vérification de robustesse et recommandations  
📄 Génération de rapport	Rapport complet et consolidé en .txt  
🧹 Nettoyage des résultats	Suppression automatique des anciens résultats  

🖼️ Aperçu
Menu interactif principal

[1] - Scan de vulnérabilité  
[2] - Page d'authentification et redirection  
[3] - Scan et Injection XSS  
[4] - Scan et Injection SQL  
[5] - Détection de CVE_2024_38473  
[6] - Détection de CVE_2021_41773  
[7] - Déployer les machines de démo  
[8] - Infos CVE  
[9] - Destruction  
[10] - Force du Password  
[11] - Lancer l'exploit CVE-2021-41773  
[12] - Broken Authentification  
[Q] - Quitter et générer rapport  

📦 Installation  
 
git clone https://github.com/votre-utilisateur/toolbox.git  
cd toolbox  
./install_kali_tools.sh  
Assurez-vous que Docker est installé si vous souhaitez utiliser les démos.

🛠️ Utilisation

python Toolbox.py  
Entrez une URL sous la forme : http://site.com/ (le slash final est obligatoire).  

📊 Interprétation des Résultats
La Toolbox génère une série de fichiers lors des analyses, stockés dans une structure claire pour faciliter l’analyse post-exécution :

📁 results/ – Fichiers bruts par module
Contient les sorties textuelles générées par chaque outil :

     nikto_<domaine>.txt : Scan des vulnérabilités HTTP (scripts, en-têtes, versions obsolètes).

     ports_<domaine>.txt : Résultat du scan de ports et services via Nmap.

     dirb_found_<domaine>.txt : Pages découvertes via brute force, y compris les interfaces de connexion.

     result_recon_<domaine>.txt : Résumé des résultats de la phase de reconnaissance.

     rapport_sqlmc_<domaine>.txt : Liste des URLs vulnérables/non vulnérables à l’injection SQL.

     xss_result.txt : Résultats des tests XSS et redirections malveillantes.

📁 reports/ – Rapports consolidés
    rapport_SQL.txt : Fusion des résultats SQLMC et SQLMap (bases, tables, dumps).

    rapport_<timestamp>.txt : Rapport horodaté généré à la fin de l'exécution.

    rapport_complet.html : Rapport HTML final structuré avec :

        Introduction et périmètre

        Outils utilisés

        Vulnérabilités détectées (par catégorie)

        Gravité des failles (CVSS) et impact

        Recommandations techniques pour la remédiation

        Détails techniques bruts pour audit approfondi

 



⚠️ Disclaimer – Usage Responsable  
Ce projet est destiné à des fins éducatives et de tests en environnement contrôlé uniquement.  

⚠️ N’utilisez jamais cet outil sans autorisation explicite sur des systèmes ou réseaux qui ne vous appartiennent pas. 
Toute utilisation non autorisée peut être considérée comme illégale et engager votre responsabilité pénale.  

L’équipe de développement ne pourra en aucun cas être tenue responsable de l’utilisation abusive ou malveillante de ce programme.  
Veuillez toujours respecter les bonnes pratiques en cybersécurité et les lois en vigueur dans votre pays.  

🙋‍♂️ Auteurs  
Mehdi MTALSI – Développeur  
Emile RODIN – Développeur  
Manel Negrouche – Développeur  
