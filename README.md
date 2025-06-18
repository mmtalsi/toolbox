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

mathematica
Copier
Modifier  
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
bash
Copier
Modifier
python Toolbox.py  
Entrez une URL sous la forme : http://site.com/ (le slash final est obligatoire).  

📄 Rapport  
Un rapport texte est généré dans reports/security_report_<date>.txt, regroupant :  

Résultats des outils (Nikto, DirB, SQLmap…)  

Détails des ports et services  

Headers HTTP et vulnérabilités détectées  

État des conteneurs Docker  



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
