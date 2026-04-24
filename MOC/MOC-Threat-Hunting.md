---
tags: [MOC, Threat-Hunting, CTI]
---

# MOC — Threat Hunting & Cyber Threat Intelligence

## Cours & Théorie

### HTB Academy — CDSA : Threat Hunting with Elastic
- [[Cours/HTB academy/CDSA/4.Introduction to Threat Hunting & Hunting With Elastic/1.Threat Hunting Fundamentals|Fondamentaux du Threat Hunting]] — Définition, objectifs, différences avec la réponse sur incident
- [[Cours/HTB academy/CDSA/4.Introduction to Threat Hunting & Hunting With Elastic/2.The Threat Hunting Process|Processus de Threat Hunting]] — Hypothèses, investigation, documentation
- [[Cours/HTB academy/CDSA/4.Introduction to Threat Hunting & Hunting With Elastic/3.Threat Hunting Glossary|Glossaire Threat Hunting]] — IoC, IoA, TTP, TTPs, pivot, télémétrie
- [[Cours/HTB academy/CDSA/4.Introduction to Threat Hunting & Hunting With Elastic/4.Threat Intelligence Fundamentals|Fondamentaux Threat Intelligence]] — Types de renseignements : stratégique, opérationnel, tactique
- [[Cours/HTB academy/CDSA/4.Introduction to Threat Hunting & Hunting With Elastic/5.Hunting For Stuxbot|Hunting for Stuxbot]] — Cas pratique : chasse à Stuxbot dans Elastic
- [[Cours/HTB academy/CDSA/4.Introduction to Threat Hunting & Hunting With Elastic/6.Skill assessment|Skill Assessment]] — Exercice pratique de threat hunting

### Let's Defend — Cyber Threat Intelligence (CTI)
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Threat Intelligence/Introduction to CTI|Introduction au CTI]] — Renseignement sur les menaces : définition et valeur pour le SOC
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Threat Intelligence/CTI Lifecycle|Cycle de vie du CTI]] — Collection, traitement, analyse, diffusion, feedback
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Threat Intelligence/Types of Cyber Threat Intelligence|Types de CTI]] — Stratégique, opérationnel, tactique, technique
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Threat Intelligence/Gathering Threat Intelligence|Collecte de Threat Intelligence]] — Sources ouvertes (OSINT), feeds, partage communautaire (ISAC)
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Threat Intelligence/Threat Intelligence Data Interpretation|Interprétation des Données CTI]] — Analyse de rapports de menace, attribution, indicateurs
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Threat Intelligence/Determining the Attack Surface|Détermination de la Surface d'Attaque]] — Mapping de l'exposition et des risques
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Threat Intelligence/Using Threat Intelligence|Utilisation du CTI]] — Intégration du CTI dans les outils SOC (SIEM, SOAR, EDR)
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Threat Intelligence/Threat Intelligence and SOC Integration|CTI & Intégration SOC]] — Comment intégrer le CTI dans les workflows SOC

### Let's Defend — MITRE ATT&CK Framework
- [[Cours/Let's Defend/SOC Analyst Path/MITRE ATT&ACK Framework/Introduction|Introduction MITRE ATT&CK]] — Présentation du framework ATT&CK et son usage
- [[Cours/Let's Defend/SOC Analyst Path/MITRE ATT&ACK Framework/Matrix|Matrice ATT&CK]] — Lecture et navigation dans la matrice Enterprise
- [[Cours/Let's Defend/SOC Analyst Path/MITRE ATT&ACK Framework/Tactics|Tactiques]] — Les 14 tactiques ATT&CK (TA0001 à TA0043)
- [[Cours/Let's Defend/SOC Analyst Path/MITRE ATT&ACK Framework/Techniques and Sub-Techniques|Techniques & Sous-techniques]] — Structure des techniques et sous-techniques
- [[Cours/Let's Defend/SOC Analyst Path/MITRE ATT&ACK Framework/Groups|Groupes d'Acteurs]] — APT28, Lazarus, Cobalt Group : profils d'acteurs malveillants
- [[Cours/Let's Defend/SOC Analyst Path/MITRE ATT&ACK Framework/Software|Logiciels Malveillants]] — Outils et malwares référencés dans ATT&CK
- [[Cours/Let's Defend/SOC Analyst Path/MITRE ATT&ACK Framework/Mitigations|Mitigations]] — Contrôles de sécurité associés aux techniques ATT&CK

### Let's Defend — Cyber Kill Chain
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Cyber kill chain steps|Étapes Kill Chain]] — Vue complète des 7 étapes de la Cyber Kill Chain
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Reconnaissance|Reconnaissance]] — Collecte d'informations sur la cible
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Weaponization|Weaponization]] — Préparation de l'arme (exploit + payload)
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Delivery|Delivery]] — Livraison du vecteur d'attaque
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Exploitation|Exploitation]] — Déclenchement de l'exploit
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Installation|Installation]] — Persistance du malware
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Command and Control (C2)|Command & Control]] — Canal C2 et communication avec l'attaquant
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Actions on Objectives|Actions on Objectives]] — Exfiltration, destruction, mouvement latéral

### HTB Academy — CDSA : Incident Handling et Kill Chain
- [[Cours/HTB academy/CDSA/1.Incident Handling Process/2.Cyber Kill Chain|Kill Chain dans l'IH]] — Application de la Kill Chain à la réponse sur incident

### Let's Defend — Détection Brute Force
- [[Cours/Let's Defend/SOC Analyst Path/Detecting Brute Force Attacks/Introduction to Detecting Brute Force Attacks|Introduction]] — Présentation des attaques par force brute
- [[Cours/Let's Defend/SOC Analyst Path/Detecting Brute Force Attacks/Brute Force Attacks|Attaques Brute Force]] — Types d'attaques : dictionary, credential stuffing, spray
- [[Cours/Let's Defend/SOC Analyst Path/Detecting Brute Force Attacks/Protocol Services That Can Be Attacked by Brute Fo|Services Vulnérables]] — SSH, RDP, HTTP, FTP, SMTP
- [[Cours/Let's Defend/SOC Analyst Path/Detecting Brute Force Attacks/Tools Used in a Brute Force Attacks|Outils d'Attaque]] — Hydra, medusa, ncrack, Burp Intruder
- [[Cours/Let's Defend/SOC Analyst Path/Detecting Brute Force Attacks/HTTP Login Brute Force Attack Detection Example|Exemple Détection HTTP]] — Identification d'un brute force HTTP dans les logs
- [[Cours/Let's Defend/SOC Analyst Path/Detecting Brute Force Attacks/SSH Brute Force Attack Detection Example 17beb38a212b8012a8b0f019354b1dd7|Exemple Détection SSH]] — Identification d'un brute force SSH dans auth.log
- [[Cours/Let's Defend/SOC Analyst Path/Detecting Brute Force Attacks/Windows Login Brute Force Detection Example|Exemple Détection Windows]] — Détection brute force Windows via Event ID 4625
- [[Cours/Let's Defend/SOC Analyst Path/Detecting Brute Force Attacks/How to Avoid Brute Force Attacks|Contre-mesures]] — Lockout, MFA, fail2ban, rate limiting

---

## CTF & Writeups

### HTB — Challenges CTI/Threat Hunting
- [[CTF/HTB/Challenges/Suspicious_Threat|Suspicious Threat]] — Identification d'une menace suspecte : TTPs et IoCs
- [[CTF/HTB/Challenges/The Suspicious Domain|The Suspicious Domain]] — Analyse d'un domaine suspect : infrastructure de l'attaquant
