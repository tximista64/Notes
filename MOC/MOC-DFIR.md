---
tags: [MOC, DFIR, Incident-Response]
---

# MOC — DFIR (Digital Forensics & Incident Response)

## Cours & Théorie

### HTB Academy — CDSA : Incident Handling Process
- [[Cours/HTB academy/CDSA/1.Incident Handling Process/1.Incident Handling Definition & Scope|Définition & Scope]] — Définition de l'incident handling et périmètre d'application
- [[Cours/HTB academy/CDSA/1.Incident Handling Process/2.Cyber Kill Chain|Cyber Kill Chain]] — Les 7 phases de la Kill Chain appliquées à l'IH
- [[Cours/HTB academy/CDSA/1.Incident Handling Process/3.Incident Handling Process Overview|Vue d'ensemble du processus]] — Présentation complète du cycle de gestion d'incident
- [[Cours/HTB academy/CDSA/1.Incident Handling Process/4.Preparation 1|Préparation (1)]] — Préparer l'équipe, les outils et les procédures
- [[Cours/HTB academy/CDSA/1.Incident Handling Process/5.Preparation 2|Préparation (2)]] — Playbooks, CSIRT et communication de crise
- [[Cours/HTB academy/CDSA/1.Incident Handling Process/6.Detection & Analysis Stage (Part 1)|Détection & Analyse (1)]] — Sources de détection, triaging initial, IoC
- [[Cours/HTB academy/CDSA/1.Incident Handling Process/7.Detection & Analysis Stage (Part 2)|Détection & Analyse (2)]] — Analyse approfondie, timeline, corrélation d'événements
- [[Cours/HTB academy/CDSA/1.Incident Handling Process/8.Containment, Eradication, & Recovery Stage|Containment, Eradication & Recovery]] — Isolation, nettoyage et retour à la normale
- [[Cours/HTB academy/CDSA/1.Incident Handling Process/9.Post-Incident Activity Stage|Post-Incident Activity]] — Rapport post-incident, leçons apprises, amélioration

### Let's Defend — Incident Management
- [[Cours/Let's Defend/SOC Analyst Path/Incident Management 101/Introduction to Incident Management|Introduction à l'Incident Management]] — Bases de la gestion d'incidents de sécurité
- [[Cours/Let's Defend/SOC Analyst Path/Incident Management 101/Basic Definitions About Incident Management|Définitions de base]] — Terminologie : incident, événement, alerte, ticket
- [[Cours/Let's Defend/SOC Analyst Path/Incident Management 101/Incident Management Systems (IMS)|Systèmes IMS]] — Outils de gestion d'incidents (ServiceNow, TheHive, Jira)
- [[Cours/Let's Defend/SOC Analyst Path/Incident Management 101/Case Alert Naming|Nommage des alertes]] — Conventions de nommage et classification des alertes
- [[Cours/Let's Defend/SOC Analyst Path/Incident Management 101/Playbooks|Playbooks]] — Construction et utilisation de playbooks de réponse

### Let's Defend — Investigating SIEM Alerts
- [[Cours/Let's Defend/SOC Analyst Path/How to Investigate a SIEM Alert/Introduction to SIEM Alerts|Introduction aux alertes SIEM]] — Types d'alertes et workflows d'investigation
- [[Cours/Let's Defend/SOC Analyst Path/How to Investigate a SIEM Alert/Detection|Détection]] — Phase de détection et analyse initiale d'une alerte
- [[Cours/Let's Defend/SOC Analyst Path/How to Investigate a SIEM Alert/Email Analysis|Analyse Email]] — Investigation d'une alerte liée à un email suspect
- [[Cours/Let's Defend/SOC Analyst Path/How to Investigate a SIEM Alert/Endpoint Analysis|Analyse Endpoint]] — Investigation sur l'endpoint (EDR, logs système)
- [[Cours/Let's Defend/SOC Analyst Path/How to Investigate a SIEM Alert/Network and Log Analysis|Analyse Réseau & Logs]] — Corrélation des logs réseau lors d'une investigation
- [[Cours/Let's Defend/SOC Analyst Path/How to Investigate a SIEM Alert/Case Creation and Playbook Initiation 150eb38a212b8077a0bbda0e72c6b427|Création de Case & Playbook]] — Initiation d'un ticket d'incident et démarrage du playbook
- [[Cours/Let's Defend/SOC Analyst Path/How to Investigate a SIEM Alert/Result|Résultat de l'investigation]] — Documentation du verdict et clôture du cas

### Let's Defend — Phishing Analysis
- [[Cours/Let's Defend/SOC Analyst Path/Phishing Email Analysis/Introduction to Phishing|Introduction au Phishing]] — Comprendre les attaques de phishing et leur anatomie
- [[Cours/Let's Defend/SOC Analyst Path/Phishing Email Analysis/What is an Email Header and How to Read Them|Lecture des En-têtes Email]] — Analyser les headers SPF/DKIM/DMARC et le routing
- [[Cours/Let's Defend/SOC Analyst Path/Phishing Email Analysis/Email Header Analysis|Analyse des Headers]] — Investigation approfondie des headers malveillants
- [[Cours/Let's Defend/SOC Analyst Path/Phishing Email Analysis/Information Gathering|Information Gathering]] — Collecte d'IoC depuis un email de phishing
- [[Cours/Let's Defend/SOC Analyst Path/Phishing Email Analysis/Static Analysis|Analyse Statique]] — Analyse statique des pièces jointes malveillantes
- [[Cours/Let's Defend/SOC Analyst Path/Phishing Email Analysis/Dynamic Analysis|Analyse Dynamique]] — Analyse dynamique d'un email de phishing en sandbox
- [[Cours/Let's Defend/SOC Analyst Path/Phishing Email Analysis/Additional Techniques|Techniques additionnelles]] — Techniques avancées d'analyse de phishing
- [[Cours/Let's Defend/SOC Analyst Path/Phishing Email Analysis/93 - SOC146 - Phishing Mail Detected - Excel 4 0 M|SOC146 - Phishing Excel]] — Cas réel : phishing avec macro Excel 4.0
- [[Cours/Let's Defend/SOC Analyst Path/Malicious Document Analysis|Analyse de Document Malveillant]] — Analyse de documents Office/PDF malveillants

### Let's Defend — Cyber Kill Chain
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Cyber kill chain steps|Étapes de la Kill Chain]] — Vue d'ensemble des 7 étapes de la Cyber Kill Chain
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Reconnaissance|Reconnaissance]] — Collecte passive/active d'information sur la cible
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Weaponization|Weaponization]] — Création de l'arme (malware, exploit)
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Delivery|Delivery]] — Livraison de la charge utile (phishing, watering hole)
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Exploitation|Exploitation]] — Exploitation de la vulnérabilité côté victime
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Installation|Installation]] — Installation de la backdoor / persistance
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Command and Control (C2)|Command & Control (C2)]] — Établissement du canal de commande
- [[Cours/Let's Defend/SOC Analyst Path/Cyber Kill Chain/Actions on Objectives|Actions on Objectives]] — Exfiltration, ransomware, sabotage

---

## CTF & Writeups

### HTB — Sherlocks (DFIR)
- [[CTF/HTB/Sherlocks/Brutus|Brutus]] — Analyse d'auth.log : brute force SSH, pivoting, persistance
- [[CTF/HTB/Sherlocks/Heartbreaker-Continuum|Heartbreaker-Continuum]] — Investigation d'un incident complexe multi-étapes
- [[CTF/HTB/Sherlocks/MangoBleed|MangoBleed]] — Analyse forensique d'une attaque impliquant un système Mango
- [[CTF/HTB/Sherlocks/PhishNET|PhishNET]] — Investigation d'une campagne de phishing réseau
- [[CTF/HTB/Sherlocks/RomCom|RomCom]] — Analyse d'un incident lié au RAT RomCom
- [[CTF/HTB/Sherlocks/SalineBreeze-1|SalineBreeze]] — Investigation forensique : étape 1
- [[CTF/HTB/Sherlocks/Telly|Telly]] — Analyse d'un incident sur infrastructure TV/media
- [[CTF/HTB/Sherlocks/Vantage|Vantage]] — Investigation d'une compromission avec analyse de logs

### HTB — Event CTF (Forensic Investigation)
- [[CTF/HTB/Event/HolmesCTF09-2025/The_enduring-echo|The Enduring Echo]] — Investigation forensique : traces persistantes sur le système
- [[CTF/HTB/Event/HolmesCTF09-2025/THe_tunnel_without_walls|The Tunnel Without Walls]] — Analyse d'un tunnel C2 dissimulé
- [[CTF/HTB/Event/HolmesCTF09-2025/The_Watchmans_Residue|The Watchman's Residue]] — Analyse d'artefacts résiduels post-compromission

### Let's Defend — SOC Cases
- [[CTF/Let's defend/Soc 141|SOC 141]] — Investigation d'alerte SOC : cas 141
- [[CTF/Let's defend/Soc 146|SOC 146]] — Investigation d'alerte SOC : cas 146
- [[CTF/Let's defend/Soc 165|SOC 165]] — Investigation d'alerte SOC : cas 165
- [[CTF/Let's defend/SOC 166|SOC 166]] — Investigation d'alerte SOC : cas 166
- [[CTF/Let's defend/Soc 167|SOC 167]] — Investigation d'alerte SOC : cas 167
- [[CTF/Let's defend/SOC 168|SOC 168]] — Investigation d'alerte SOC : cas 168
- [[CTF/Let's defend/SOC 169|SOC 169]] — Investigation d'alerte SOC : cas 169
- [[CTF/Let's defend/SOC 170|SOC 170]] — Investigation d'alerte SOC : cas 170
