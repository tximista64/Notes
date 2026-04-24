---
tags: [MOC, SIEM, Splunk, ELK]
---

# MOC — SIEM & Analyse de Logs

## Cours & Théorie

### HTB Academy — CDSA : SIEM Fundamentals
- [[Cours/HTB academy/CDSA/2.Security Monitoring & SIEM Fundamentals/1.SIEM Definition & Fundamentals|SIEM — Définition & Fondamentaux]] — Architecture SIEM, collecte, normalisation, corrélation

### HTB Academy — CDSA : Splunk
- [[Cours/HTB academy/CDSA/5.Understanding Log Sources & Investigating with Splunk/1.Introduction To Splunk & SPL|Introduction Splunk & SPL]] — Prise en main de Splunk et du langage SPL
- [[Cours/HTB academy/CDSA/5.Understanding Log Sources & Investigating with Splunk/2.Using Splunk Applications|Applications Splunk]] — Splunk apps, Enterprise Security, Threat Intelligence
- [[Cours/HTB academy/CDSA/5.Understanding Log Sources & Investigating with Splunk/3.Intrusion Detection With Splunk (Real-world Scenario|Détection d'Intrusion avec Splunk]] — Scénario réel d'investigation Splunk

### Let's Defend — SIEM 101
- [[Cours/Let's Defend/SOC Analyst Path/SIEM 101/SIEM Introduction|Introduction SIEM]] — Qu'est-ce qu'un SIEM, pourquoi l'utiliser, acteurs du marché
- [[Cours/Let's Defend/SOC Analyst Path/SIEM 101/Log Collection|Collecte de Logs]] — Sources de logs, agents, syslog, API
- [[Cours/Let's Defend/SOC Analyst Path/SIEM 101/Log Aggregation and Parsing|Agrégation & Parsing]] — Normalisation, parsing, enrichissement des logs
- [[Cours/Let's Defend/SOC Analyst Path/SIEM 101/Log Storage|Stockage des Logs]] — Architecture de stockage, indexation, rétention
- [[Cours/Let's Defend/SOC Analyst Path/SIEM 101/Alerting|Alerting]] — Création de règles de corrélation et d'alertes

### Let's Defend — Splunk
- [[Cours/Let's Defend/SOC Analyst Path/Splunk/Introduction to Splunk|Introduction Splunk]] — Vue d'ensemble de Splunk pour les analystes SOC
- [[Cours/Let's Defend/SOC Analyst Path/Splunk/Splunk Installation on Linux|Installation Linux]] — Installation et configuration de Splunk sur Linux
- [[Cours/Let's Defend/SOC Analyst Path/Splunk/Splunk Installation on Windows|Installation Windows]] — Installation et configuration de Splunk sur Windows
- [[Cours/Let's Defend/SOC Analyst Path/Splunk/Add Data to Splunk|Ajout de Données]] — Ingestion de logs dans Splunk (inputs, forwarders, HEC)
- [[Cours/Let's Defend/SOC Analyst Path/Splunk/Search on Splunk|Recherche SPL]] — Requêtes SPL : search, stats, eval, rex, table
- [[Cours/Let's Defend/SOC Analyst Path/Splunk/Dashboards|Dashboards]] — Création de tableaux de bord Splunk pour le monitoring SOC
- [[Cours/Let's Defend/SOC Analyst Path/Splunk/Alerts on Splunk|Alertes]] — Configuration d'alertes et de triggers dans Splunk
- [[Cours/Let's Defend/SOC Analyst Path/Splunk/Splunk Reports|Rapports]] — Génération de rapports périodiques
- [[Cours/Let's Defend/SOC Analyst Path/Splunk/Splunk Universal Forwarders|Universal Forwarders]] — Déploiement des Universal Forwarders pour la collecte
- [[Cours/Let's Defend/SOC Analyst Path/Splunk/Splunk Health Status Check|Health Check]] — Supervision de la santé d'une instance Splunk
- [[Cours/Let's Defend/SOC Analyst Path/Splunk/User Management on Splunk|Gestion des Utilisateurs]] — Rôles, permissions et gestion des accès Splunk

### Let's Defend — How to Investigate a SIEM Alert
- [[Cours/Let's Defend/SOC Analyst Path/How to Investigate a SIEM Alert/Introduction to SIEM Alerts|Introduction aux Alertes SIEM]] — Types d'alertes et workflow d'investigation
- [[Cours/Let's Defend/SOC Analyst Path/How to Investigate a SIEM Alert/Detection|Détection]] — Phase de détection et triage
- [[Cours/Let's Defend/SOC Analyst Path/How to Investigate a SIEM Alert/Network and Log Analysis|Analyse Réseau & Logs]] — Corrélation réseau dans le SIEM
- [[Cours/Let's Defend/SOC Analyst Path/How to Investigate a SIEM Alert/Endpoint Analysis|Analyse Endpoint]] — Investigation endpoint depuis le SIEM
- [[Cours/Let's Defend/SOC Analyst Path/How to Investigate a SIEM Alert/Email Analysis|Analyse Email]] — Investigation email dans le SIEM
- [[Cours/Let's Defend/SOC Analyst Path/How to Investigate a SIEM Alert/Case Creation and Playbook Initiation 150eb38a212b8077a0bbda0e72c6b427|Création de Case]] — Création d'un ticket et démarrage du playbook
- [[Cours/Let's Defend/SOC Analyst Path/How to Investigate a SIEM Alert/Result|Résultat]] — Documentation et clôture de l'alerte

### Let's Defend — SOC Fundamentals
- [[Cours/Let's Defend/SOC Analyst Path/SOC Fundamentals/Soc types|Types de SOC]] — SOC interne, MSSP, hybride, virtual SOC
- [[Cours/Let's Defend/SOC Analyst Path/SOC Fundamentals/Common Mistakes made by SOC Analysts|Erreurs Courantes des Analystes SOC]] — Pièges à éviter : faux positifs, alert fatigue
- [[Cours/Let's Defend/SOC Analyst Path/SOC Fundamentals/EDR - Endpoint Detection and Response|EDR]] — Rôle des EDR dans le SOC : CrowdStrike, Sentinel One, Defender
- [[Cours/Let's Defend/SOC Analyst Path/SOC Fundamentals/SOAR (Security Orchestration Automation and Respon|SOAR]] — Automatisation et orchestration (Palo Alto XSOAR, Splunk SOAR)
- [[Cours/Let's Defend/SOC Analyst Path/SOC Fundamentals/Threat Intel|Threat Intel dans le SOC]] — Intégration du renseignement sur les menaces

### Let's Defend — Solutions de Sécurité
- [[Cours/Let's Defend/SOC Analyst Path/Security Solutions/Introduction to Security Solutions|Introduction]] — Vue d'ensemble des solutions de sécurité d'une organisation
- [[Cours/Let's Defend/SOC Analyst Path/Security Solutions/Firewall|Firewall]] — Types de firewalls et leur positionnement
- [[Cours/Let's Defend/SOC Analyst Path/Security Solutions/Intrusion Detection System (IDS)|IDS]] — Systèmes de détection d'intrusion (Snort, Suricata)
- [[Cours/Let's Defend/SOC Analyst Path/Security Solutions/Intrusion Prevention System (IPS)|IPS]] — Systèmes de prévention d'intrusion
- [[Cours/Let's Defend/SOC Analyst Path/Security Solutions/Web Application Firewall (WAF)|WAF]] — Pare-feu applicatif web
- [[Cours/Let's Defend/SOC Analyst Path/Security Solutions/Endpoint Detection and Response (EDR)|EDR]] — Solutions EDR : capacités et déploiement
- [[Cours/Let's Defend/SOC Analyst Path/Security Solutions/Antivirus Software (AV)|Antivirus]] — Fonctionnement des AV : signatures, heuristiques, sandboxing
- [[Cours/Let's Defend/SOC Analyst Path/Security Solutions/Proxy Server|Proxy]] — Proxy web : inspection du trafic, filtrage URL
- [[Cours/Let's Defend/SOC Analyst Path/Security Solutions/Sandbox Solutions|Sandbox]] — Sandboxing : Cuckoo, Any.run, Joe Sandbox
- [[Cours/Let's Defend/SOC Analyst Path/Security Solutions/Email Security Solutions|Sécurité Email]] — Anti-spam, anti-phishing, SPF/DKIM/DMARC
- [[Cours/Let's Defend/SOC Analyst Path/Security Solutions/Data Loss Prevention (DLP)|DLP]] — Prévention de la fuite de données
- [[Cours/Let's Defend/SOC Analyst Path/Security Solutions/Load Balancer|Load Balancer]] — Load balancers et leur positionnement sécurité
- [[Cours/Let's Defend/SOC Analyst Path/Security Solutions/Asset Management Solutions|Asset Management]] — Inventaire des actifs et gestion de la surface d'attaque
- [[Cours/Let's Defend/SOC Analyst Path/CrowdSec|CrowdSec]] — Solution open-source de détection collaborative (CrowdSec)

### Let's Defend — IT Security Basis for Corporates
- [[Cours/Let's Defend/SOC Analyst Path/IT Security Basis for Corporates/Introduction to IT Security Basis for Corporates 17aeb38a212b80399240d22671fd57b3|Introduction]] — Bases de la sécurité IT en entreprise
- [[Cours/Let's Defend/SOC Analyst Path/IT Security Basis for Corporates/Access Control|Contrôle d'Accès]] — Politique des moindres privilèges, MFA, PAM
- [[Cours/Let's Defend/SOC Analyst Path/IT Security Basis for Corporates/Patching|Patching]] — Gestion des correctifs et CVE
- [[Cours/Let's Defend/SOC Analyst Path/IT Security Basis for Corporates/Backups|Sauvegardes]] — Stratégie de backup : 3-2-1
- [[Cours/Let's Defend/SOC Analyst Path/IT Security Basis for Corporates/Network|Réseau Entreprise]] — Segmentation, VLAN, Zero Trust
- [[Cours/Let's Defend/SOC Analyst Path/IT Security Basis for Corporates/Risk Analysis|Analyse de Risques]] — Méthodes d'analyse de risques (EBIOS, ISO 27005)
- [[Cours/Let's Defend/SOC Analyst Path/IT Security Basis for Corporates/Phishing Prevention|Prévention Phishing]] — Sensibilisation et mesures anti-phishing
- [[Cours/Let's Defend/SOC Analyst Path/IT Security Basis for Corporates/Internet Browsing Protection|Protection Navigation Web]] — Proxy, DNS filtering, content filtering
- [[Cours/Let's Defend/SOC Analyst Path/IT Security Basis for Corporates/Inventory|Inventaire]] — Gestion de l'inventaire des actifs

### HTB Academy — Elastic / Threat Hunting
- [[Cours/HTB academy/CDSA/4.Introduction to Threat Hunting & Hunting With Elastic/1.Threat Hunting Fundamentals|Fondamentaux Threat Hunting]] — Présentation du threat hunting avec Elastic SIEM

---

## CTF & Writeups

### Let's Defend — SOC Cases
- [[CTF/Let's defend/Soc 141|SOC 141]] — Investigation d'alerte SIEM : cas 141
- [[CTF/Let's defend/Soc 146|SOC 146]] — Investigation d'alerte SIEM : cas 146
- [[CTF/Let's defend/Soc 165|SOC 165]] — Investigation d'alerte SIEM : cas 165
- [[CTF/Let's defend/SOC 166|SOC 166]] — Investigation d'alerte SIEM : cas 166
- [[CTF/Let's defend/Soc 167|SOC 167]] — Investigation d'alerte SIEM : cas 167
- [[CTF/Let's defend/SOC 168|SOC 168]] — Investigation d'alerte SIEM : cas 168
- [[CTF/Let's defend/SOC 169|SOC 169]] — Investigation d'alerte SIEM : cas 169
- [[CTF/Let's defend/SOC 170|SOC 170]] — Investigation d'alerte SIEM : cas 170
