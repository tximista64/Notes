---
tags: [MOC, Windows, Blue-Team]
---

# MOC — Windows & Event Logs

## Cours & Théorie

### HTB Academy — CDSA : Windows Event Logs
- [[Cours/HTB academy/CDSA/3.Windows Event Logs & Finding Evil/1.Windows event logs|Windows Event Logs]] — Architecture des logs Windows : canaux, providers, IDs d'événements
- [[Cours/HTB academy/CDSA/3.Windows Event Logs & Finding Evil/2.Analyzing Evil With Sysmon & Event Logs|Sysmon & Event Logs]] — Détection d'activités malveillantes avec Sysmon et les event logs
- [[Cours/HTB academy/CDSA/3.Windows Event Logs & Finding Evil/3.Event Tracing for Windows (ETW)|ETW — Event Tracing]] — Event Tracing for Windows : architecture et providers
- [[Cours/HTB academy/CDSA/3.Windows Event Logs & Finding Evil/4.Tapping Into ETW|Utiliser ETW]] — Collecter et analyser des traces ETW
- [[Cours/HTB academy/CDSA/3.Windows Event Logs & Finding Evil/5.Get-WinEvent|Get-WinEvent PowerShell]] — Requêtes PowerShell sur les logs Windows avec Get-WinEvent
- [[Cours/HTB academy/CDSA/3.Windows Event Logs & Finding Evil/6.Skills Assessment|Skills Assessment]] — Exercice pratique : trouver des activités malveillantes dans les logs

### HTB Academy — Windows Target (Pentest)
- [[Cours/HTB academy/CJCA/11 Pentest in a nutshell/6Windows Target/Windows_Information_Gathering|Collecte d'Informations]] — Énumération initiale d'une cible Windows
- [[Cours/HTB academy/CJCA/11 Pentest in a nutshell/6Windows Target/Windows_System_Enumeration|Énumération Système]] — Services, utilisateurs, partages, registre, applications
- [[Cours/HTB academy/CJCA/11 Pentest in a nutshell/6Windows Target/Windows_Vulnerability_Assessment|Évaluation des Vulnérabilités]] — Identification de CVEs et misconfigurations Windows
- [[Cours/HTB academy/CJCA/11 Pentest in a nutshell/6Windows Target/Windows_Initial_Access|Accès Initial]] — Exploitation d'une vulnérabilité pour obtenir un shell Windows

### Let's Defend — Windows Fundamentals
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Windows Fundamentals/Introduction to Windows|Introduction à Windows]] — Architecture Windows pour les analystes sécurité
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Windows Fundamentals/Directory Structure|Structure des Répertoires]] — C:\Windows, System32, AppData : fichiers clés
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Windows Fundamentals/Windows Filesystems|Systèmes de Fichiers]] — NTFS, FAT32, ReFS : attributs et permissions
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Windows Fundamentals/Permissions Management on Windows|Gestion des Permissions]] — ACL, DACL, SACL, héritage des permissions
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Windows Fundamentals/Windows Users and Groups|Utilisateurs & Groupes]] — Comptes locaux, AD, groupes built-in, SID
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Windows Fundamentals/Windows Services|Services Windows]] — SCM, services, drivers : démarrage et persistance malware
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Windows Fundamentals/Windows Process Management|Gestion des Processus]] — Task Manager, Process Explorer, processus légitimes vs malveillants
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Windows Fundamentals/Windows Registry|Registre Windows]] — Structure du registre, hives, clés de persistance malware
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Windows Fundamentals/Windows Management Instrumentation (WMI)|WMI]] — WMI : requêtes, abonnements, persistance via WMI
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Windows Fundamentals/Task Scheduler Windows|Planificateur de Tâches]] — Tâches planifiées : analyse et détection de persistance
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Windows Fundamentals/Windows Firewall|Firewall Windows]] — Configuration du firewall Windows et règles de filtrage
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Windows Fundamentals/Windows Command Line|Ligne de Commande Windows]] — CMD et PowerShell : commandes essentielles
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Windows Fundamentals/Event Logs|Event Logs]] — Visualiseur d'événements, Security/System/Application logs

### Let's Defend — SOC Lab Windows
- [[Cours/Let's Defend/SOC Analyst Path/Building a SOC Lab at Home/Windows Workstation|Windows Workstation Lab]] — Configuration d'une station Windows pour lab SOC
- [[Cours/Let's Defend/SOC Analyst Path/Sysmon|Sysmon]] — Installation et configuration de Sysmon pour la détection

### Windows Internals
- [[Images/Windows Internals/Résumé 1e7eb38a212b803191acf8b6a33491d0|Windows Internals — Résumé]] — Synthèse visuelle des mécanismes internes Windows

### Cheatsheets Windows
- [[Cours/Cheatsheet/Windows|Windows Cheatsheet]] — Référence rapide des commandes Windows
- [[Cours/Cheatsheet/Windows_cmd|Windows CMD Cheatsheet]] — Commandes CMD/PowerShell essentielles

---

## CTF & Writeups

### Root-Me — Forensics Windows
- [[CTF/Root-Me/Forensics/Windows - LDAP User ASRepRoastable|LDAP ASRepRoastable]] — Identification d'utilisateurs ASREPRoastables
- [[CTF/Root-Me/Forensics/Windows - LDAP User KerbeRoastable|LDAP KerbeRoastable]] — Identification d'utilisateurs Kerberoastables
- [[CTF/Root-Me/Forensics/Windows - NTDS Extraction de secrets|NTDS Extraction]] — Extraction des secrets depuis NTDS.dit

### Root-Me — App-Script PowerShell
- [[CTF/Root-Me/App-Script/Powershell - Basic jail|PowerShell Jail]] — Évasion d'un environnement PowerShell restreint (Constrained Language Mode)
- [[CTF/Root-Me/App-Script/Powershell - Command injection|PowerShell Cmd Injection]] — Injection dans un script PowerShell
- [[CTF/Root-Me/App-Script/Powershell - SecureString|PowerShell SecureString]] — Décryptage d'une SecureString PowerShell
