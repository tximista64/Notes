---
tags: [MOC, Linux, Privilege-Escalation]
---

# MOC — Linux & Privilege Escalation

## Cours & Théorie

### TCM — Linux 101
- [[Cours/TCM/Linux 101/Tcm Linux 101|Linux 101 — Vue d'ensemble]] — Introduction à Linux pour le hacking éthique
- [[Cours/TCM/Linux 101/commandes multiples|Commandes Multiples]] — Enchaînement de commandes, pipes, redirections
- [[Cours/TCM/Linux 101/Changer le hostname|Changer le Hostname]] — Modifier le hostname d'une machine Linux
- [[Cours/TCM/Linux 101/Chiffrerdéchiffrer avec open s|Chiffrement avec OpenSSL]] — Chiffrement/déchiffrement de fichiers avec OpenSSL

### TCM — Introduction à Linux (Ethical Hacking)
- [[Cours/TCM/TCM Ethical Hacking Course/Introduction to linux/Navigating the file system|Navigation Système de Fichiers]] — cd, ls, find, locate pour naviguer dans Linux
- [[Cours/TCM/TCM Ethical Hacking Course/Introduction to linux/Viewing creating and editing f|Fichiers — Création & Édition]] — cat, nano, vim, touch, cp, mv, rm
- [[Cours/TCM/TCM Ethical Hacking Course/Introduction to linux/Users and privileges|Utilisateurs & Privilèges]] — chmod, chown, sudo, groupes, /etc/passwd, /etc/shadow
- [[Cours/TCM/TCM Ethical Hacking Course/Introduction to linux/Starting and stopping services|Services]] — systemctl, service, démarrage au boot
- [[Cours/TCM/TCM Ethical Hacking Course/Introduction to linux/Installing and upgrating tools|Installation d'Outils]] — apt, pip, git clone pour installer des outils de hacking
- [[Cours/TCM/TCM Ethical Hacking Course/Introduction to linux/common network control|Contrôle Réseau]] — ifconfig, ip, netstat, ss, ping pour l'analyse réseau Linux

### Let's Defend — Linux for Blueteam
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Linux for Blueteam/Introduction to Linux|Introduction à Linux]] — Bases Linux pour les analystes Blue Team
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Linux for Blueteam/Basic Terminal Commands - 1|Commandes Terminal (1)]] — Navigation, gestion de fichiers, texte
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Linux for Blueteam/Basic Terminal Commands - 2|Commandes Terminal (2)]] — Filtrage, recherche, pipes et redirections
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Linux for Blueteam/Linux File System Hierarchy|Hiérarchie FHS]] — /etc, /var, /proc, /tmp : structure des dossiers Linux
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Linux for Blueteam/Permissions Management|Gestion des Permissions]] — Lecture des permissions rwx, SUID/SGID, ACL
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Linux for Blueteam/User Management and Groups|Utilisateurs & Groupes]] — Création, suppression, gestion des comptes
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Linux for Blueteam/Process Management|Gestion des Processus]] — ps, top, kill, strace, analyse de processus
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Linux for Blueteam/Service Management|Gestion des Services]] — systemd, journald, gestion des services système
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Linux for Blueteam/Scheduled Tasks|Tâches Planifiées]] — Crontab, at, anacron : persistance et détection
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Linux for Blueteam/Package Management|Gestion des Paquets]] — apt, dpkg, rpm, yum
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Linux for Blueteam/Network Management|Gestion Réseau Linux]] — Configuration réseau, outils de diagnostic
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Linux for Blueteam/Archive File Formats|Formats d'Archive]] — tar, gzip, bzip2, zip : analyse d'archives

### HTB Academy — Linux Target (Pentest)
- [[Cours/HTB academy/CJCA/11 Pentest in a nutshell/5Linux Target/Linux_Information_Gathering|Collecte d'Informations]] — Énumération initiale d'une cible Linux
- [[Cours/HTB academy/CJCA/11 Pentest in a nutshell/5Linux Target/Linux_System_Enumeration|Énumération Système]] — OS version, kernel, utilisateurs, SUID, crontab
- [[Cours/HTB academy/CJCA/11 Pentest in a nutshell/5Linux Target/Linux_Vulnerability_Assessment|Évaluation des Vulnérabilités]] — Identification des CVEs et misconfigs Linux
- [[Cours/HTB academy/CJCA/11 Pentest in a nutshell/5Linux Target/Linux_Initial_Access|Accès Initial]] — Exploitation d'une vulnérabilité pour obtenir un shell
- [[Cours/HTB academy/CJCA/11 Pentest in a nutshell/5Linux Target/Linux_Privilege_Escalation|Escalade de Privilèges]] — SUID, sudo, cron, PATH, kernel exploits
- [[Cours/HTB academy/CJCA/11 Pentest in a nutshell/5Linux Target/Linux_Pillaging|Pillaging]] — Recherche de credentials, clés SSH, fichiers sensibles

### Cheatsheets Linux
- [[Cours/Cheatsheet/Linux|Linux Cheatsheet]] — Référence rapide des commandes Linux essentielles
- [[Cours/Cheatsheet/Docker|Docker Cheatsheet]] — Commandes Docker pour le déploiement et l'exploitation
- [[Cours/Cheatsheet/Freebsd|FreeBSD Cheatsheet]] — Commandes spécifiques FreeBSD

---

## CTF & Writeups

### PentesterLab — Unix Badge
- [[Cours/PentesterLab/Unix badge/Unix00cat|Unix00 — cat]] — Lecture de fichiers avec cat en contexte restreint
- [[Cours/PentesterLab/Unix badge/Unix01directorytraversal|Unix01 — Directory Traversal]] — Traversée de répertoires sur un système Unix
- [[Cours/PentesterLab/Unix badge/Unix02blind cat|Unix02 — Blind cat]] — Lecture de fichiers en aveugle
- [[Cours/PentesterLab/Unix badge/Unix03bash_history|Unix03 — Bash History]] — Exploitation du fichier .bash_history pour trouver des credentials
- [[Cours/PentesterLab/Unix badge/Unix04find&bash_history|Unix04 — find & bash_history]] — Combinaison de find et bash_history
- [[Cours/PentesterLab/Unix badge/Unix05.bashrc|Unix05 — .bashrc]] — Exploitation du .bashrc pour la persistance ou l'escalade
- [[Cours/PentesterLab/Unix badge/Unix06PATH|Unix06 — PATH]] — Hijacking du PATH pour exécuter du code arbitraire
- [[Cours/PentesterLab/Unix badge/Unix07othershells|Unix07 — Other Shells]] — Évasion via d'autres interpréteurs (sh, dash, zsh)
- [[Cours/PentesterLab/Unix badge/Unix08wronghome|Unix08 — Wrong Home]] — Exploitation d'un HOME mal configuré
- [[Cours/PentesterLab/Unix badge/Unix09passwordmistake|Unix09 — Password Mistake]] — Récupération de mot de passe mal stocké
- [[Cours/PentesterLab/Unix badge/Unix10 tmpforgottenfile|Unix10 — /tmp Forgotten File]] — Fichier sensible oublié dans /tmp
- [[Cours/PentesterLab/Unix badge/Unix11 vartmpforgottenfile|Unix11 — /var/tmp]] — Fichier sensible dans /var/tmp
- [[Cours/PentesterLab/Unix badge/Unix12bzip,file,strings|Unix12 — bzip/strings]] — Extraction d'informations avec bzip2, file, strings
- [[Cours/PentesterLab/Unix badge/Unix13cron|Unix13 — cron]] — Exploitation d'une tâche cron vulnérable
- [[Cours/PentesterLab/Unix badge/Unix14cron su|Unix14 — cron + su]] — Escalade via cron et su combinés
- [[Cours/PentesterLab/Unix badge/unix15etcshadow|Unix15 — /etc/shadow]] — Lecture et crackage de /etc/shadow
- [[Cours/PentesterLab/Unix badge/unix16etcshadow2|Unix16 — /etc/shadow (2)]] — Exploitation avancée via /etc/shadow
- [[Cours/PentesterLab/Unix badge/unix17tomcat|Unix17 — Tomcat]] — Escalade via Apache Tomcat mal configuré
- [[Cours/PentesterLab/Unix badge/unix 18mysql|Unix18 — MySQL]] — Escalade via MySQL (UDF, FILE privilege)
- [[Cours/PentesterLab/Unix badge/unix19mysqlpassword|Unix19 — MySQL Password]] — Récupération du mot de passe MySQL
- [[Cours/PentesterLab/Unix badge/unix20password|Unix20 — Password]] — Récupération de mot de passe dans des fichiers config
- [[Cours/PentesterLab/Unix badge/unix21norootpassword|Unix21 — No Root Password]] — Accès root sans mot de passe
- [[Cours/PentesterLab/Unix badge/unix22postgres|Unix22 — PostgreSQL]] — Escalade via PostgreSQL
- [[Cours/PentesterLab/Unix badge/unix23fileaccesswithpostgres|Unix23 — File Access PostgreSQL]] — Lecture de fichiers via COPY TO/FROM PostgreSQL
- [[Cours/PentesterLab/Unix badge/unix24sqlite3|Unix24 — SQLite3]] — Escalade ou extraction via SQLite3
- [[Cours/PentesterLab/Unix badge/unix25sudo|Unix25 — sudo]] — Escalade via sudo (GTFOBins)
- [[Cours/PentesterLab/Unix badge/unix26sudo&find|Unix26 — sudo + find]] — RCE via sudo find
- [[Cours/PentesterLab/Unix badge/unix27sudo&vim|Unix27 — sudo + vim]] — Shell via sudo vim
- [[Cours/PentesterLab/Unix badge/unix28less|Unix28 — less]] — Shell via sudo less
- [[Cours/PentesterLab/Unix badge/Unix29awk|Unix29 — awk]] — Exécution de commandes via awk
- [[Cours/PentesterLab/Unix badge/Unix30setuid|Unix30 — SUID]] — Exploitation de binaires SUID
- [[Cours/PentesterLab/Unix badge/unix31perl|Unix31 — perl]] — Shell et exec via sudo perl
- [[Cours/PentesterLab/Unix badge/unix32python|Unix32 — python]] — Shell via sudo python
- [[Cours/PentesterLab/Unix badge/unix33ruby|Unix33 — ruby]] — Shell via sudo ruby
- [[Cours/PentesterLab/Unix badge/unix34node|Unix34 — node]] — Shell via sudo node

### Root-Me — App-Script (Linux)
- [[CTF/Root-Me/App-Script/Bash - System 1|Bash System 1]] — Exploitation d'un script bash
- [[CTF/Root-Me/App-Script/Bash - System 2|Bash System 2]] — Exploitation bash avancée
- [[CTF/Root-Me/App-Script/Bash - cron|Bash Cron]] — Exploitation d'une tâche cron
- [[CTF/Root-Me/App-Script/sudo - faiblesse de configuration|sudo Misconfiguration]] — Escalade via sudo mal configuré
- [[CTF/Root-Me/App-Script/Docker - I am groot|Docker Root]] — Évasion de conteneur Docker
