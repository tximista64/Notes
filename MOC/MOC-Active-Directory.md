---
tags: [MOC, Active-Directory]
---

# MOC — Active Directory

## Cours & Théorie

### TCM — Ethical Hacking Course
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Overview|Overview AD]] — Introduction à Active Directory : structure, Kerberos, rôle dans les entreprises
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Overview/Logical AD components|Composants logiques]] — Domaines, forêts, OUs, GPO, trusts
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Overview/Phisical AD components|Composants physiques]] — Contrôleurs de domaine, sites, réplication
- [[Cours/TCM/TCM Ethical Hacking Course/AD/ad case study|AD Case Study]] — Étude de cas complète d'une attaque AD

### Vecteurs d'attaque initiaux
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Initial Attack Vectors/LLMNR Poisoning + (hashcat tip|LLMNR Poisoning]] — Empoisonnement LLMNR/NBT-NS pour capturer des hashes
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Initial Attack Vectors/smb relay attack|SMB Relay Attack]] — Relayer les authentifications NTLM via SMB
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Initial Attack Vectors/smb relay mitigation|SMB Relay Mitigation]] — Contre-mesures pour les attaques SMB Relay
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Initial Attack Vectors/Ipv6 attacks|IPv6 Attacks]] — Attaques via IPv6 (mitm6, DHCPv6 spoofing)
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Initial Attack Vectors/Ipv6 attacks defense|IPv6 Defense]] — Défenses contre les attaques IPv6
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Initial Attack Vectors/passback attack|Passback Attack]] — Attaque passback sur imprimantes et services
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Initial Attack Vectors/Gaining shell|Gaining Shell]] — Obtention d'un shell initial sur un réseau AD
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Initial Attack Vectors/Initial attack strategy|Initial Attack Strategy]] — Stratégie globale d'attaque initiale

### Post-Compromise — Attaques
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise attcks/Kerberoasting|Kerberoasting]] — Extraction et crackage de tickets de service Kerberos
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise attcks/Kerberoasting overview|Kerberoasting Overview]] — Présentation théorique du Kerberoasting
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise attcks/Kerberoasting mitigations|Kerberoasting Mitigations]] — Contre-mesures au Kerberoasting
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise attcks/Mimikatz|Mimikatz]] — Extraction de credentials avec Mimikatz
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise attcks/Pass attacks attack|Pass-the-Hash / Pass-the-Password]] — Attaques pass-the-hash et pass-the-password
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise attcks/Pass attacks overview|Pass Attacks Overview]] — Vue d'ensemble des attaques Pass
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise attcks/Pass attacks mitigation|Pass Attacks Mitigation]] — Contre-mesures aux attaques Pass
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise attcks/Token impersonation|Token Impersonation]] — Usurpation de tokens Windows
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise attcks/Token impersonation overview|Token Impersonation Overview]] — Théorie de l'impersonation de tokens
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise attcks/Token impersonation mitigation|Token Impersonation Mitigation]] — Défenses contre l'impersonation
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise attcks/GPP attacks|GPP Attacks]] — Exploitation des Group Policy Preferences
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise attcks/Dumping and cracking hashes|Dumping & Cracking Hashes]] — Extraction et crackage de hashes NTLM
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise attcks/ URL File Attacks|URL File Attacks]] — Attaques via fichiers .url malveillants

### Post-Compromise — Énumération
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise Enumeration/Bloodhound|BloodHound]] — Cartographie des chemins d'attaque AD avec BloodHound
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise Enumeration/ldapdomaindump|ldapdomaindump]] — Extraction d'informations LDAP via ldapdomaindump
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Attacking Active Directory Post-Compromise Enumeration/Plumhound|Plumhound]] — Analyse des résultats BloodHound avec Plumhound

### Post-Compromise — Domain Dominance
- [[Cours/TCM/TCM Ethical Hacking Course/AD/We've Compromised the Domain - Now What/ Dumping the NTDS.dit|Dumping NTDS.dit]] — Extraction de la base de données AD (NTDS.dit)
- [[Cours/TCM/TCM Ethical Hacking Course/AD/We've Compromised the Domain - Now What/Golden Ticket attack|Golden Ticket Attack]] — Création et utilisation d'un Golden Ticket Kerberos
- [[Cours/TCM/TCM Ethical Hacking Course/AD/We've Compromised the Domain - Now What/Golden Ticket overview|Golden Ticket Overview]] — Théorie des Golden Tickets
- [[Cours/TCM/TCM Ethical Hacking Course/AD/We've Compromised the Domain - Now What/Post-Compromise Attack Strateg|Post-Compromise Strategy]] — Stratégie après compromission du domaine

### Attaques supplémentaires
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Additional Ad attacks/printnightmare|PrintNightmare]] — Exploitation de la vulnérabilité PrintNightmare (CVE-2021-34527)
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Additional Ad attacks/Zerologon|ZeroLogon]] — Exploitation de ZeroLogon (CVE-2020-1472)
- [[Cours/TCM/TCM Ethical Hacking Course/AD/Additional Ad attacks/Section overview|Section Overview]] — Vue d'ensemble des attaques AD avancées

### Let's Defend — SOC Lab
- [[Cours/Let's Defend/SOC Analyst Path/Building a SOC Lab at Home/Active Directory|Active Directory Lab]] — Mise en place d'un environnement AD pour lab SOC

### Cheatsheet
- [[Cours/Cheatsheet/AD|AD Cheatsheet]] — Référence rapide des commandes et techniques Active Directory

---

## CTF & Writeups

### Root-Me — Forensics AD
- [[CTF/Root-Me/Forensics/Active Directory-GPO|Active Directory-GPO]] — Analyse d'un PCAP contenant un GPP cpassword via SMB
- [[CTF/Root-Me/Forensics/Windows - LDAP User ASRepRoastable|Windows - LDAP User ASRepRoastable]] — Identification d'un utilisateur ASREPRoastable via LDAP
- [[CTF/Root-Me/Forensics/Windows - LDAP User KerbeRoastable|Windows - LDAP User KerbeRoastable]] — Identification d'un compte Kerberoastable dans un dump AD
- [[CTF/Root-Me/Forensics/Windows - NTDS Extraction de secrets|Windows - NTDS Extraction]] — Extraction de secrets depuis un fichier NTDS.dit

### Root-Me — Réaliste AD
- [[CTF/Root-Me/Réaliste/OpenClassrooms - Sécurité Active Directory|OpenClassrooms — Sécurité AD]] — Scénario réaliste de sécurisation et attaque AD
- [[CTF/Root-Me/Réaliste/Windows - ASRepRoast|Windows - ASRepRoast]] — Exploitation d'un compte sans pré-authentification Kerberos
- [[CTF/Root-Me/Réaliste/Windows - KerbeRoast|Windows - KerbeRoast]] — Kerberoasting d'un compte de service dans un environnement réaliste
- [[CTF/Root-Me/Réaliste/Windows - Group Policy Preferences Passwords|GPP Passwords]] — Récupération de mots de passe via les GPP
- [[CTF/Root-Me/Réaliste/Windows - ZeroLogon|Windows - ZeroLogon]] — Exploitation de la vulnérabilité ZeroLogon sur un DC

### Root-Me — Réseaux
- [[CTF/Root-Me/Réseaux/Kerberos - Authententification|Kerberos Authentication]] — Analyse du protocole Kerberos dans un PCAP
- [[CTF/Root-Me/Réseaux/LDAP - null bind|LDAP Null Bind]] — Exploitation d'un LDAP avec un bind anonyme
