---
tags: [MOC, Index]
---

# INDEX — Maps of Content (Cybersécurité)

Vue d'ensemble du vault. Chaque MOC liste les fichiers correspondants avec liens et descriptions.

---

## Blue Team / Défense

| MOC | Thème | Contenu |
|-----|-------|---------|
| [[MOC-DFIR]] | Incident Response | Cycle de vie des incidents, CSIRT, playbooks, Sherlocks HTB |
| [[MOC-SIEM]] | SIEM & Logs | Splunk, Elastic, corrélation, solutions SOC, cases Let's Defend |
| [[MOC-Threat-Hunting]] | Threat Hunting & CTI | MITRE ATT&CK, Kill Chain, Elastic hunting, renseignement menaces |
| [[MOC-Forensic]] | Forensique | PCAP, artefacts disque/mémoire, logs, Root-Me forensics |
| [[MOC-Malware]] | Analyse de Malware | Statique, dynamique, YARA, VirusTotal, sandbox |
| [[MOC-Windows]] | Windows | Event Logs, Sysmon, ETW, internals, PowerShell |
| [[MOC-Linux]] | Linux | Administration, privesc, GTFOBins, PentesterLab Unix |

---

## Red Team / Offensif

| MOC | Thème | Contenu |
|-----|-------|---------|
| [[MOC-Pentest]] | Pentest | Méthodologie, Metasploit, exploitation, post-exploitation, HTB Boxes |
| [[MOC-Active-Directory]] | Active Directory | LLMNR, Kerberoasting, Golden Ticket, BloodHound, Root-Me AD |
| [[MOC-Web]] | Web Application | XSS, SQLi, SSRF, IDOR, JWT, PentesterLab, PortSwigger, Root-Me Web |
| [[MOC-OSINT]] | OSINT | Réseaux sociaux, géolocalisation, EXIF, TCM OSINT course |
| [[MOC-Reverse]] | Reverse Engineering | Cracking ELF/PE/APK, Root-Me cracking |
| [[MOC-Pwn]] | Exploitation Binaire | Buffer overflow, heap overflow, Root-Me App-System |

---

## Transverse

| MOC | Thème | Contenu |
|-----|-------|---------|
| [[MOC-Réseau]] | Réseau & Protocoles | OSI, TCP/IP, PCAP PentesterLab, Root-Me réseaux, Wireshark |
| [[MOC-Cryptographie]] | Cryptographie & Stéga | Hachage, chiffrement, Root-Me cryptanalyse & stéganographie |
| [[MOC-Cheatsheet]] | Cheatsheets | Nmap, AD, Metasploit, Linux, Windows, ASM, Web Requests |

---

## Sources de Contenu

```
Cours/
├── Cheatsheet/          → 15 référentiels rapides
├── HTB academy/
│   ├── CDSA/            → Blue Team : IH, SIEM, EventLogs, ThreatHunting, Malware
│   └── CJCA/            → Red Team : InfoSec, Réseau, Footprinting, Metasploit, Pentest
├── Let's Defend/
│   ├── Career Switch/   → Fondamentaux : Crypto, Linux, Windows, Réseau
│   └── SOC Analyst/     → SOC : SIEM, Malware, Phishing, CTI, Détection
├── TCM/                 → AD, Exploitation, OSINT, Linux, Python, Post-Exploit
├── PentesterLab/        → Web vulnérabilités, PCAP, Unix privesc, HTTP
└── PortSwigger/         → Server-side vulnerabilities, SQLi

CTF/
├── HTB/                 → Boxes, Challenges, Sherlocks, Events
├── Root-Me/             → Web, Crypto, Forensics, Réseaux, Cracking, App-System
└── Let's defend/        → SOC cases (141, 146, 165-170)
```
