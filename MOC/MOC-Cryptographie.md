---
tags: [MOC, Cryptographie, Stéganographie]
---

# MOC — Cryptographie & Stéganographie

## Cours & Théorie

### Let's Defend — Introduction to Cryptology
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Introduction to Cryptology/Basic Concepts of Cryptology|Concepts de Base]] — Terminologie : chiffrement, déchiffrement, clé, plaintext
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Introduction to Cryptology/Objectives of Cryptography|Objectifs de la Cryptographie]] — Confidentialité, intégrité, authenticité, non-répudiation
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Introduction to Cryptology/Types of Cryptography|Types de Cryptographie]] — Symétrique, asymétrique, hachage
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Introduction to Cryptology/Symmetric Algorithms|Algorithmes Symétriques]] — AES, DES, 3DES, RC4 — modes opératoires
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Introduction to Cryptology/Historical Ciphers|Chiffrements Historiques]] — César, Vigenère, Enigma — bases de la cryptanalyse
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Introduction to Cryptology/Hash Functions|Fonctions de Hachage]] — MD5, SHA-1, SHA-256, SHA-3 et leurs usages
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Introduction to Cryptology/Digital Signatures|Signatures Numériques]] — RSA, ECDSA, PKI et chaîne de confiance
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Introduction to Cryptology/SSL TLS Protocol|SSL/TLS]] — Handshake TLS, certificats X.509, HTTPS
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Introduction to Cryptology/Base64 Encoding Decoding|Base64]] — Encodage Base64 : principes et détection
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Introduction to Cryptology/Cryptographic Attacks|Attaques Cryptographiques]] — Brute force, birthday attack, rainbow tables, side-channel
- [[Cours/Let's Defend/Career Switch to Cybersecurity/Introduction to Cryptology/Random Number Generators|Générateurs de Nombres Aléatoires]] — PRNG vs TRNG, vulnérabilités des RNG faibles

### PentesterLab — Cryptographie
- [[Cours/PentesterLab/White badge/Electronic Code Book|ECB Mode]] — Vulnérabilités du mode ECB (patterns dans les blocs)
- [[Cours/PentesterLab/White badge/JSON Web Token|JWT Attacks]] — Attaques sur les JSON Web Tokens : alg:none, weak secret, kid injection

---

## CTF & Writeups

### Root-Me — Cryptanalyse
- [[CTF/Root-Me/Cryptanalyse/Encodage - ASCII|Encodage ASCII]] — Décodage de données encodées en ASCII
- [[CTF/Root-Me/Cryptanalyse/Encodage - Codebook|Codebook]] — Déchiffrement d'un code par substitution avec codebook
- [[CTF/Root-Me/Cryptanalyse/Encodage - UU|Encodage UU]] — Décodage de l'encodage UUencode
- [[CTF/Root-Me/Cryptanalyse/Chiffrement par décalage|Chiffre de César]] — Cryptanalyse d'un chiffrement par décalage (ROT/César)
- [[CTF/Root-Me/Cryptanalyse/Substitution monoalphabétique - César|Substitution Monoalphabétique]] — Analyse fréquentielle pour casser une substitution simple
- [[CTF/Root-Me/Cryptanalyse/Clair connu - XOR|XOR Clair Connu]] — Attaque par clair connu sur du XOR
- [[CTF/Root-Me/Cryptanalyse/Circular Bit Shift|Circular Bit Shift]] — Décryptage d'un chiffrement par rotation de bits
- [[CTF/Root-Me/Cryptanalyse/CISCO - Salted Password|CISCO Salted Password]] — Crackage de mots de passe Cisco (type 5/7)
- [[CTF/Root-Me/Cryptanalyse/ELF64 - Chiffrement avec le PID|ELF64 Chiffrement PID]] — Rétro-ingénierie d'un chiffrement basé sur le PID du processus
- [[CTF/Root-Me/Cryptanalyse/Fichier - PKZIP|PKZIP]] — Attaque sur archive ZIP chiffrée (known-plaintext)
- [[CTF/Root-Me/Cryptanalyse/Décomposition pixelisée|Décomposition Pixelisée]] — Cryptanalyse visuelle / stéganographie par pixels
- [[CTF/Root-Me/Cryptanalyse/Hash - DCC|Hash DCC]] — Crackage de hash Domain Cached Credentials (DCC)
- [[CTF/Root-Me/Cryptanalyse/Hash - DCC2|Hash DCC2]] — Crackage de hash DCC v2 (MS-Cache v2)
- [[CTF/Root-Me/Cryptanalyse/Hash - LM|Hash LM]] — Crackage de hash LAN Manager (LM hash Windows)
- [[CTF/Root-Me/Cryptanalyse/Hash - Message Digest 5|Hash MD5]] — Crackage de hash MD5
- [[CTF/Root-Me/Cryptanalyse/Hash - NT|Hash NT]] — Crackage de hash NTLM (NT hash Windows)
- [[CTF/Root-Me/Cryptanalyse/Hash - SHA-2|Hash SHA-2]] — Crackage de hash SHA-256/SHA-512

### Root-Me — Stéganographie
- [[CTF/Root-Me/Steganographie/EXIF - Metadata|EXIF Metadata]] — Extraction d'informations cachées dans les métadonnées EXIF
- [[CTF/Root-Me/Steganographie/EXIF - Miniature|EXIF Miniature]] — Données cachées dans la miniature EXIF d'une image
- [[CTF/Root-Me/Steganographie/Points jaunes|Points Jaunes]] — Décryptage des points jaunes (steganographie imprimantes laser)
- [[CTF/Root-Me/Steganographie/Point à la ligne|Point à la Ligne]] — Stéganographie dans les sauts de ligne/espaces blancs
- [[CTF/Root-Me/Steganographie/Twitter Secret Messages|Twitter Secret Messages]] — Messages cachés dans des tweets
- [[CTF/Root-Me/Steganographie/WAV - Analyse de bruit|WAV Bruit]] — Extraction de données cachées dans le bruit d'un fichier WAV
- [[CTF/Root-Me/Steganographie/WAV - Analyse spectrale|WAV Spectral]] — Analyse spectrale d'un fichier audio pour extraire un message
- [[CTF/Root-Me/Steganographie/Mimic - Dummy sight|Mimic]] — Stéganographie avancée avec l'outil Mimic
- [[CTF/Root-Me/Steganographie/Poem from Space|Poem from Space]] — Message caché dans un poème (stéganographie textuelle)
- [[CTF/Root-Me/Steganographie/Steganomobile|Steganomobile]] — Stéganographie dans une image mobile

### HTB — Challenges Crypto
- [[CTF/HTB/Challenges/Simple Encryptor|Simple Encryptor]] — Reverse d'un algorithme de chiffrement simple
- [[CTF/HTB/Challenges/Primed_For_Action|Primed For Action]] — Challenge de cryptographie basé sur les nombres premiers
