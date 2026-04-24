##### Sherlock Scenario
Susan works at the Research Lab in Forela International Hospital. A Microsoft Defender alert was received from her computer, and she also mentioned that while extracting a document from the received file, she received tons of errors, but the document opened just fine. According to the latest threat intel feeds, WinRAR is being exploited in the wild to gain initial access into networks, and WinRAR is one of the Software programs the staff uses. You are a threat intelligence analyst with some background in DFIR. You have been provided a lightweight triage image to kick off the investigation while the SOC team sweeps the environment to find other attack indicators.
### What is the CVE assigned to the WinRAR vulnerability exploited by the RomCom threat group in 2025?
CVE-2025-8088
https://french.opswat.com/blog/cve-2025-8088-technical-analysis-winrar-arbitrary-file-write-through-ads
### What is the nature of this vulnerability?
Path Traversal
### What is the name of the archive file under Susan's documents folder that exploits the vulnerability upon opening the archive file?
On va déja monter l'image
```shell
sudo modprobe nbd max_part=8
sudo qemu-nbd --connect=/dev/nbd0 2025-09-02T083211_pathology_department_incidentalert.vhdx
sudo mount /dev/nbd0p1 /mnt
```

ctf HTB sherlock defensive dfir threatintel CVE-2025-8088 winrar windows forensics
