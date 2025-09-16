# SalineBreeze-1


## Mitre Attack & Cisco Talos

https://blog.talosintelligence.com/salt-typhoon-analysis/

**Starting with the MITRE ATT&CK page, which country is thought be behind Salt Typhoon?
- China https://attack.mitre.org/groups/G1045/
**According to that page, Salt Typhoon has been active since at least when? (Year)
- 2019 https://attack.mitre.org/groups/G1045/
**What kind of infrastructure does Salt Typhoon target?
- network https://home.treasury.gov/news/press-releases/jy2792
**Salt Typhoon has been associated with multiple custom built malware, what is the name of the malware associated with the ID S1206?
- JumbledPath https://attack.mitre.org/software/S1206/
**What operating system does this malware target?
- Linux  https://attack.mitre.org/software/S1206/
**What programming language is the malware written in?
- GO https://attack.mitre.org/software/S1206/
**On which vendor's devices does the malware act as a network sniffer?
- cisco https://blog.talosintelligence.com/salt-typhoon-analysis/
**The malware can perform 'Indicator Removal' by erasing logs. What is the MITRE ATT&CK ID for this?** 
- T1070.002 https://attack.mitre.org/techniques/T1070/002/
**On December 20th, 2024, Picus Security released a blog on Salt Typhoon detailing some of the CVEs associated with the threat actor. What was the CVE for the vulnerability related to the Sophos Firewall?** 
- CVE-2022-3236 https://www.picussecurity.com/resource/blog/salt-typhoon-telecommunications-threat
**The blog demonstrates how the group modifies the registry to obtain persistence with a backdoor known as Crowdoor. Which registry key do they target?
- HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
**On November 25th, 2024, TrendMicro published a blog post detailing the threat actor. What name does this blog primarily use to refer to the group?
- [Earth Estries](https://www.trendmicro.com/en_us/research/23/h/earth-estries-targets-government-tech-for-cyberespionage.html "open on a new tab")
**The blog post identifies additional malware attributed to the threat actor. Which malware do they describe as a 'multi-modular backdoor...using a custom protocol protected by Transport Layer Security'
- telcom.grishamarkovgf8936.workers.dev
**What is the filename for the first GET request to the C&C server used by the malware?

**Communication protocol**

The communication requests that are used by the GHOSTSPIDER stager follow a common format. A connection ID is placed in the HTTP header's cookie as “phpsessid”. The connection ID is calculated using CRC32 or CRC64 with UUID4 values. Figure 10 shows an example of a stager's first request to the C&C server. 

![Figure 10. Example of a stager's first request to the C&C server](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/24/k/earth-estries/EarthEstries-Fig10.jpg)

