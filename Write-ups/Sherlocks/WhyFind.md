# WhyFind

We have been hot on the trail for a political dissident. They jump from café to café using the Wi-Fi making it hard to nab them. During one of their trips, they unknowingly sat next to one of our agents and we captured them with their laptop on. We need to know where they have been and what they have been doing. Analyze the KAPE output and see if you can get us some answers.

What is the Computer name of the machine?

```bash[2025-05-30 13:35:33.2001251 | INF] KAPE directory: D:\kape\KAPE  
[2025-05-30 13:35:33.2076457 | INF] Command line:   --tsource C: --target !SANS_Triage,ProgramData --tdest D:\KAPEOUT    
[2025-05-30 13:35:33.2086145 | INF] System info: Machine name: INVISIBLECHAINS, 64-bit: true, User: Ernes OS: "Windows10" (10.0.22631)  
[2025-05-30 13:35:37.1964875 | INF] Using Target operations
```

What is the first Wi-Fi SSID(Decoded) they connected to on May 30th 2025?

```bash
[Sep 19, 2025 - 22:41:02 (CEST)] exegol-ctf KAPEOUT # find C -type f -ipath '*/ProgramData/Microsoft/Wlansvc/Profiles/*' -print

C/ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/{18C11DBD-93AB-4CA9-A804-4F4475DA25B8}/{BAC95378-DC6B-4464-918E-4E005F747786}.xml
C/ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/{18C11DBD-93AB-4CA9-A804-4F4475DA25B8}/{B426F51B-2CDB-43FB-91C5-ACA8AF142052}.xml
C/ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/{18C11DBD-93AB-4CA9-A804-4F4475DA25B8}/{81093F9C-0E5B-4D1F-A839-1EE818B5DBC7}.xml
C/ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/{18C11DBD-93AB-4CA9-A804-4F4475DA25B8}/{BD1C26C2-663A-41DF-84D9-CFD5EDB58CC8}.xml
C/ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/{18C11DBD-93AB-4CA9-A804-4F4475DA25B8}/{6CD4E9FC-AF2A-4A34-8098-96571811E252}.xml
[Sep 19, 2025 - 22:41:11 (CEST)] exegol-ctf KAPEOUT # cat C/ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/{18C11DBD-93AB-4CA9-A804-4F4475DA25B8}/{BAC95378-DC6B-4464-918E-4E005F747786}.xml

<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
        <name>ArboretumCoffee</name>
        <SSIDConfig>
                <SSID>
                        <hex>4172626F726574756D436F66666565</hex>
                        <name>ArboretumCoffee</name>
                </SSID>
        </SSIDConfig>
        <connectionType>ESS</connectionType>
        <connectionMode>manual</connectionMode>
        <MSM>
                <security>
                        <authEncryption>
                                <authentication>WPA2PSK</authentication>
                                <encryption>AES</encryption>
                                <useOneX>false</useOneX>
                        </authEncryption>
                        <sharedKey>
                                <keyType>passPhrase</keyType>
                                <protected>true</protected>
                                <keyMaterial>01000000D08C9DDF0115D1118C7A00C04FC297EB010000005A4ABC7BC4832440BF97B61BA5FA90E800000000020000000000106600000001000020000000E4FD57B3D76FA93C87E992C3A26D581ACCD48B22096E204F71EBF2D8CFB4B85D000000000E8000000002000020000000A11DF9B27393BDDF0FC92D1C1574E6123A72F1BB2C15D56205133E1B758833A01000000023E23F30E0F5D1424E83EEB2F4489C084000000020A7695FDD6AB15A8D73A4B1DA59186C07AEBC028E22C58AFD8698FDA87F1EBECBA71A927F4DA03EB5F5041660A76B6D296C0F7D32B7BD6654070EBFA99246F9</keyMaterial>
                        </sharedKey>
                </security>
        </MSM>
        <MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">
                <enableRandomization>false</enableRandomization>
                <randomizationSeed>2228671806</randomizationSeed>
        </MacRandomization>
```

#hacking
