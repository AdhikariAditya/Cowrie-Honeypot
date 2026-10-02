# Cowrie Honeypot

## Introduction

A honeypot is a term in cybersecurity used to describe a system that is left intentionally weak to entice attackers. It is specifically set up with open SSH ports, completely isolated from any actual data, and ensures rich telemetry of all actions taken by malicious parties. I built my own honeypot and spent the past week logging and analyzing common patterns and techniques attackers used, and built custom Wazuh and Sigma rules against them.

## What I used

My honeypot requires three main things:

1. **A system:** For this component, I used Oracle Cloud Infrastructure (OCI) free tier. This provides basic virtual machines, but they're strong enough to handle a honeypot. My system runs Ubuntu 22.04 with 4 OCPUs and 24GB of memory — plenty of power for the next two components.

2. **Honeypot software:** There are a fair number of options that can virtualize a honeypot. I used Cowrie, a medium-interaction honeypot that specializes in logging and capturing all interactions attackers attempt against a system. This includes SSH brute-force attacks, commands executed in the terminal, and files downloaded. Cowrie logs all of this extensively, which is perfect to feed into the next component.

3. **Security Information and Event Management (SIEM) software:** For my SIEM, I used Wazuh, since I was already familiar with it from my SOC home lab project. By feeding the JSON files Cowrie generates into Wazuh, I can build and test custom detection rules — but this time against actual attackers instead of just myself.

## Honeypot Data

For the first part of this project, I collected data from the honeypot: most common IPs, most-used commands, brute-force attempts, and client software. This data reflects roughly 2-3 days of honeypot uptime — a snapshot rather than a long-term trend.

All the data was generated with a simple Python script:

```python
import sys, json
from collections import Counter
MY_IPS = {'***.*.*.*', '***.***.***.*'}
ips, creds, cmds, clients = Counter(), Counter(), Counter(), Counter()
for line in sys.stdin:
    try: e = json.loads(line)
    except: continue
    if e.get('src_ip') in MY_IPS: continue
    eid = e.get('eventid','')
    if eid.startswith('cowrie.login'):
        ips[e['src_ip']] += 1
        creds[(e.get('username',''), e.get('password',''))] += 1
    elif eid == 'cowrie.command.input': cmds[e.get('input','')] += 1
    elif eid == 'cowrie.client.version': clients[e.get('version','')] += 1
print('=== Top attacker IPs ==='); [print(f'{ip}: {n}') for ip,n in ips.most_common(10)]
print('=== Top credentials ==='); [print(f'{u} / {p}: {n}') for (u,p),n in creds.most_common(15)]
print('=== Commands executed ==='); [print(f'{n}x  {c[:80]}') for c,n in cmds.most_common(10)]
print('=== Client software ==='); [print(f'{n}x  {v}') for v,n in clients.most_common(10)]
```

### 5th September 2026 – 7th September 2026

![Top attacker IPs, credentials, commands, and client software](/Writeup/images/image1.png)

Now this is already a lot to dissect. After just 2-3 days of honeypot uptime, a lot of data has been generated. Let's start from the top:

1. A lot of the same IPs have made a huge number of attempts. This is likely because attackers use VPNs or other compromised devices to mask their true IP — the IPs seen here most likely route back to VPN servers or compromised devices owned by innocent third parties. It's astonishing to see such a large number of attempts on my honeypot after very little uptime.

2. Cowrie honeypots specifically allow any combination of username and password to generate a successful login. Even so, it's interesting to see the most common ones being support / support or root / 12345. Most open machines like this honeypot are treated by bots as low-value, meaningless systems, so brute-forcers tend to reach for the most easily guessable combinations first.

3. The most commonly executed commands are largely the same across sessions. Attackers first run a discovery command (ATT&CK T1082) via uname. The second most common command simply prints xsec to the console — my best guess is that this is a liveness check, confirming the shell is a real interactive terminal before the attacker invests further steps. Most of the observed commands are discovery-stage. The two least common command sequences actually downloaded files to infect the honeypot: scp transfers the file, and chmod/bash execute it. Luckily, Cowrie saves every downloaded file to disk, named by its hash.

   ![Downloads directory listing on the honeypot host](/01_Setup_Writeup/images/image7.png)

   VirusTotal reveals interesting things about these hashes (numbering the hash right after .gitignore as 1):

   1. This hash was flagged as a trojan horse by 1 of 61 vendors (first reported by Kingsoft). Given the file is only 54 bytes — far too small to contain functional malicious code — this is most likely a heuristic false positive rather than a genuine threat.

      ![VirusTotal: 1/61 detections, 54 bytes](/Writeup/images/image3.png)

   2. This hash is a benign file, possibly used by the attacker as a test file to confirm downloads can occur on the system.

      ![VirusTotal: 0/61 detections, 399 bytes](/Writeup/images/image2.png)

   3. This hash is an IRC-based botnet trojan responsible for establishing backdoor access to a system.

      ![VirusTotal: 40/61 detections, ircbot/shell family](/Writeup/images/image4.png)

   4. This hash belongs to a known cryptocurrency miner — the attacker would piggyback off the host's hardware to mine cryptocurrency for their own benefit.

      ![VirusTotal: 44/61 detections, miner family](/Writeup/images/image6.png)

   5. Although this hash is flagged by 36/63 security vendors, VirusTotal's own code insights — which analyze a file's binary to determine its true purpose — reveal that this is actually a legitimate networking tool called Tailscale, with no malicious behavior (e.g. C2 communication or persistence) detected. The file itself isn't malicious, but a legitimate remote-access tool like this could still be dropped by an attacker to establish a persistent, encrypted access channel that blends in with normal VPN traffic.

      ![VirusTotal: 36/63 detections, code insights identify Tailscale](/Writeup/images/image5.png)

   Attackers will use any and all tools in their arsenal for their own benefit.

4. The final category is the client software attackers use. Many attackers are just bots instructed to find open SSH ports and run a preselected set of commands, which is why certain commands recur so heavily — these bots share common source code. SSH-2.0-Go alone accounts for 4,429 connections; Go is the de facto library for building custom scanners and botnets, so the large majority of this traffic is automated rather than human-driven. A small number of sessions used PUTTY or an OpenSSH client on Raspbian, distinct from the automated Go-based clients that dominate the traffic.

### Conclusion

It was genuinely surprising to see the sheer volume of attacks and data that has been collected over just three days. Even while emulating my own attacks for my SOC Home Lab project, I could not even imagine the sheer amount of attacks that an actual analyst might have to face and sort through. My next step in this project is to make more custom rules: this time in both XML for Wazuh and Sigma for other SIEMs. 

## Additional Notes

The Oracle system is fitted with my public key; it will only accept connections from my private key.

The system is named service102 to make it blend in and appear as a generic machine.

The system is extremely fresh/unused — over the coming weeks, I'll add more files and ensure the system looks "lived-in."
