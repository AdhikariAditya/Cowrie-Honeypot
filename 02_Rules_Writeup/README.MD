# Cowrie Honeypot: Rules

I previously built a honeypot using Cowrie on an Oracle Cloud Machine. I analysed all the logs and understood tactics that real-world attackers or bots might use against an actual system. For my next step, I want to shield my machine against these attackers. My honeypot is already set up with Wazuh SIEM and all telemetry goes through it. For this part of my project, I will write more rules: both Sigma and Wazuh XML rules which will be able to differentiate between bots and humans. 

*To find their Sigma equivalent of the rules I write, find the attached file: [Sigma Rules.md](/02_Rules_Writeup/SigmaRules.md).*

# Rule 1: Logging in (T1110)

The biggest issue with our honeypot is that we have to engineer rules for something that is meant to have no rules. My initial thought was a rule for logging on, but that would flag everything. So I have to refine it further. Most robots brute force a log on, enter a few commands and log off. Since this entire process is automated, it is all executed within a very small time frame — less than a few seconds. If an actual human were to do any of this, it would take them time to type out the commands or logins, maybe they would even have a few typos. This discrepancy between robotic efficiency and human efficiency is the perfect place for our first rule.

```
<group name="cowrie,brute_force,">

<rule id="100001" level="5">  
<decoded_as>json</decoded_as>  
<field name="eventid">cowrie.login.failed</field>  
<description>Cowrie failed login from $(src_ip)</description>  
</rule>

<rule id="100002" level="12" frequency="10" timeframe="10">  
<if_matched_sid>100001</if_matched_sid>  
<same_field>src_ip</same_field>  
<description>SSH brute force from $(src_ip) - matches bot speed</description>  
<mitre><id>T1110.001</id></mitre>  
</rule>

<rule id="100003" level="14" frequency="5" timeframe="120">  
<if_matched_sid>100001</if_matched_sid>  
<same_field>src_ip</same_field>  
<description>SSH brute force attack from $(src_ip) - matches human speed</description>  
<mitre><id>T1110.001</id></mitre>  
</rule>

</group>
```

Rule 100001 detects any logins, but that does not mean anything malicious if this were an actual SSH system hence why it is at a severity level of 5. Rule 100002 is more interesting: it detects if 10 logins have been made within 10 seconds from the same source IP, something impossible by a human. After it detects this, it then alerts us of the IP this attack is coming from and informs us that it is possibly an automated attack. 

Rule 100003 is similar, it detects if 5 login attempts have been made in 120 seconds, an average of 1 login per 24 seconds. This is achievable by normal humans and a robot which might be trained to maximize efficiency would not delay its attacks this much. Just like the previous rule, this one also informs us of the IP and the possible attack. 

Rule 100002 has a severity ID of 12 while a 100003 has a severity ID of 14, these are intentional design choices. An actual human trying to break into your system is much more alarming than an automated script doing so.

This rule is limited by the fact that if an attacker is tailoring a program against our system and causes a delay in their brute force attempts, attackers could also paste the passwords via keyboard shortcuts to lessen the delay and falsely pass as bots or if a human themselves forgot their login password and tried various passwords, then it would be flagged. But these 3 rules would detect any brute force attacks that happen to any random unsecured open system. 

Let’s test out the rule:

[Video of Rule Firing](/02_Rules_Writeup/Media/Wazuh%20Log%20In%20Rules.mp4)

Our rule has successfully worked and flagged me as human. So officially, if any attacker tries to brute force themselves into my honeypot, Wazuh SIEM will detect it immediately. 

# Rule 2: Executing Commands

As we analyzed previously, there are quite a fair few attacks that can occur through the basic terminal itself. In our analysis itself, we noted 3603 iterations of the uname commands, 4 different ways to download files online, 275 different echo xsec's that test out the terminal — and that number has only gone up in the time of me writing this. So a rule that can detect an account logging in and quickly executing a list of discovery commands would be perfect for detecting any bots or human attackers.

```
<group name="command_line_execution,discovery_attacks">

<rule id="100005" level="5">  
<decoded_as>json</decoded_as>  
<field name="eventid">cowrie.command.input</field>   
<field name="input" type="pcre2">(?i)(uname|hostname|echo|export|scp|chmod)</field>  
<description>Cowrie possible attack: '$(input)' executed</description>  
<mitre>  
<id>T1059</id>  
</mitre>  
</rule>

<rule id="100006" level="11" frequency="3" timeframe="2">  
<if_matched_sid>100005</if_matched_sid>  
<same_field>src_ip</same_field>  
<description>Possible bot attack from $(src_ip)</description>  
<mitre>  
<id>T1059</id>  
</mitre>  
</rule>

<rule id="100007" level="14" frequency="3" timeframe="60">  
<same_field>src_ip</same_field>  
<if_matched_sid>100005</if_matched_sid>  
<description>Possible human attack from $(src_ip)</description>  
<mitre>  
<id>T1059</id>  
</mitre>  
</rule>

</group>
```

These rules follow the same logic and reasoning as the previous section. There is an initial rule which detects any discovery commands: 100005. These commands are not noteworthy by themselves, but if you somehow type them and execute three of them in less than two seconds, that's a cause for concern. This is rule 100006 does, a way to detect any bot attacks. However, if these attacks were executed 3 times in say 60 seconds, then it is more likely to be a human assisted attack — this is where rule 100007 registers the slow speed as a human trying to enter and warns us.

This rule has the same limitations as the rules for brute force attacks and there is a high chance of false positives from actual individuals using the terminal for their own commands. This rule unfortunately will not fire if any attackers use multiple discovery commands in one line by using && since this only fires rule 100005.

Let's test these and see if they appear on Wazuh. For this test, I will use these commands: "uname -s -v -n -r -m", "echo xsec", "hostname" and "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:", all of which are commands which are used by attackers on the honeypot — including the truncated PATH variable.

[Video of Rule Firing](/02_Rules_Writeup/Media/Wazuh%20Command%20Line%20Execution%20Rules.mp4)

Again, the rules work successfully and I am once again flagged correctly as a human. So no matter who logs in and tries to work around my system, I will get alerted on their activities and if they are a human or bot.

# Rule 3: Ingress File Transfer

Now, the third most common commands were always related to downloading a file or a piece of software on our honeypot. So the natural progression would now be to detect this, however, just adding a basic detection rule would be simple — I wanted to challenge myself. So not only does this rule detect any downloads and download commands being run, it also checks it against VirusTotal and does not get flagged if it is benign. 

```
<group name="honeypot,virus_detection,ingress_file_transfer">  
<rule id="100008" level="5">  
<decoded_as>json</decoded_as>  
<field name="eventid">cowrie.session.file_download</field>  
<description>Possible file downloaded, checking against VirusTotal</description>  
<mitre>  
<id>T1105</id>  
</mitre>  
</rule>
```

Now this is the rule that detects any downloads. To detect if these downloads are benign or malicious we can use two tools given to us by Wazuh and Cowrie. Firstly, Cowrie saves the hashes of all downloaded files. Secondly, Wazuh has a built in tool that allows for these hashes to go through VirusTotal with the help of an API to flag if it is benign, malicious or completely unknown. You can configure this on your own system by traversing to the ossec.conf file of your Wazuh settings.

```
<ossec_config>  
  <integration>  
    <name>custom-virustotal</name>  
    <api_key>API KEY</api_key>  
    <rule_id>100008</rule_id>  
    <alert_format>json</alert_format>  
  </integration>  
</ossec_config>
```

This allows for the VirusTotal integration to occur when rule 100008 is flagged. Depending on the result — benign, malicious and unknown — three different prepackaged Wazuh rules are flagged, saving me time to write rules for them. For this section, I made a completely new VirusTotal integration file. Normal VirusTotal integration looks at the provided logs and checks for a MD5 hash inside a syscheck field while Cowrie saves SHA-256 hashes in its shasum field. If the original integration was allowed to go through, my rule would never have fired. So I made a new integration named custom-virustotal to allow for the integration to use SHA-256 hashes inside the shasum block.

This rule however has a fatal limitation: it can run out. My VirusTotal API key has a very strict limit of 4 tests per minute and 500 per day. If an attacker were to download a huge burst of files all at once, then this rule would not work. Furthermore, an unknown file would also need help being filtered out further. This rule also cannot differentiate between a bot downloading or a human downloading as both have no differentiating factors.

Now that we have set up and defined the rule, let us now see it in action by using an EICAR file. EICAR test files are small strings of text that are designed to flag antiviruses for testing purposes, just like ours. So by using the EICAR.txt, let's see if our rule is flagged properly and integrated with VirusTotal or not.

[Video of Rule Firing](/02_Rules_Writeup/Media/Wazuh%20Ingress%20File%20Transfer%20Rule%20Firing.mp4)

Success, the rule fires and the file is checked against VirusTotal correctly. We have now implemented a basic download monitoring system through Wazuh.

# Conclusion;

We have now finally made custom rules for attackers. Not only do two of them detect any attacks, they also detect if a human or a robot is responsible for the attacks. Our final rule also implements a simple download monitoring system against any illegal downloads. Thank you for reading my writeup, hope you also visit my SOC Home Lab where I first started writing custom rules against my own attacks.