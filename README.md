# Network-Security

### Security Control Types
- The concept of defense in depth can be broken down into three different security control types. Identify the security control type of each set of defense tactics.
  * Walls, bollards, fences, guard dogs, cameras, and lighting are what type of security control? `Preventative - Phyiscal`
  * Security awareness programs, BYOD policies, and ethical hiring practices are what type of security control? `Administrative`
  * Encryption, biometric fingerprint readers, firewalls, endpoint security, and intrusion detection systems are what type of security control? `Technical`

### Intrusion Detection & Attack Indicators
- What's the difference between an IDS and an IPS?
  * `An IPS is an active system that does everything that an IDS can do, but can also respond to attacks whereas an IDS is a passive system that logs attacks.`
- What's the difference between an Indicator of Attack and an Indicator of Compromise?
  * `ndicators of attack indicate attacks happening in real time. Indicators of compromise indicate previous malicious activity.`

### Cyber Kill Chain
- Name each of the seven stages for the Cyber Kill chain and provide a brief example of each.
  * Stage 1: Reconnaissance - The attacker gathers the necessary information during the reconnaissance step. Hackers select the victim, conduct in-depth research of the company, and look for weak points in the target network.
  * Stage 2: Weaponization - The attacker team found a weak point in the system and knows how to create an entry point. The criminal team now designs a virus or a worm to target the weakness. If attackers found a zero-day exploit, they typically work fast before the victim discovers and fixes the vulnerability.
  * Stage 3: Delivery - Criminals launch the attack into the target environment. This can often be through phishing attacks, exploiting a hardware or software flaw, compromised user accounts, a drive-by download that installs malware alongside a regular program. Direct hacking through an open port or other external access point. The goal of this step is to breach the system and silently establish a foothold.
  * Stage 4: Installation - This is when the malware installs on the network. Once the malware installs, intruders get access to the network. Keeping their presence secret is critical for attackers. Intruders typically wipe files and metadata, overwrite data with false timestamps, and modify documents to remain undetected.
  * Stage 5: Lateral Move - Intruders move laterally to other systems and accounts on the network. The goal is to gain higher permissions and reach more data. Standard techniques during this stage are exploiting password vulnerabilities, brute force attacks, credential extraction, and/ or targeting further system vulnerabilities.
  * Stage 6: Command and Control - Complex malware requires manual interaction to operate, so attackers need keyboard access to the target environment. The last step before the execution phase is to establish a command-and-control channel (C2) with an external server. Hackers typically achieve C2 via a beacon over an external network path. Beacons are usually HTTP or HTTPS-based and appear as ordinary traffic due to falsified HTTP headers. If data exfiltration is the attack’s goal, intruders start placing target data into bundles during the C2 phase. A typical location for data bundles is a part of the network with little to no activity or traffic.
  * Stage 7: Execution - Intruders take action to fulfill the attack’s purpose. Immediately before an attack starts, intruders cover their tracks by causing chaos across the network. Some criminals also launch another DDoS attack to distract the security controls while extracting data.

### SNORT Rule Analysis
- Use the Snort rule to answer the following questions:
**SNORT Rule #1**
`alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"ET SCAN Potential VNC Scan 5800-5820"; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2002910; classtype:attempted-recon; sid:2002910; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)`
  * Alert on a device with an external IP address attempting to remotely control a computer on home ports 5800 and 5820, indicating botnet attack.
  * Alert violates Recon stage of Cyber Kill Chain
  * an IOC attack is indicated
**SNORT Rule #2**
`lert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET POLICY PE EXE or DLL Windows file download HTTP"; flow:established,to_client; flowbits:isnotset,ET.http.binary; flowbits:isnotset,ET.INFO.WindowsUpdate; file_data; content:"MZ"; within:2; byte_jump:4,58,relative,little; content:"PE|00 00|"; distance:-64; within:4; flowbits:set,ET.http.binary; metadata: former_category POLICY; reference:url,doc.emergingthreats.net/bin/view/Main/2018959; classtype:policy-violation; sid:2018959; rev:4; metadata:created_at 2014_08_19, updated_at 2017_02_01;)`
  * A program was downloaded that violates SNORT policy
  * Alert violates Application layer of Defense in Depth model
  * Policy violation attack indicated
**SNORT Rule #3**
  * Write a Snort rule that alerts when traffic is detected inbound on port 4444 to the local network on any port. Be sure to include the msg in the Rule Option.
  * `alert ip any any -> any 4444 {msg: "Traffic on Port 4444 detected";}`

### "Drop Zone" Lab
- Login to Azure `firewalld` machine
- Uninstall `ufw`
- Run `$ sudo ufw disable` to remove any running instances of ufw.
- Enable and start firewalld with:
```
$ sudo sysctl enable firewalld
$ sudo /etc/init.d/firewalld start
```
- Confirm service is running with: `sudo /etc/init.d/firewalld status`
- List any currently configured firewall rules: `sudo firewall-cmd --list-all-zones`
- List supported service types that can be enabled: `sudo firewall-cmd --get-services`
- Zone views: `sudo firewall-cmd --list-all-zones`
- Create Zones for Web, Sales, and Mail:
```
$  firewall-cmd --new-zone=Web --permanent
$  firewall-cmd --new-zone=Sales --permanent
$  firewall-cmd --new-zone=Mail --permanent
```
- Set zones to designated interfaces:
```
$ sudo firewall-cmd --zone=Web --change-interface=eth1  --permanent
$ sudo firewall-cmd --zone=Sales --change-interface=eth1  --permanent
$ sudo firewall-cmd --zone=Mail --change-interface=eth1  --permanent
```
- Add services to active zones:
  * Public:
  ```
  $ firewall-cmd --zone=public --add-service=http  --permanent
  $ firewall-cmd --zone=public --add-service=https  --permanent
  $ firewall-cmd --zone=public --add-service=smtp  --permanent
  $ firewall-cmd --zone=public --add-service=pop3  --permanent
  ```
  * Web: `$ firewall-cmd --zone=Web --add-service=https --permanent`
  * Sales: `$ firewall-cmd --zone=Sales --add-service=https --permanent`
  * Mail:
  ```
  $  firewall-cmd --zone=Mail --add-service=stmp --permanent
  $  firewall-cmd --zone=Mail --add-service=pop3 --permanent
  ```
  * Statuses of HTTP, HTTPS, and SMTP are all `open`
- Adding adversaries - Run the command that will add all current and any future blacklisted IPs to the Drop Zone:
```
$ firewall-cmd --new-ipset=blacklist --type=hash:net --option=family=inet --option=hashsize=4096 --option=maxelem=200000 --permanent
$ firewall-cmd --ipset=ipv4blacklist --add-entry=192.168.0.5 --permanent
$ firewall-cmd --zone=drop --add-source=ipset:blacklist --permanent
```
- Make rules permanent then reload them (It's good practice to ensure that your firewalld installation remains nailed up and retains its services across reboots. This ensure that the network remains secured after unplanned outages such as power failures):
`$ firewall-cmd --reload`
- View active Zones: `$ sudo firewall-cmd --list-services`
- Block IP address 138.138.0.3: `$ sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="138.138.0.3" reject`
- Block Ping & ICMP Requests: `$ sudo firewall-cmd --zone=public --add-icmp-block={echo-request,echo-reply,timestamp-reply,timestamp-request} --permanent	`
- Rule Check - verify all settings have ataken effect:
```
$  sudo firewall-cmd --zone=public --list-all
$  sudo firewall-cmd --zone=Web --list-all
$  sudo firewall-cmd --zone=Sales --list-all
$  sudo firewall-cmd --zone=Zone --list-all
$  sudo firewall-cmd --zone=drop --list-all
```

### IDS, IPS, DiD, and Firewalls
- IDS vs. IPS Systems
  * An IDS connects to a network via perimeter or host
  * An IPS connects with the flow of data usually placed between the network switch and firewall
  * Signature type IDS compares patterns of traffic to predefined signatures and is unable to detect Zero-Day attacks
  * Anomaly type IDS is beneficial for detecting all suspicious traffic that deviates from the well-known baseline and is excellent at detecting when an attacker probes or sweeps a network

### Defense in Depth
- For each of the following scenarios, provide the layer of Defense in Depth that applies:
  * A criminal hacker tailgates an employee through an exterior door into a secured facility, explaining that they forgot their badge at home: `Physical`
  * A zero-day goes undetected by antivirus software: `Application`
  * A criminal successfully gains access to HR’s database: `Data`
  * A criminal hacker exploits a vulnerability within an operating system: `Host`
  * A hacktivist organization successfully performs a DDoS attack, taking down a government website: `Network`
  * Data is classified at the wrong classification level: `Policy`
  * A state sponsored hacker group successfully firewalked an organization to produce a list of active services on an email server: `Perimeter`
- Name one method of protecting data-at-rest from being readable on hard drive: `Encryption key`
- Name one method to protect data-in-transit: `TLS encrpytion or VPN with IPSEC`
- What technology could provide law enforcement with the ability to track and recover a stolen laptop: `GPS`
- How could you prevent an attacker from booting a stolen laptop using an external hard drive? `Enabble firmware password or disable USB ports`

### Firewall Architectures & Methodologies
- Which type of firewall verifies the three-way TCP handshake? TCP handshake checks are designed to ensure that session packets are from legitimate sources: `Circuit level or proxy firewalls`
- Which type of firewall considers the connection as a whole? Meaning, instead of looking at only individual packets, these firewalls look at whole streams of packets at one time: `Stateful firewalls`
- Which type of firewall intercepts all traffic prior to being forwarded to its final destination. In a sense, these firewalls act on behalf of the recipient by ensuring the traffic is safe prior to forwarding it? `Application or Proxy firewalls`
- Which type of firewall examines data within a packet as it progresses through a network interface by examining source and destination IP address, port number, and packet type- all without opening the packet to inspect its contents? `Stateless firewalls`
- Which type of firewall filters based solely on source and destination MAC address? ` MAC layer filtering firewalls`

