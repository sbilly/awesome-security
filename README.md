# Awesome Security

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A collection of awesome software, libraries, documents, books, resources and cool stuff about security.

Inspired by [awesome-php](https://github.com/ziadoz/awesome-php), [awesome-python](https://github.com/vinta/awesome-python).

Thanks to all [contributors](https://github.com/sbilly/awesome-security/graphs/contributors), you're awesome and wouldn't be possible without you! The goal is to build a categorized community-driven collection of very well-known resources.

- [Awesome Security](#awesome-security)
  - [Network](#network)
    - [Scanning / Pentesting](#scanning--pentesting)
    - [Monitoring / Logging](#monitoring--logging)
    - [IDS / IPS / Host IDS / Host IPS](#ids--ips--host-ids--host-ips)
    - [Honey Pot / Honey Net](#honey-pot--honey-net)
    - [Full Packet Capture / Forensic](#full-packet-capture--forensic)
    - [Sniffer](#sniffer)
    - [Security Information & Event Management](#security-information--event-management)
    - [VPN](#vpn)
    - [Fast Packet Processing](#fast-packet-processing)
    - [Firewall](#firewall)
    - [Anti-Spam](#anti-spam)
    - [Docker](#docker-images-for-penetration-testing--security)
  - [Endpoint](#endpoint)
    - [Anti-Virus / Anti-Malware](#anti-virus--anti-malware)
    - [Configuration Management](#configuration-management)
    - [Authentication](#authentication)
    - [Mobile / Android / iOS](#mobile--android--ios)
    - [Forensics](#forensics)
  - [Threat Intelligence](#threat-intelligence)
  - [Web](#web)
    - [Organization](#organization)
    - [Web Application Firewall](#web-application-firewall)
    - [Scanning / Pentesting](#scanning--pentesting-1)
    - [Runtime Application Self-Protection](#runtime-application-self-protection)
  - [Big Data](#big-data)
  - [DevOps](#devops)
  - [Other Awesome Lists](#other-awesome-lists)
    - [Other Security Awesome Lists](#other-security-awesome-lists)
    - [Other Common Awesome Lists](#other-common-awesome-lists)
  - [Contributing](#contributing)

------

## Network

### Scanning / Pentesting

- [OpenVAS](http://www.openvas.org/) - OpenVAS is a framework of several services and tools offering a comprehensive and powerful vulnerability scanning and vulnerability management solution.
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework) - A tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
- [Kali](https://www.kali.org/) - Kali Linux is a Debian-derived Linux distribution designed for digital forensics and penetration testing. Kali Linux is preinstalled with numerous penetration-testing programs, including nmap (a port scanner), Wireshark (a packet analyzer), John the Ripper (a password cracker), and Aircrack-ng (a software suite for penetration-testing wireless LANs).
- [pig](https://github.com/rafael-santiago/pig) - A Linux packet crafting tool.
- [scapy](https://github.com/secdev/scapy) - Scapy: the python-based interactive packet manipulation program & library.
- [Pompem](https://github.com/rfunix/Pompem) - Pompem is an open source tool, which is designed to automate the search for exploits in major databases. Developed in Python, has a system of advanced search, thus facilitating the work of pentesters and ethical hackers. In its current version, performs searches in databases: Exploit-db, 1337day, Packetstorm Security...
- [Nmap](https://nmap.org) - Nmap is a free and open source utility for network discovery and security auditing.

### Monitoring / Logging

- [snyk.io](https://snyk.io/) -  Snyk is a paid-for opensource tool to scan for vulnerabilities. Find, fix and monitor for known vulnerabilities in Node.js npm package fixtures used for testing the patches of vulndb.
- [justniffer](http://justniffer.sourceforge.net/) - Justniffer is a network protocol analyzer that captures network traffic and produces logs in a customized way, can emulate Apache web server log files, track response times and extract all "intercepted" files from the HTTP traffic.
- [httpry](http://dumpsterventures.com/jason/httpry/) - httpry is a specialized packet sniffer designed for displaying and logging HTTP traffic. It is not intended to perform analysis itself, but to capture, parse, and log the traffic for later analysis. It can be run in real-time displaying the traffic as it is parsed, or as a daemon process that logs to an output file. It is written to be as lightweight and flexible as possible, so that it can be easily adaptable to different applications.
- [ngrep](http://ngrep.sourceforge.net/) - ngrep strives to provide most of GNU grep's common features, applying them to the network layer. ngrep is a pcap-aware tool that will allow you to specify extended regular or hexadecimal expressions to match against data payloads of packets. It currently recognizes IPv4/6, TCP, UDP, ICMPv4/6, IGMP and Raw across Ethernet, PPP, SLIP, FDDI, Token Ring and null interfaces, and understands BPF filter logic in the same fashion as more common packet sniffing tools, such as tcpdump and snoop.
- [passivedns](https://github.com/gamelinux/passivedns) - A tool to collect DNS records passively to aid Incident handling, Network Security Monitoring (NSM) and general digital forensics. PassiveDNS sniffs traffic from an interface or reads a pcap-file and outputs the DNS-server answers to a log file. PassiveDNS can cache/aggregate duplicate DNS answers in-memory, limiting the amount of data in the logfile without loosing the essens in the DNS answer.
- [sagan](http://sagan.quadrantsec.com/) - Sagan uses a 'Snort like' engine and rules to analyze logs (syslog/event log/snmptrap/netflow/etc).
- [Node Security Platform](https://nodesecurity.io/) - Similar feature set to Snyk, but free in most cases, and very cheap for others.
- [ntopng](http://www.ntop.org/products/traffic-analysis/ntop/) - Ntopng is a network traffic probe that shows the network usage, similar to what the popular top Unix command does.
- [Fibratus](https://github.com/rabbitstack/fibratus) - Fibratus is a tool for exploration and tracing of the Windows kernel. It is able to capture the most of the Windows kernel activity - process/thread creation and termination, file system I/O, registry, network activity, DLL loading/unloading and much more. Fibratus has a very simple CLI which encapsulates the machinery to start the kernel event stream collector, set kernel event filters or run the lightweight Python modules called filaments.

### IDS / IPS / Host IDS / Host IPS

- [Snort](https://www.snort.org/) - Snort is a free and open source network intrusion prevention system (NIPS) and network intrusion detection system (NIDS)created by Martin Roesch in 1998. Snort is now developed by Sourcefire, of which Roesch is the founder and CTO. In 2009, Snort entered InfoWorld's Open Source Hall of Fame as one of the "greatest [pieces of] open source software of all time".
- [Bro](https://www.bro.org/) - Bro is a powerful network analysis framework that is much different from the typical IDS you may know.
- [OSSEC](https://ossec.github.io/) - Comprehensive Open Source HIDS. Not for the faint of heart. Takes a bit to get your head around how it works. Performs log analysis, file integrity checking, policy monitoring, rootkit detection, real-time alerting and active response. It runs on most operating systems, including Linux, MacOS, Solaris, HP-UX, AIX and Windows. Plenty of reasonable documentation. Sweet spot is medium to large deployments.
- [Suricata](http://suricata-ids.org/) - Suricata is a high performance Network IDS, IPS and Network Security Monitoring engine. Open Source and owned by a community run non-profit foundation, the Open Information Security Foundation (OISF). Suricata is developed by the OISF and its supporting vendors.
- [Security Onion](http://blog.securityonion.net/) - Security Onion is a Linux distro for intrusion detection, network security monitoring, and log management. It's based on Ubuntu and contains Snort, Suricata, Bro, OSSEC, Sguil, Squert, Snorby, ELSA, Xplico, NetworkMiner, and many other security tools. The easy-to-use Setup wizard allows you to build an army of distributed sensors for your enterprise in minutes!
- [sshwatch](https://github.com/marshyski/sshwatch) - IPS for SSH similar to DenyHosts written in Python.  It also can gather information about attacker during the attack in a log.
- [Stealth](https://fbb-git.github.io/stealth/) - File integrity checker that leaves virtually no sediment. Controller runs from another machine, which makes it hard for an attacker to know that the file system is being checked at defined pseudo random intervals over SSH. Highly recommended for small to medium deployments.
- [AIEngine](https://bitbucket.org/camp0/aiengine) - AIEngine is a next generation interactive/programmable Python/Ruby/Java/Lua packet inspection engine with capabilities of learning without any human intervention, NIDS(Network Intrusion Detection System) functionality, DNS domain classification, network collector, network forensics and many others.
- [Denyhosts](http://denyhosts.sourceforge.net/) - Thwart SSH dictionary based attacks and brute force attacks.
- [Fail2Ban](http://www.fail2ban.org/wiki/index.php/Main_Page) - Scans log files and takes action on IPs that show malicious behavior.
- [SSHGuard](http://www.sshguard.net/) - A software to protect services in addition to SSH, written in C

### Honey Pot / Honey Net

- [awesome-honeypots](https://github.com/paralax/awesome-honeypots) - The canonical awesome honeypot list.
- [HoneyPy](https://github.com/foospidy/HoneyPy) - HoneyPy is a low to medium interaction honeypot. It is intended to be easy to: deploy, extend functionality with plugins, and apply custom configurations.
- [Dionaea](http://dionaea.carnivore.it/) - Dionaea is meant to be a nepenthes successor, embedding python as scripting language, using libemu to detect shellcodes, supporting ipv6 and tls.
- [Conpot](http://conpot.org/) - ICS/SCADA Honeypot. Conpot is a low interactive server side Industrial Control Systems honeypot designed to be easy to deploy, modify and extend. By providing a range of common industrial control protocols we created the basics to build your own system, capable to emulate complex infrastructures to convince an adversary that he just found a huge industrial complex. To improve the deceptive capabilities, we also provided the possibility to server a custom human machine interface to increase the honeypots attack surface. The response times of the services can be artificially delayed to mimic the behaviour of a system under constant load. Because we are providing complete stacks of the protocols, Conpot can be accessed with productive HMI's or extended with real hardware. Conpot is developed under the umbrella of the Honeynet Project and on the shoulders of a couple of very big giants.
- [Amun](https://github.com/zeroq/amun) - Amun Python-based low-interaction Honeypot.
- [Glastopf](http://glastopf.org/) - Glastopf is a Honeypot which emulates thousands of vulnerabilities to gather data from attacks targeting web applications. The principle behind it is very simple: Reply the correct response to the attacker exploiting the web application.
- [Kippo](https://github.com/desaster/kippo) - Kippo is a medium interaction SSH honeypot designed to log brute force attacks and, most importantly, the entire shell interaction performed by the attacker.
- [Kojoney](http://kojoney.sourceforge.net/) - Kojoney is a low level interaction honeypot that emulates an SSH server. The daemon is written in Python using the Twisted Conch libraries.
- [HonSSH](https://github.com/tnich/honssh) - HonSSH is a high-interaction Honey Pot solution. HonSSH will sit between an attacker and a honey pot, creating two separate SSH connections between them.
- [Bifrozt](http://sourceforge.net/projects/bifrozt/) - Bifrozt is a NAT device with a DHCP server that is usually deployed with one NIC connected directly to the Internet and one NIC connected to the internal network. What differentiates Bifrozt from other standard NAT devices is its ability to work as a transparent SSHv2 proxy between an attacker and your honeypot. If you deployed an SSH server on Bifrozt’s internal network it would log all the interaction to a TTY file in plain text that could be viewed later and capture a copy of any files that were downloaded. You would not have to install any additional software, compile any kernel modules or use a specific version or type of operating system on the internal SSH server for this to work. It will limit outbound traffic to a set number of ports and will start to drop outbound packets on these ports when certain limits are exceeded.
- [HoneyDrive](http://bruteforce.gr/honeydrive) - HoneyDrive is the premier honeypot Linux distro. It is a virtual appliance (OVA) with Xubuntu Desktop 12.04.4 LTS edition installed. It contains over 10 pre-installed and pre-configured honeypot software packages such as Kippo SSH honeypot, Dionaea and Amun malware honeypots, Honeyd low-interaction honeypot, Glastopf web honeypot and Wordpot, Conpot SCADA/ICS honeypot, Thug and PhoneyC honeyclients and more. Additionally it includes many useful pre-configured scripts and utilities to analyze, visualize and process the data it can capture, such as Kippo-Graph, Honeyd-Viz, DionaeaFR, an ELK stack and much more. Lastly, almost 90 well-known malware analysis, forensics and network monitoring related tools are also present in the distribution.
- [Cuckoo Sandbox](http://www.cuckoosandbox.org/) - Cuckoo Sandbox is an Open Source software for automating analysis of suspicious files. To do so it makes use of custom components that monitor the behavior of the malicious processes while running in an isolated environment.

### Full Packet Capture / Forensic

- [tcpflow](https://github.com/simsong/tcpflow) - tcpflow is a program that captures data transmitted as part of TCP connections (flows), and stores the data in a way that is convenient for protocol analysis and debugging. Each TCP flow is stored in its own file. Thus, the typical TCP flow will be stored in two files, one for each direction. tcpflow can also process stored 'tcpdump' packet flows.
- [Xplico](http://www.xplico.org/) - The goal of Xplico is extract from an internet traffic capture the applications data contained. For example, from a pcap file Xplico extracts each email (POP, IMAP, and SMTP protocols), all HTTP contents, each VoIP call (SIP), FTP, TFTP, and so on. Xplico isn’t a network protocol analyzer. Xplico is an open source Network Forensic Analysis Tool (NFAT).
- [Moloch](https://github.com/aol/moloch) - Moloch is an open source, large scale IPv4 packet capturing (PCAP), indexing and database system. A simple web interface is provided for PCAP browsing, searching, and exporting. APIs are exposed that allow PCAP data and JSON-formatted session data to be downloaded directly. Simple security is implemented by using HTTPS and HTTP digest password support or by using apache in front. Moloch is not meant to replace IDS engines but instead work along side them to store and index all the network traffic in standard PCAP format, providing fast access. Moloch is built to be deployed across many systems and can scale to handle multiple gigabits/sec of traffic.
- [OpenFPC](http://www.openfpc.org) - OpenFPC is a set of tools that combine to provide a lightweight full-packet network traffic recorder & buffering system. It's design goal is to allow non-expert users to deploy a distributed network traffic recorder on COTS hardware while integrating into existing alert and log management tools.
- [Dshell](https://github.com/USArmyResearchLab/Dshell) - Dshell is a network forensic analysis framework. Enables rapid development of plugins to support the dissection of network packet captures.
- [stenographer](https://github.com/google/stenographer) - Stenographer is a packet capture solution which aims to quickly spool all packets to disk, then provide simple, fast access to subsets of those packets.

### Sniffer

- [wireshark](https://www.wireshark.org) - Wireshark is a free and open-source packet analyzer. It is used for network troubleshooting, analysis, software and communications protocol development, and education. Wireshark is very similar to tcpdump, but has a graphical front-end, plus some integrated sorting and filtering options.
- [netsniff-ng](http://netsniff-ng.org/) -  netsniff-ng is a free Linux networking toolkit, a Swiss army knife for your daily Linux network plumbing if you will. Its gain of performance is reached by zero-copy mechanisms, so that on packet reception and transmission the kernel does not need to copy packets from kernel space to user space and vice versa.
- [Live HTTP headers](https://chrome.google.com/webstore/detail/live-http-headers/iaiioopjkcekapmldfgbebdclcnpgnlo?utm_source=chrome-ntp-icon) - Live HTTP headers is a free chrome extension to see your browser requests in real time. It shows the entire headers of the requests and can be used to find the security loopholes in implementations.

### Security Information & Event Management

- [Prelude](https://www.prelude-ids.org/) - Prelude is a Universal "Security Information & Event Management" (SIEM) system. Prelude collects, normalizes, sorts, aggregates, correlates and reports all security-related events independently of the product brand or license giving rise to such events; Prelude is "agentless".
- [OSSIM](https://www.alienvault.com/open-threat-exchange/projects) - OSSIM provides all of the features that a security professional needs from a SIEM offering – event collection, normalization, and correlation.
- [FIR](https://github.com/certsocietegenerale/FIR) - Fast Incident Response, a cybersecurity incident management platform.

### VPN

- [OpenVPN](https://openvpn.net/) - OpenVPN is an open source software application that implements virtual private network (VPN) techniques for creating secure point-to-point or site-to-site connections in routed or bridged configurations and remote access facilities. It uses a custom security protocol that utilizes SSL/TLS for key exchange.

### Fast Packet Processing

- [DPDK](http://dpdk.org/) - DPDK is a set of libraries and drivers for fast packet processing.
- [PFQ](https://github.com/pfq/PFQ) - PFQ is a functional networking framework designed for the Linux operating system that allows efficient packets capture/transmission (10G and beyond), in-kernel functional processing and packets steering across sockets/end-points.
- [PF_RING](http://www.ntop.org/products/packet-capture/pf_ring/) - PF_RING is a new type of network socket that dramatically improves the packet capture speed.
- [PF_RING ZC (Zero Copy)](http://www.ntop.org/products/packet-capture/pf_ring/pf_ring-zc-zero-copy/) - PF_RING ZC (Zero Copy) is a flexible packet processing framework that  allows you to achieve 1/10 Gbit line rate packet processing (both RX and TX) at any packet size. It implements zero copy operations including patterns for inter-process and inter-VM (KVM) communications.
- [PACKET_MMAP/TPACKET/AF_PACKET](http://lxr.free-electrons.com/source/Documentation/networking/packet_mmap.txt) - It's fine to use PACKET_MMAP to improve the performance of the capture and transmission process in Linux.
- [netmap](http://info.iet.unipi.it/~luigi/netmap/) - netmap is a framework for high speed packet I/O. Together with its companion VALE software switch, it is implemented as a single kernel module and available for FreeBSD, Linux and now also Windows.

### Firewall
- [pfSense](https://www.pfsense.org/) - Firewall and Router FreeBSD distribution.
- [fwknop](https://www.cipherdyne.org/fwknop/) - Protects ports via Single Packet Authorization in your firewall.

### Anti-Spam
- [SpamAssassin](https://spamassassin.apache.org/) - A powerful and popular email spam filter employing a variety of detection technique.


### Docker Images for Penetration Testing & Security
- `docker pull kalilinux/kali-linux-docker` [official Kali Linux](https://hub.docker.com/r/kalilinux/kali-linux-docker/)
- `docker pull owasp/zap2docker-stable` - [official OWASP ZAP](https://github.com/zaproxy/zaproxy)
- `docker pull wpscanteam/wpscan` - [official WPScan](https://hub.docker.com/r/wpscanteam/wpscan/)
- `docker pull remnux/metasploit` - [docker-metasploit](https://hub.docker.com/r/remnux/metasploit/)
- `docker pull citizenstig/dvwa` - [Damn Vulnerable Web Application (DVWA)](https://hub.docker.com/r/citizenstig/dvwa/)
- `docker pull wpscanteam/vulnerablewordpress` - [Vulnerable WordPress Installation](https://hub.docker.com/r/wpscanteam/vulnerablewordpress/)
- `docker pull hmlio/vaas-cve-2014-6271` - [Vulnerability as a service: Shellshock](https://hub.docker.com/r/hmlio/vaas-cve-2014-6271/)
- `docker pull hmlio/vaas-cve-2014-0160` - [Vulnerability as a service: Heartbleed](https://hub.docker.com/r/hmlio/vaas-cve-2014-0160/)
- `docker pull opendns/security-ninjas` - [Security Ninjas](https://hub.docker.com/r/opendns/security-ninjas/)
- `docker pull usertaken/archlinux-pentest-lxde` - [Arch Linux Penetration Tester](https://hub.docker.com/r/usertaken/archlinux-pentest-lxde/)
- `docker pull diogomonica/docker-bench-security` - [Docker Bench for Security](https://hub.docker.com/r/diogomonica/docker-bench-security/)
- `docker pull ismisepaul/securityshepherd` - [OWASP Security Shepherd](https://hub.docker.com/r/ismisepaul/securityshepherd/)
- `docker pull danmx/docker-owasp-webgoat` - [OWASP WebGoat Project docker image](https://hub.docker.com/r/danmx/docker-owasp-webgoat/)
- `docker pull citizenstig/nowasp` - [OWASP Mutillidae II Web Pen-Test Practice Application](https://hub.docker.com/r/citizenstig/nowasp/)


## Endpoint

### Anti-Virus / Anti-Malware

- [Linux Malware Detect](https://www.rfxn.com/projects/linux-malware-detect/) - A malware scanner for Linux designed around the threats faced in shared hosted environments.

### Configuration Management

- [Rudder](http://www.rudder-project.org/) - Rudder is an easy to use, web-driven, role-based solution for IT Infrastructure Automation & Compliance. Automate common system administration tasks (installation, configuration); Enforce configuration over time (configuring once is good, ensuring that configuration is valid and automatically fixing it is better); Inventory of all managed nodes; Web interface to configure and manage nodes and their configuration; Compliance reporting, by configuration and/or by node.

### Authentication

- [google-authenticator](https://github.com/google/google-authenticator) - The Google Authenticator project includes implementations of one-time passcode generators for several mobile platforms, as well as a pluggable authentication module (PAM). One-time passcodes are generated using open standards developed by the Initiative for Open Authentication (OATH) (which is unrelated to OAuth). These implementations support the HMAC-Based One-time Password (HOTP) algorithm specified in RFC 4226 and the Time-based One-time Password (TOTP) algorithm specified in RFC 6238. [Tutorials: How to set up two-factor authentication for SSH login on Linux](http://xmodulo.com/two-factor-authentication-ssh-login-linux.html)

### Mobile / Android / iOS

- [android-security-awesome](https://github.com/ashishb/android-security-awesome) - A collection of android security related resources. A lot of work is happening in academia and industry on tools to perform dynamic analysis, static analysis and reverse engineering of android apps.
- [SecMobi Wiki](http://wiki.secmobi.com/) - A collection of mobile security resources which including articles, blogs, books, groups, projects, tools and conferences. *

### Forensics

- [grr](https://github.com/google/grr) - GRR Rapid Response is an incident response framework focused on remote live forensics.
- [Volatility](https://github.com/volatilityfoundation/volatility) - Python based memory extraction and analysis framework.
- [mig](http://mig.mozilla.org/) - MIG is a platform to perform investigative surgery on remote endpoints. It enables investigators to obtain information from large numbers of systems in parallel, thus accelerating investigation of incidents and day-to-day operations security.


## Threat Intelligence

- [abuse.ch](https://www.abuse.ch/) - ZeuS Tracker / SpyEye Tracker / Palevo Tracker / Feodo Tracker tracks Command&Control servers (hosts) around the world and provides you a domain- and an IP-blocklist.
- [Emerging Threats - Open Source](http://www.emergingthreats.net/open-source) - Emerging Threats began 10 years ago as an open source community for collecting Suricata and SNORT® rules, firewall rules, and other IDS rulesets. The open source community still plays an active role in Internet security, with more than 200,000 active users downloading the ruleset daily. The ETOpen Ruleset is open to any user or organization, as long as you follow some basic guidelines. Our ETOpen Ruleset is available for download any time.
- [PhishTank](http://www.phishtank.com/) - PhishTank is a collaborative clearing house for data and information about phishing on the Internet. Also, PhishTank provides an open API for developers and researchers to integrate anti-phishing data into their applications at no charge.
- [SBL / XBL / PBL / DBL / DROP / ROKSO](http://www.spamhaus.org/) - The Spamhaus Project is an international nonprofit organization whose mission is to track the Internet's spam operations and sources, to provide dependable realtime anti-spam protection for Internet networks, to work with Law Enforcement Agencies to identify and pursue spam and malware gangs worldwide, and to lobby governments for effective anti-spam legislation.
- [Internet Storm Center](https://www.dshield.org/reports.html) - The ISC was created in 2001 following the successful detection, analysis, and widespread warning of the Li0n worm. Today, the ISC provides a free analysis and warning service to thousands of Internet users and organizations, and is actively working with Internet Service Providers to fight back against the most malicious attackers.
- [AutoShun](https://www.autoshun.org/) - AutoShun is a Snort plugin that allows you to send your Snort IDS logs to a centralized server that will correlate attacks from your sensor logs with other snort sensors, honeypots, and mail filters from around the world.
- [DNS-BH](http://www.malwaredomains.com/) - The DNS-BH project creates and maintains a listing of domains that are known to be used to propagate malware and spyware. This project creates the Bind and Windows zone files required to serve fake replies to localhost for any requests to these, thus preventing many spyware installs and reporting.
- [AlienVault Open Threat Exchange](http://www.alienvault.com/open-threat-exchange/dashboard) - AlienVault Open Threat Exchange (OTX), to help you secure your networks from data loss, service disruption and system compromise caused by malicious IP addresses.
- [Tor Bulk Exit List](https://collector.torproject.org/) - CollecTor, your friendly data-collecting service in the Tor network. CollecTor fetches data from various nodes and services in the public Tor network and makes it available to the world. If you're doing research on the Tor network, or if you're developing an application that uses Tor network data, this is your place to start. [TOR Node List](https://www.dan.me.uk/tornodes) /  [DNS Blacklists](https://www.dan.me.uk/dnsbl) / [Tor Node List](http://torstatus.blutmagie.de/)
- [leakedin.com](http://www.leakedin.com/) - The primary purpose of leakedin.com is to make visitors aware about the risks of loosing data. This blog just compiles samples of data lost or disclosed on sites like pastebin.com.
- [FireEye OpenIOCs](https://github.com/fireeye/iocs) - FireEye Publicly Shared Indicators of Compromise (IOCs)
- [OpenVAS NVT Feed](http://www.openvas.org/openvas-nvt-feed.html) - The public feed of Network Vulnerability Tests (NVTs). It contains more than 35,000 NVTs (as of April 2014), growing on a daily basis. This feed is configured as the default for OpenVAS.
- [Project Honey Pot](http://www.projecthoneypot.org/) - Project Honey Pot is the first and only distributed system for identifying spammers and the spambots they use to scrape addresses from your website. Using the Project Honey Pot system you can install addresses that are custom-tagged to the time and IP address of a visitor to your site. If one of these addresses begins receiving email we not only can tell that the messages are spam, but also the exact moment when the address was harvested and the IP address that gathered it.
- [virustotal](https://www.virustotal.com/) - VirusTotal, a subsidiary of Google, is a free online service that analyzes files and URLs enabling the identification of viruses, worms, trojans and other kinds of malicious content detected by antivirus engines and website scanners. At the same time, it may be used as a means to detect false positives, i.e. innocuous resources detected as malicious by one or more scanners.
- [IntelMQ](https://github.com/certtools/intelmq/) - IntelMQ is a solution for CERTs for collecting and processing security feeds, pastebins, tweets using a message queue protocol. It's a community driven initiative called IHAP (Incident Handling Automation Project) which was conceptually designed by European CERTs during several InfoSec events. Its main goal is to give to incident responders an easy way to collect & process threat intelligence thus improving the incident handling processes of CERTs. [ENSIA Homepage](https://www.enisa.europa.eu/activities/cert/support/incident-handling-automation).
- [CIFv2](https://github.com/csirtgadgets/massive-octo-spice) - CIF is a cyber threat intelligence management system. CIF allows you to combine known malicious threat information from many sources and use that information for identification (incident response), detection (IDS) and mitigation (null route).
- [CriticalStack](https://intel.criticalstack.com/) - Free aggregated threat intel for the Bro network security monitoring platform.

## Web

### Organization

- [OWASP](http://www.owasp.org) - The Open Web Application Security Project (OWASP) is a 501(c)(3) worldwide not-for-profit charitable organization focused on improving the security of software.

### Web Application Firewall

- [ModSecurity](http://www.modsecurity.org/) - ModSecurity is a toolkit for real-time web application monitoring, logging, and access control.
- [NAXSI](https://github.com/nbs-system/naxsi) - NAXSI is an open-source, high performance, low rules maintenance WAF for NGINX, NAXSI means Nginx Anti Xss & Sql Injection.
- [ironbee](https://www.ironbee.com/) - IronBee is an open source project to build a universal web application security sensor. IronBee as a framework for developing a system for securing web applications - a framework for building a web application firewall (WAF).

### Scanning / Pentesting

- [sqlmap](http://sqlmap.org/) - sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.
- [ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - The Zed Attack Proxy (ZAP) is an easy to use integrated penetration testing tool for finding vulnerabilities in web applications. It is designed to be used by people with a wide range of security experience and as such is ideal for developers and functional testers who are new to penetration testing. ZAP provides automated scanners as well as a set of tools that allow you to find security vulnerabilities manually.
- [w3af](http://w3af.org/) - w3af is a Web Application Attack and Audit Framework. The project’s goal is to create a framework to help you secure your web applications by finding and exploiting all web application vulnerabilities.
- [Recon-ng](https://bitbucket.org/LaNMaSteR53/recon-ng) - Recon-ng is a full-featured Web Reconnaissance framework written in Python. Recon-ng has a look and feel similar to the Metasploit Framework.
- [PTF](https://github.com/trustedsec/ptf) - The Penetration Testers Framework (PTF) is a way for modular support for up-to-date tools.

### Runtime Application Self-Protection

- [Sqreen](https://www.sqreen.io/) - Sqreen is a Runtime Application Self-Protection (RASP) solution for software teams. An in-app agent instruments and monitors the app. Suspicious user activities are reported and attacks are blocked at runtime without code modification or traffic redirection.

## Big Data

- [data_hacking](https://github.com/ClickSecurity/data_hacking) - Examples of using IPython, Pandas, and Scikit Learn to get the most out of your security data.
- [hadoop-pcap](https://github.com/RIPE-NCC/hadoop-pcap) - Hadoop library to read packet capture (PCAP) files.
- [Workbench](http://workbench.readthedocs.org/) - A scalable python framework for security research and development teams.
- [OpenSOC](https://github.com/OpenSOC/opensoc) - OpenSOC integrates a variety of open source big data technologies in order to offer a centralized tool for security monitoring and analysis.
- [binarypig](https://github.com/endgameinc/binarypig) - Scalable Binary Data Extraction in Hadoop. Malware Processing and Analytics over Pig, Exploration through Django, Twitter Bootstrap, and Elasticsearch.

## DevOps

- [Securing DevOps](https://manning.com/books/securing-devops?a_aid=securingdevops&a_bid=1353bcd8) - A book on Security techniques for DevOps that reviews state of the art practices used in securing web applications and their infrastructure.

## Datastores

- [Vault](https://www.vaultproject.io/) - An encrypted datastore secure enough to hold environment and application secrets.
- [Safe](https://github.com/starkandwayne/safe) - A Vault CLI that makes reading from and writing to the Vault easier to do.
- [Sops](https://github.com/mozilla/sops - An editor of encrypted files that supports YAML, JSON and BINARY formats and encrypts with AWS KMS and PGP.

## Other Awesome Lists

### Other Security Awesome Lists

- [Android Security Awesome](https://github.com/ashishb/android-security-awesome) - A collection of android security related resources.
- [Awesome CTF](https://github.com/apsdehal/awesome-ctf) - A curated list of CTF frameworks, libraries, resources and software.
- [Awesome Cyber Skills](https://github.com/joe-shenouda/awesome-cyber-skills) - A curated list of hacking environments where you can train your cyber skills legally and safely.
- [Awesome Hacking](https://github.com/carpedm20/awesome-hacking) - A curated list of awesome Hacking tutorials, tools and resources.
- [Awesome Honeypots](https://github.com/paralax/awesome-honeypots) - An awesome list of honeypot resources.
- [Awesome Malware Analysis](https://github.com/rshipp/awesome-malware-analysis) - A curated list of awesome malware analysis tools and resources.
- [Awesome PCAP Tools](https://github.com/caesar0301/awesome-pcaptools) - A collection of tools developed by other researchers in the Computer Science area to process network traces.
- [Awesome Pentest](https://github.com/enaqx/awesome-pentest) - A collection of awesome penetration testing resources, tools and other shiny things.
- [Awesome Linux Containers](https://github.com/Friz-zy/awesome-linux-containers) - A curated list of awesome Linux Containers frameworks, libraries and software.
- [Awesome Incident Response](https://github.com/meirwah/awesome-incident-response) - A curated list of resources for incident response.
- [Awesome Web Hacking](https://github.com/infoslack/awesome-web-hacking) - This list is for anyone wishing to learn about web application security but do not have a starting point.
- [Best of StackOverflow](https://github.com/NimitS1/best_of_stackoverflow) - A curated list of best security questions on Information Security stackexchange.

### Other Common Awesome Lists

Other amazingly awesome lists:

- [awesome-awesomeness](https://github.com/bayandin/awesome-awesomeness) - awesome-* or *-awesome lists.
- [lists](https://github.com/jnv/lists) - The definitive list of (awesome) lists curated on GitHub.

## [Contributing](contributing.md)

Your contributions are always welcome!
