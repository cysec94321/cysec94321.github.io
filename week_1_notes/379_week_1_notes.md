---

title: Week 1 Notes
layout: md

---

*SIT379 Ethical Hacking*

# Week 1:

### Ciphers

**ROT13**
	- Rotation cipher
	- Default is 'ROT13'
	- Assigns one number to each letter of alphabet 1=A, 2=B, 3=C etc.
	- ROT 13; 14=A, 15=B, 16=C.
	- Can use cyber chef to brute-force cipher and decode message 

### Privacy vs Security:

**Security**
- CIA Triad
	- Confidentiality
	- Integrity
	- Availability

**Privacy**
- Data protection regulations
- Consent
- Individual rights

**Hacking**
- Exploiting system vulnerabilities and compromising security controls to obtain unauthorised or inappropriate access to a system's resources.
- Modifying systems or data to accomplish objectives beyond their original purpose. It may involve activities aimed at unauthorised access to, theft of, or redistribution of intellectual property, consequently resulting in financial losses for businesses.

## Hacking Frameworks:

### CEH Hacking Methodology (CHM)

![[Pasted image 20240714234824.png]]

- **Footprinting**
	- Gain extensive information about the target prior to the attack.
	- Create a profile of the target organisation.
		- IP ranges
		- Namespaces
		- Employee Information

- **Scanning**
	- Extension of recon/footprinting
		- Identify active hosts
		- Identify open ports
		- Identify services on particular hosts

- **Enumeration**
	- Intrusive probing to gather information
		- Network user lists
		- Routing Tables 
		- Security flaws/vulnerabilities
		- Shared users/Groups
		- Applications
		- Banners
	- Involves making active connections to a target system or subjecting it to direct queries.

- **Vulnerability Analysis
	- Scrutinising the system or service and assessing its security measures to determine its resilience to types of attacks.
	- Discover security weaknesses and gaps in a target network, infrastructure or endpoints. 
	- List out potential entry points for attacks/attackers.\

-**Gaining Access:**
	- The attack/hacking phase. 
	- Use the information collected in previous steps and use techniques, from 2 categories; *password cracking* and/or *vulnerability exploitation*, to access the target system.
	- Success dependent on many variables:
		- System's architecture
		- Perpetrator skill level
		- Level of initial access required

- **Escalating Privileges**
	- Following initial access through a low-priv user account, attackers commonly seek out to escalate their privileges to an admin/root level.
	- Use known system vulnerabilities.
	- Allows undertaking of secondary operations.

- **Maintaining Access:**
	- **Executing Applications:**
		- Once admin privileges are achieved.
		- Install malware (trojans, backdoors, rootkits, keyloggers, etc.)
		- Achieve persistence and remote system access.

	- **Hiding Files:**
		- Attempt to hide evidence of malware to ensure persistence.

- **Clearing Logs:** 
	- **Covering Tracks:**
		- To remain undetected, attackers can erase all evidence of the breach and system compromise.
		- Limits evidence gathering, makes harder to identify/track malicious behaviour or the threat actor.
		- Can modify or delete logs within the system. (Manually or with log-wiping utilities).

### Cyber Kill Chain (Lockheed Martin)

The model identifies what the adversaries must complete in order to achieve their objective.
#### 1. Reconnaissance
- Harvesting email addresses
- Conference Information

#### 2. Weaponization
- Coupling exploit with backdoor into deliverable payload

#### 3. Delivery
- Delivering weaponized bundle to the victim via email, web, USB, etc.

#### 4. Exploitation
- Exploiting a vulnerability to execute code on a victim's system.

#### 5. Installation
- Installing malware on the asset.

#### 6. Command and Control (C2)
- Command channel for remote manipulation of victim.

#### 7. Actions on Objectives
- With *'Hands on Keyboard access'*, intruders accomplish their original goals.

### MITRE ATT&CK Framework
Knowledge base of adversary tactics and techniques based on real-world observations of cyber attacks.

**ATT&CK:** Adversarial Tactics, Techniques, and Common Knowledge.

**Attack Tactic:**
- Why an attack technique is used.
- The attackers tactical goal.

| Technique/Sub-technique (Action/How) | Tactic (Why)                                                                          |
| ------------------------------------ | ------------------------------------------------------------------------------------- |
| Reconnaissance                       | The adversary is trying to gather information they can use to plan future operations. |
**Attack Technique:**
- Techniques represent "how" an adversary achieves a tactical goal by performing an action.
- E.g.. *An adversary may dump credentials to achieve credential access.*

**Attack Sub-techniques:**
- More specific description of the adversarial behaviour used to achieve a goal. 
- Describe the action at a lower level than the techniques.
- E.g..  *An adversary may dump credentials by accessing the Local Security Authority (LSA) Secrets.*

**Attack Procedure:**
- The specific implementation the adversary uses for techniques or sub-techniques.
- E.g.. *An adversary using PowerShell to inject into lsass.exe to dump credentials by scraping LSASS memory on a victim*

### Mandiant Attack Lifecycle

Kill chain model in which the weaponization stage is removed and a loop is introduced to represent the continuous activities of internal recon, lateral movement and persistence performed by attacks. 
![[Pasted image 20240715213722.png]]


### Diamond Model of Intrusion Analysis

**Adversary:** Where are attackers from? Who are the attackers? Who is the sponsor? Why attack? What is the activity timeline and planning?

**Infrastructure:** Infected computer(s), C&C domain names, location of C&C servers, C&C server types, mechanism and structure of C2, data management & control, and data leakage paths

**Capability:** What skills do attackers need to conduct reconnaissance, deliver their attacks, exploit vulnerabilities, deploy remote-controlled malware and backdoors, and develop their tools?

**Target (Victim):** Who is their target country/region, industry sector, individual, or data?

### Threat Hunting: 

- A proactive cybersecurity practice where analysts actively search for threats and indicators of compromise within an organization's network.

- Process involves identifying, isolating, and mitigating potential threats that have evaded traditional security measures, such as firewalls and antivirus software.

Hypothesis (likely attack type/compromise)=> Identification (IoCs) => Action plan (removal)

### Cyber Threat Intelligence:

Cyber Threat Intelligence (CTI) involves the collection and analysis of information about current and potential threats to an organization’s cybersecurity. It aims to understand the motives, methods, and targets of cyber attackers to better defend against and mitigate attacks.

Drawing of patterns based on threats and adversaries that allow for informed decisions regarding preparedness, prevention and response to various cyber attacks.

- **Strategic Threat Intelligence**:
    
    - **Purpose**: Provides high-level information about threat trends and risks to help executives and decision-makers understand the broader threat landscape.
    - **Content**: Reports on long-term trends, threat actors’ motives, and potential impacts on the organization.
    - **Audience**: Senior management and executives.

- **Tactical Threat Intelligence**:
    
    - **Purpose**: Focuses on the tactics, techniques, and procedures (TTPs) used by threat actors.
    - **Content**: Detailed analysis of attack methods, tools used, and indicators of compromise (IOCs).
    - **Audience**: Security operations teams and incident responders.

- **Operational Threat Intelligence**:
    
    - **Purpose**: Provides information about specific, imminent threats to help prepare and respond effectively.
    - **Content**: Alerts and advisories about active campaigns, targeted attacks, and emerging vulnerabilities.
    - **Audience**: Incident response teams and security operations centers (SOCs).

- **Technical Threat Intelligence**:
    
    - **Purpose**: Delivers technical data on threats to assist in the detection and mitigation of attacks.
    - **Content**: IP addresses, domain names, file hashes, malware signatures, and other technical indicators.
    - **Audience**: Security analysts and IT staff responsible for implementing and maintaining security controls.

### Threat Modelling: 

Threat modelling is a process used in cybersecurity to systematically identify and evaluate potential threats to a system. Here's a more detailed breakdown:

1. **Identify Assets**: Determine critical components, data, and functionalities that need protection.
2. **Create a System Architecture**: Develop detailed diagrams showing how data flows and how components interact.
3. **Identify Entry Points**: Pinpoint all potential access points where an attacker could gain entry.
4. **Enumerate Threats**: Use methodologies like STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) to list possible threats specific to the system's architecture.
5. **Rank Threats**: Assess each threat based on its potential impact and likelihood of occurrence.
6. **Mitigate Threats**: Develop and implement security controls to address the identified threats, such as input validation, access controls, and encryption.

**Microsoft STRIDE Threat Model:**

- **S**poofing - pretending to be someone / something else.
- **T**ampering - modifying something that should not be modified.
- **R**epudiation  - denial of something that was done (true or not).
- **I**nformation disclosure - divulge information that should not be divulged, a breach of confidentiality.
- **D**enial of service - prevent a system or service from being available or fulfilling its purpose.
- **E**levation of privilege - executing something without being allowed to do so.