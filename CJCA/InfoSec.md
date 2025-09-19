# InfoSec

InfoSec is Information Security, it is a very vast, essential part when it comes to security. It’s all about securing personal data, systems and logs for example from people that shouldn’t access them.

These are the areas where we find InfoSec, as i said it is vast :

1. Network Security
2. Application Security
3. Operational Security
4. Disaster Recovery and Business Continuity
5. Cloud Security
6. Physical Security
7. Mobile Security
8. Internet of Things (IoT) Security

### **Roles in Information Security**

In the expansive world of Information Security (InfoSec), there are a plethora of different roles each carrying their unique set of responsibilities. These roles are integral parts of a robust InfoSec infrastructure, contributing to the secure operations of an organization:

| **Role** | **Description** | **Relevance to Penetration Testing** |
| --- | --- | --- |
| `Chief Information Security Officer` (`CISO`) | Oversees the entire information security program | Sets overall security strategy that pen testers will evaluate |
| `Security Architect` | Designs secure systems and networks | Creates the systems that pen testers will attempt to breach |
| `Penetration Tester` | Identifies vulnerabilities through simulated attacks | Actively looks for and exploits vulnerabilities within a system, legally and ethically. This is likely your target role. |
| `Incident Response Specialist` | Manages and responds to security incidents | Often works in tandem with pen testers by responding to their attacks, and sharing/collaborating with them afterwards to discuss lessons learned. |
| `Security Analyst` | Monitors systems for threats and analyzes security data | May use pen test results to improve monitoring |
| `Compliance Specialist` | Ensures adherence to security standards and regulations | Pen test reports often support compliance efforts |

# Network Security

| **Element** | **Description** |
| --- | --- |
| `Firewalls` | Act as barriers between trusted internal networks and untrusted external networks, filtering traffic based on predetermined security rules. |
| `Intrusion Detection and Prevention Systems` (`IDS`/`IPS`) | Monitor network traffic for suspicious activities and take automated actions to detect or block potential threats. |
| `Virtual Private Networks` (`VPNs`) | Provide secure, encrypted connections over public networks, ensuring data privacy and integrity during transmission. For example, used by employees to connect to internal network resources. |
| `Access control mechanisms` | Include authentication and authorization protocols to ensure only legitimate users can access network resources. |
| `Encryption technologies` | Protect sensitive data both in transit and at rest, rendering it unreadable to unauthorized parties. |

# Application Security

In software development, Security by Design works the same way. When creating an app, developers think about security right from the planning stage. This can include:

- `Threat modeling`: Like imagining all the ways someone might break into your house, threat modeling helps developers figure out potential risks to the app early on.
- `Secure code reviews`: After writing the code, developers carefully check it to make sure there are no weak spots, similar to inspecting the house’s foundation for cracks before finishing construction.
- `Servers and databases`: These are like the land your house sits on and the water supply it uses. If they aren’t secure, the whole system is at risk.
- `Authentication and authorization`: Think of these as high-quality locks on your doors. Authentication ensures only the right people can get in, while authorization makes sure they can only access the rooms (data) they’re allowed to.

# Disaster Recovery & Business Continuity

Disaster Recovery is keeping the workflow in the times of disasters, those disasters can be natural like earthquakes or technical in some cases. It consists of backing up data, servers and services and make use of them in these times.

Business Continuity is like making a backup plan without needing extra physical material, look at this example: It's like having a contingency for moving the concert indoors if the weather forecast looks bad or arranging for an acoustic performance if all else fails.

# Cloud Security

Basically has to work both ways, meaning if you host a vulnerable application in the cloud , you can’t expect it to not get hacked or exploited, but the cloud offers overall security but the admin has to properly configure the app, roles and clearances to ensure the safety of the user’s data.

This is called a shared reponsibility model. 

# DDoS attacks

A `Distributed Denial of Service` (`DDoS`) attack is a malicious attempt to interrupt the normal functioning of a website, server, or online service by overwhelming it with a flood of internet traffic. Unlike a traditional `Denial of Service` (`DoS`) attack, which originates from a single source, a DDoS attack comes from multiple sources simultaneously. These sources are often compromised computers or devices infected with malware, collectively known as a "botnet.”

# Ransomware

Attackers gain entry to an enterprise’s local network or server or database that the enterprise rely heavily on, then, they go ahead and encrypt the data they found with simple asymmetrical cryptography techniques. After they demand money from the enterprise to give them the key so they can decrypt the data.

# Social Engineering

Social engineering techniques are sophisticated methods that exploit the fundamental human tendency to trust others. These tactics leverage psychological vulnerabilities to manipulate individuals into divulging confidential information or performing actions that compromise security. Cybercriminals have developed and refined a diverse array of social engineering techniques, each designed to exploit different aspects of human behavior and social interactions. These methods are constantly evolving, adapting to new technologies and social norms, making them particularly challenging to defend against. There are five fundamental techniques being utilized, but not limited to:

1. Phishing
2. Pretexting
3. Baiting
4. Tailgating
5. Quid Pro Quo

# Advanced Persistent Threats

It when an attacker grants an entry point to a compromised system and remains undetected for a long period of time. They can install malwares or create backdoors and remain completely undetected. Then they try some lateral movement escalating privileges and possibly compromising the whole network. 

# Cybersecurity Teams

- Threat Actors: Black hat hackers that do the exploitation part for extorsion and blackmail or even espionage, basically outlaws.
- Red Team: They simulate real-world attack scenarios under the approval of the enterprise, the whole point is to enhance the corporate security not exploit it.
- Blue Team: Blue team serves as the frontline defense in cybersecurity, collaborating on keeping an organization’s digital infrastructure safe and sound.
- Purple Team: Basically both red and blue teams working together simulating real world attacks and the whole point behind this team, is to improve security defenses and enhance detection and response.

# Penetration Testers (Ethical Hackers)

A `Penetration Tester` (also known as `Ethical Hacker`) is a cybersecurity professional who acts like a malicious hacker to find vulnerabilities in an organization's computer systems, networks, or web applications `but` without the malicious intent.

# Security Operations Center (SOC)

A `Security Operations Center` (`SOC`) is a centralized unit that acts as the core of an organization's cybersecurity operations. It’s a place where skilled professionals work continuously to monitor, detect, analyze, and respond to cyber threats and security incidents

# Bug Bounty Hunters

Bug bounty hunters are skilled cybersecurity professionals who operate independently to uncover vulnerabilities in various digital assets belonging to organizations. These assets may include software applications, websites, or complex network systems.