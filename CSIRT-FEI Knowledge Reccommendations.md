# CSIRT Education Guidelines

This document contains summary on recommended knowledge topics for new and current CSIRT-FEI members along with recommended courses to take.

**Table of contents**

1. [Basig Knowledge](#basic_knowledge)
2. [SCIRT subteams](csirt_subteams)
3. [Red Team](#red_team)
4. [Blue Team](#blue_team)

## Basic Konwledge
Knowledge that is mandatory for each member to have. Every new member upon acceptance into CSIRT-FEI is tested or educated on this basic knowledge. It is recommended to complete each suggested course for each topic. 

- Networking, protocols  https://tryhackme.com/room/introtonetworking
- Python/bash/(scripting)
- OS - Linux/Windows
  - https://tryhackme.com/room/linuxmodules
  - https://tryhackme.com/room/investigatingwindows 
- Cybersecurity essentials
  - https://tryhackme.com/room/jrsecanalystintrouxo 
  - https://tryhackme.com/room/threatintelligenceforsoc
  - https://tryhackme.com/room/trafficanalysisessentials
  - https://tryhackme.com/room/beginnerpathintro
- Incident handling/ basic hacing tools and techniques

API Prereguisisties
- OS (C)
- PKRIM (B)
- UPB (B)
- *BISPP (B)
- *WEBTE (B)

## CSIRT subteams

### Training range
Training manegemnet teams makes sure the new members are aducated in the field of their desired team. Each member upon acceptance goeas througb basic training provided by training range mebers. Members of training range provide platform and virtual machines fro thorough education of existing members.
- Creativity
- Open stack - machine virtualization
- OS administration
- Advanced hacking techniques
- Forensic analysis

### Asset management
Asset management team helps with inventarization of faculty department devices. Provides administrative support and cooperate with tasking system team.
- Database systems
- Netbox
- OS administration
- Communicatoin skills
- Scripting - ticket creation 

### Network monitoring
Network monitoring team takes role of maintaining security of devices by monitoring netwrok traffic and managing alerts. The aim is to connect suitable monitoring tools and create advanced monitoring system.
- OS administration
- Networking and protocols
- SIEM systems
- basic SOC knowledge

## Red Team

### Introduction to Red Teaming

#### What is red teaming  and its purpose

Red teaming is a systematic and structured approach used in various fields, such as cybersecurity, military, business, and more, to test and improve the effectiveness of an organization's security, strategies, and decision-making processes. The primary purpose of red teaming is to identify vulnerabilities, weaknesses, and blind spots that may not be apparent through traditional methods, with the ultimate goal of enhancing an organization's overall resilience and preparedness.

#### Difference between red team and blue team

- **Red Team:** The red team consists of individuals or groups tasked with simulating real-world adversaries. They adopt an adversarial mindset and use creative, unconventional methods to identify and exploit vulnerabilities within an organization's systems, processes, or strategies. Red team activities are focused on testing and challenging an organization's defenses, probing for weaknesses, and providing a critical, independent perspective on potential threats and risks.

- **Blue Team:** The blue team, in contrast, represents the defenders of the organization. Their role is to maintain and defend the organization's systems, networks, and strategies. They typically work to detect, prevent, and mitigate threats and vulnerabilities. Blue team activities involve monitoring and maintaining the security posture, responding to security incidents, and implementing safeguards to protect against potential threats identified by the red team.

#### Red team mindset

An adversarial mindset is a critical aspect of red teaming and serves as the foundation for its effectiveness. Here's why it's essential:

- **Uncovering Hidden Weaknesses:** Red teamers think like real adversaries, exploring potential attack vectors that might be overlooked by the organization's own defenders. This approach helps reveal vulnerabilities that might not be apparent to those with a more defensive perspective.

- **Challenging Assumptions:** Red teaming encourages organizations to question their assumptions about their security, strategies, and decision-making. By doing so, it helps in breaking complacency and preventing groupthink, leading to more robust and adaptable security measures.

- **Improving Resilience:** The adversarial mindset helps organizations build resilience by understanding how adversaries may exploit their weaknesses. This information is invaluable in developing better response plans and strengthening defenses.

- **Enhancing Preparedness:** Red teaming provides a realistic testing environment for an organization's response capabilities. This helps in refining incident response procedures and crisis management, ensuring that they can effectively mitigate threats.

In summary, red teaming is a proactive and dynamic approach that aims to improve an organization's security and decision-making by simulating adversarial attacks and tactics. The adversarial mindset is a key element, enabling organizations to identify and address vulnerabilities, challenge assumptions, and enhance their overall preparedness and resilience in the face of real-world threats.

### Penetration Testing Techniques

#### Penetration Testing Methodologies and Tools

Penetration testing, also known as ethical hacking, involves systematically probing an organization's systems and networks to identify vulnerabilities and weaknesses that malicious attackers could exploit. Various methodologies and tools are used in this process, including:

1. **Reconnaissance:** This phase involves gathering information about the target, such as IP addresses, domain names, and network architecture. Tools like [osintframework.com](https://osintframework.com/) [urlscan.io](https://urlscan.io/), [Shodan](https://www.shodan.io/), [crt.sh](https://crt.sh/), [AbuseIPDB](https://www.abuseipdb.com/), [Virustotal](https://www.virustotal.com/gui/home/upload), [Censys](https://search.censys.io/), [SecurityTrails](https://securitytrails.com/).

2. **Scanning:** During scanning, penetration testers use tools like [nmap](https://nmap.org/book/man.html) to identify open ports, services, and vulnerabilities on the target system.

3. **Exploitation:** Once vulnerabilities are identified, testers attempt to exploit them to gain unauthorized access. Tools like `Metasploit` and custom scripts are often used for this purpose.

4. **Post-Exploitation:** After gaining access, testers explore the compromised system, escalate privileges, and maintain access. Tools like `Meterpreter` or `PowerShell` can be used for post-exploitation activities.

5. **Reporting:** The findings are documented in a comprehensive report, including the vulnerabilities discovered, their impact, and recommendations for remediation.

#### Real-World Examples of Successful Attacks

1. **Stuxnet:** Stuxnet was a sophisticated malware that targeted Iran's nuclear program. It exploited multiple vulnerabilities, including a zero-day vulnerability in Windows, to infiltrate and damage industrial control systems.

2. **Equifax Data Breach:** In 2017, Equifax suffered a massive data breach due to a vulnerability in the Apache Struts web application. Attackers used the vulnerability to gain access to sensitive data on millions of customers.

3. **Sony Pictures Hack:** In 2014, Sony Pictures was the victim of a high-profile hack, which exposed sensitive emails, financial data, and unreleased films. The attack was attributed to North Korea and involved the use of various hacking techniques.

#### The Importance of Ethical Hacking and Responsible Disclosure

Ethical hacking plays a crucial role in enhancing cybersecurity by identifying and mitigating vulnerabilities before malicious actors can exploit them. Responsible disclosure is an essential part of this process, as it ensures that vulnerabilities are reported to the affected organizations rather than being publicly disclosed without warning. The benefits of ethical hacking and responsible disclosure include:

- **Security Improvement:** Organizations can fix vulnerabilities and strengthen their security posture based on the findings of ethical hackers.

- **Reduced Risks:** Identifying vulnerabilities proactively helps prevent data breaches and cyberattacks, reducing risks to businesses and individuals.

- **Legal and Ethical:** Ethical hackers follow a code of conduct and work within the boundaries of the law, ensuring that their activities are ethical and lawful.

- **Trust and Collaboration:** Responsible disclosure fosters trust between the security community and organizations, leading to collaboration in making the digital world safer.

In summary, penetration testing involves various methodologies and tools to identify and address vulnerabilities in systems and networks. Real-world examples of successful attacks illustrate the importance of proactive security measures. Ethical hacking and responsible disclosure are essential for improving cybersecurity and maintaining a secure online environment.

### Exploitation and Post-Exploitation

#### Common Exploitation Techniques

Exploitation techniques are used by attackers to take advantage of vulnerabilities in systems or software to gain unauthorized access. Some common exploitation techniques include:

  1. **Phishing:** Attackers send deceptive emails or messages to trick users into clicking on malicious links or downloading malicious attachments.

  2. **Buffer Overflow:** Exploiting vulnerabilities in software by overflowing a buffer, which can lead to arbitrary code execution.

  3. **SQL Injection:** Injecting malicious SQL queries into web applications to manipulate databases or gain unauthorized access.

  4. **Cross-Site Scripting (XSS):** Injecting malicious scripts into web pages that are then executed by other users' browsers.

  5. **Zero-Day Exploits:** Leveraging previously unknown vulnerabilities that haven't been patched by the software vendor.

#### Maintaining Persistence and Lateral Movement

Once attackers gain initial access to a system, they aim to maintain persistence and move laterally within a network to expand their control. Common techniques for this include:

1. **Backdoors:** Attackers install backdoor malware on compromised systems, allowing them to regain access even if their initial entry point is discovered and removed.

2. **Privilege Escalation:** Exploiting additional vulnerabilities to elevate privileges, gaining more control over the system.

3. **Pass-the-Hash:** Stealing password hashes to move laterally within a network without the need for plaintext passwords.

4. **Credential Dumping:** Extracting credentials from memory or databases to gain access to other systems.

#### Case Studies of Post-Exploitation Scenarios

1. **The Target Data Breach (2013):** Attackers initially gained access to Target's network through a third-party HVAC vendor's compromised credentials. They then installed malware to steal credit card data, leading to one of the largest retail data breaches in history.

2. **NotPetya Ransomware Attack (2017):** The NotPetya ransomware outbreak began as a software update for accounting software used by many Ukrainian businesses. Attackers exploited the update mechanism to distribute the malware, which later caused significant damage worldwide.

3. **Stuxnet (2010):** Stuxnet is a sophisticated worm that targeted Iran's nuclear program. It used multiple vulnerabilities to infiltrate industrial control systems, causing physical damage to centrifuges used in uranium enrichment.

4. **SolarWinds Supply Chain Attack (2020):** Attackers compromised the SolarWinds software update process, injecting a backdoor into the software. This allowed them to gain access to numerous government and private-sector organizations.

In these case studies, attackers leveraged various exploitation techniques to gain access and then used post-exploitation tactics to maintain control and move within the networks. Understanding these tactics and learning from past incidents is crucial for enhancing cybersecurity and preventing future attacks.

### Social Engineering

#### Social Engineering Techniques

Social engineering is a method of manipulating individuals to gain unauthorized access, sensitive information, or perform actions they wouldn't typically do. Several common social engineering techniques include:

- **Phishing:** Attackers send deceptive emails or messages that appear legitimate to trick recipients into clicking on malicious links or revealing sensitive information such as passwords, credit card numbers, or personal data.

- **Pretexting:** In pretexting, an attacker fabricates a scenario or pretext to trick someone into disclosing information or performing actions that they wouldn't under normal circumstances. This can involve impersonating an authority figure or someone the victim trusts.

- **Tailgating:** Tailgating occurs when an attacker gains physical access to a restricted area by following an authorized person through a secure entry point, such as a locked door or gate, without proper authentication.

#### Real-Life Social Engineering Attacks and Consequences

1. **RSA SecurID Attack (2011):** In one of the most well-known incidents, attackers sent phishing emails to employees at RSA, a prominent security company. The employees unwittingly opened malicious attachments, leading to the compromise of the company's SecurID two-factor authentication tokens. The consequences included the compromise of numerous organizations relying on RSA's technology for security.

2. **The Bangladesh Bank Heist (2016):** Cybercriminals attempted to steal nearly $1 billion from the Bangladesh Bank by using social engineering techniques, including forging the bank's credentials to authorize fraudulent transactions. While most of the attempted theft was thwarted, they still managed to steal around $81 million, making it one of the largest bank heists in history.

3. **DEF CON Social Engineering Capture the Flag (SECTF):** The DEF CON SECTF is an annual competition where participants use various social engineering techniques to extract information from target companies in a controlled, ethical setting. This event highlights the effectiveness of social engineering attacks in a competition format.

These real-life examples demonstrate the significant impact social engineering attacks can have on organizations and individuals. It underscores the importance of awareness, education, and implementing security measures to prevent and mitigate such attacks.

### Reporting and Remediation in Red Teaming

#### Creating Comprehensive Red Teaming Reports

Comprehensive red teaming reports are essential for effectively communicating findings, vulnerabilities, and recommendations to an organization. The following steps can help you create an informative and actionable report:

1. **Title and Cover Page:** Begin with a title that clearly identifies the report as a red teaming assessment. Include a cover page with the organization's name, date, and contact information.

2. **Executive Summary:** Provide a brief summary of the red teaming engagement, highlighting the key findings, vulnerabilities, and their potential impact. This section should be accessible to non-technical stakeholders.

3. **Scope and Objectives:** Define the scope and objectives of the engagement, specifying the systems, networks, and strategies that were assessed. Ensure clarity on what was tested and the goals of the assessment.

4. **Methodology:** Describe the methods and tools used during the assessment. Outline the steps taken by the red team, including the attack vectors and techniques employed.

5. **Findings and Vulnerabilities:** Present a detailed account of the findings, including identified vulnerabilities, weaknesses, and potential risks. Categorize and prioritize these findings based on their severity and potential impact on the organization.

6. **Recommendations:** Offer specific and actionable recommendations for mitigating the identified vulnerabilities. Include a step-by-step guide for remediation and suggested best practices.

7. **Evidence and Proof of Concept (PoC):** Include evidence to support the identified vulnerabilities. This may consist of screenshots, logs, or proof-of-concept demonstrations to illustrate the feasibility of an attack.

8. **Technical Details:** Provide technical details, such as system configurations, network diagrams, and any additional documentation necessary for IT and security teams to understand and replicate the findings.

9. **Appendices:** Include any supplementary information, logs, or data that may be relevant to the assessment. Appendices should be organized and labeled for easy reference.

10. **Acknowledgments:** Acknowledge the collaborative effort between the red team and blue team, as well as any third-party entities that may have been involved in the assessment. Recognize the importance of teamwork in improving security.

#### Collaborating with the Blue Team

Effective collaboration between the red team and blue team is essential to address identified vulnerabilities and enhance the organization's security posture. Here's how you can foster collaboration:

1. **Debriefing:** Conduct a debriefing session in which the red team and blue team come together to discuss the findings, attack techniques, and the potential impact of vulnerabilities. This is an opportunity to share insights and lessons learned.

2. **Vulnerability Prioritization:** Collaboratively prioritize vulnerabilities based on their potential risk and ease of exploitation. Assess which vulnerabilities require immediate attention and focus.

3. **Remediation Planning:** Work together to create a remediation plan that outlines the steps necessary to mitigate the identified vulnerabilities. This may involve patching, configuration changes, or other security enhancements.

4. **Testing and Validation:** The blue team should validate the effectiveness of the proposed remediation measures. This validation process ensures that vulnerabilities are successfully mitigated and that the organization is adequately protected.

5. **Training and Awareness:** Share knowledge gained during the red team engagement with the blue team and the broader organization. This knowledge transfer helps improve security awareness and training programs.

#### The Importance of Responsible Disclosure

Responsible disclosure is a critical ethical principle, especially when dealing with identified vulnerabilities in an organization's systems. It ensures a balance between security research and the protection of organizations. Here are key aspects to consider:

1. **Non-Disclosure Agreement (NDA):** Ensure that both the red team and blue team, as well as any third parties involved, sign non-disclosure agreements (NDAs) to protect sensitive information and findings.

2. **Notify the Organization:** In cases where severe vulnerabilities are identified, promptly inform the organization, making them aware of the risks and potential impact. The organization needs to be informed to take immediate action.

3. **Cooperate with Remediation:** Collaborate with the blue team and the organization to implement remediation measures for addressing the identified vulnerabilities responsibly. Ensure that these measures are effective in reducing risk.

4. **Public Disclosure:** Publicly disclosing vulnerabilities should only occur after the organization has had sufficient time to address them. Responsible disclosure ensures that vulnerabilities are not exploited before mitigation occurs.

Responsible disclosure is essential for maintaining a cooperative and ethical approach to cybersecurity, ultimately contributing to improved security and responsible practices within the industry.

### Red Team training

#### [picoCTF](https://picoctf.org/)

- **Cybersecurity Introduction:** picoCTF is an accessible platform introducing users to cybersecurity and capture the flag challenges.
- **Diverse Challenges:** It offers tasks in cryptography, reverse engineering, forensics, and more, mimicking real-world scenarios.
- **Hands-On Learning:** Participants engage in problem-solving and critical thinking, gaining practical experience in a user-friendly environment.

#### Try hack me
Intro to offensive security - https://tryhackme.com/room/introtooffensivesecurity
Red Team Engagement - https://tryhackme.com/room/redteamengagements
Red Team Fundamentals - https://tryhackme.com/room/redteamfundamentals
Basic Pentesting - https://tryhackme.com/room/basicpentestingjt


## Blue Team

#### Try Hack Me
- Junior security analyst intro - https://tryhackme.com/room/jrsecanalystintrouxo
- Threat Intelligence info - https://tryhackme.com/room/threatinteltools
- Wazuh - https://tryhackme.com/room/wazuhct
- *honeypots - https://tryhackme.com/room/introductiontohoneypots
- Threat Intelligence for SOC - https://tryhackme.com/room/threatintelligenceforsoc
- IR - https://tryhackme.com/room/preparation
- IR2 - https://tryhackme.com/room/identificationandscoping
#### Understanding the Blue Team's Role

The Blue Team represents defenders within an organization, dedicated to fortifying its systems, strategies, and security measures. Their primary objective is to uphold and safeguard the organization against potential threats, ensuring a robust defense that mitigates risks and maintains operational continuity.

#### Differentiating Blue Team from Red Team

- **Blue Team:** Comprising individuals adept at proactive defense, the Blue Team's focus lies in fortifying the organization's systems. Their responsibilities include constant monitoring, threat detection, implementing preventive measures, and swiftly responding to security incidents. Unlike the Red Team, their role is centered on maintaining the integrity and security of the organization’s infrastructure and strategies.

- **Red Team:** In contrast, the Red Team takes on an adversarial role, simulating real-world threats to identify vulnerabilities and weaknesses. They challenge the Blue Team’s defenses, probing for gaps and providing an external perspective on potential risks.

#### The Mindset of the Blue Team

The defensive mindset embraced by the Blue Team is instrumental for a well-rounded security approach. Here's why it's crucial:

- **Proactive Defense:** Blue Teamers anticipate and prevent threats by continuously assessing, monitoring, and strengthening the organization's security measures.

- **Swift Response and Resolution:** They are equipped to respond promptly and efficiently to security incidents, minimizing potential damage and swiftly restoring operational normalcy.

- **Maintaining Stability:** The Blue Team's efforts ensure the stability and reliability of the organization’s systems, providing a strong foundation for operations.

- **Continuous Improvement:** By learning from incidents and analyzing potential risks, the Blue Team iteratively enhances security measures, ensuring adaptability and resilience.

The Blue Team, with their proactive and defensive approach, plays a vital role in maintaining the organization's security and stability. Their commitment to constant vigilance and readiness fortifies the organization against a spectrum of potential threats, contributing to its resilience and robustness in the face of adversities.
