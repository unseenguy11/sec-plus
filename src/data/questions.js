import { newUnits } from './new_units.js';

export const questionsData = {
    "unit-2": [
        { q: 'What is the primary trade-off usually observed when increasing security measures?', options: ['Increased convenience', 'Decreased usability', 'Lower cost', 'Faster performance'], answer: 1, explanation: 'There is typically an inverse relationship between security and usability/convenience.' },
        { q: 'Which term refers to protecting data from unauthorized access, modification, and destruction?', options: ['Information Security', 'Information System Security', 'Network Security', 'Physical Security'], answer: 0, explanation: 'Information Security focuses on protecting the data itself.' },
        { q: 'Which term refers to protecting the systems that hold and process data?', options: ['Information Security', 'Information System Security', 'Data Privacy', 'Content Filtering'], answer: 1, explanation: 'Information System Security focuses on the devices/systems (servers, computers, etc.).' },
        { q: 'In the CIA triad, what does Confidentiality ensure?', options: ['Data is accurate', 'Data is available when needed', 'Data is only accessible to authorized users', 'Data cannot be denied'], answer: 2, explanation: 'Confidentiality ensures information is kept secret from unauthorized people.' },
        { q: 'Which method is primarily used to ensure Confidentiality?', options: ['Hashing', 'Encryption', 'Redundancy', 'Digital Signatures'], answer: 1, explanation: 'Encryption is the primary tool for maintaining confidentiality.' },
        { q: 'In the CIA triad, what does Integrity ensure?', options: ['Data is not altered without authorization', 'Data is encrypted', 'Systems are online', 'Users are identified'], answer: 0, explanation: 'Integrity ensures data remains accurate and unchanged.' },
        { q: 'Which tool is best for verifying Data Integrity?', options: ['Firewall', 'Hashing', 'VPN', 'Backup'], answer: 1, explanation: 'Hashing creates a unique fingerprint to detect alterations.' },
        { q: 'In the CIA triad, what does Availability ensure?', options: ['Data is secret', 'Systems and data are accessible when needed', 'Users are accountable', 'Non-repudiation'], answer: 1, explanation: 'Availability ensures authorized users can access resources when required.' },
        { q: 'What is the primary method to ensure Availability?', options: ['Encryption', 'Redundancy', 'Hashing', 'Auditing'], answer: 1, explanation: 'Redundancy (backups, failover) ensures systems stay available.' },
        { q: 'What does "Five Nines" of availability represent?', options: ['99%', '99.9%', '99.99%', '99.999%'], answer: 3, explanation: 'Five nines means 99.999% uptime, or about 5 minutes of downtime per year.' },
        { q: 'Non-repudiation provides undeniable proof of what?', options: ['Data encryption', 'System uptime', 'Participation in a transaction', 'User location'], answer: 2, explanation: 'Non-repudiation prevents a sender from denying they sent a message.' },
        { q: 'Which technology provides Non-repudiation?', options: ['Symmetric Encryption', 'Digital Signatures', 'Firewalls', 'Load Balancers'], answer: 1, explanation: 'Digital signatures (using private keys) provide non-repudiation.' },
        { q: 'In AAA, what is Authentication?', options: ['Tracking user actions', 'Determining user permissions', 'Verifying the identity of a user', 'Encrypting user data'], answer: 2, explanation: 'Authentication is the process of verifying who you are.' },
        { q: 'In AAA, what is Authorization?', options: ['Verifying identity', 'Determining what a user is allowed to do', 'Logging user activity', 'Backing up data'], answer: 1, explanation: 'Authorization happens after authentication and sets permissions.' },
        { q: 'In AAA, what is Accounting?', options: ['Paying bills', 'Verifying identity', 'Tracking and logging user activities', 'Granting permissions'], answer: 2, explanation: 'Accounting involves logging and monitoring user actions for auditing.' },
        { q: 'Which is an example of a "Something You Know" authentication factor?', options: ['Fingerprint', 'Smart Card', 'Password', 'GPS Location'], answer: 2, explanation: 'Passwords, PINs, and secret questions are knowledge factors.' },
        { q: 'Which is an example of a "Something You Have" authentication factor?', options: ['Password', 'Retina Scan', 'Smart Card / Token', 'Typing rhythm'], answer: 2, explanation: 'Physical tokens, phones, or cards are possession factors.' },
        { q: 'Which is an example of a "Something You Are" authentication factor?', options: ['Password', 'Biometrics (Fingerprint/Face)', 'Smart Card', 'Location'], answer: 1, explanation: 'Biometrics rely on physical characteristics.' },
        { q: 'Multi-Factor Authentication (MFA) requires what?', options: ['Two passwords', 'Two or more different types of authentication factors', 'A password and a PIN', 'A fingerprint and a face scan'], answer: 1, explanation: 'MFA requires 2+ *different* types (e.g., Password + Token), not just two of the same type.' },
        { q: 'Antivirus software is an example of which Security Control Category?', options: ['Managerial', 'Operational', 'Technical', 'Physical'], answer: 2, explanation: 'Technical controls use hardware/software to enforce security.' },
        { q: 'Security Policies and Risk Assessments are examples of which Security Control Category?', options: ['Technical', 'Managerial', 'Operational', 'Physical'], answer: 1, explanation: 'Managerial (Administrative) controls focus on governance and strategy.' },
        { q: 'User Awareness Training and Incident Response Plans are examples of which Security Control Category?', options: ['Technical', 'Managerial', 'Operational', 'Physical'], answer: 2, explanation: 'Operational controls cover day-to-day people processes.' },
        { q: 'Fences, Locks, and Guards are examples of which Security Control Category?', options: ['Technical', 'Managerial', 'Operational', 'Physical'], answer: 3, explanation: 'Physical controls protect the physical environment.' },
        { q: 'A firewall blocking malicious traffic before it enters the network is which Control Type?', options: ['Preventative', 'Detective', 'Corrective', 'Deterrent'], answer: 0, explanation: 'Preventative controls stop an incident before it happens.' },
        { q: 'Security cameras and warning signs are primarily which Control Type?', options: ['Preventative', 'Deterrent', 'Corrective', 'Compensating'], answer: 1, explanation: 'Deterrent controls discourage attackers by increasing perceived risk.' },
        { q: 'An Intrusion Detection System (IDS) is which Control Type?', options: ['Preventative', 'Detective', 'Corrective', 'Directive'], answer: 1, explanation: 'Detective controls identify and alert on issues as they happen.' },
        { q: 'Restoring data from a backup after a ransomware attack is which Control Type?', options: ['Preventative', 'Detective', 'Corrective', 'Deterrent'], answer: 2, explanation: 'Corrective controls mitigate damage and restore systems after an incident.' },
        { q: 'Using a legacy system isolated on a VLAN because it cannot be patched is an example of which Control Type?', options: ['Preventative', 'Compensating', 'Detective', 'Directive'], answer: 1, explanation: 'Compensating controls provide an alternative measure when the primary control isn\'t feasible.' },
        { q: 'An Acceptable Use Policy (AUP) is which Control Type?', options: ['Preventative', 'Detective', 'Directive', 'Corrective'], answer: 2, explanation: 'Directive controls mandate behavior through rules and policies.' },
        { q: 'What is the core principle of Zero Trust?', options: ['Trust but Verify', 'Trust Nothing, Verify Everything', 'Trust Internal Users', 'Trust the Perimeter'], answer: 1, explanation: 'Zero Trust assumes breach and verifies every request.' },
        { q: 'In Zero Trust, which plane defines policies and manages identities?', options: ['Data Plane', 'Control Plane', 'Network Plane', 'User Plane'], answer: 1, explanation: 'The Control Plane handles policy definition and decision making.' },
        { q: 'In Zero Trust, which plane enforces access decisions?', options: ['Data Plane', 'Control Plane', 'Management Plane', 'Strategy Plane'], answer: 0, explanation: 'The Data Plane (Policy Enforcement Point) executes the allow/block decisions.' },
        { q: 'What is "Adaptive Identity" in Zero Trust?', options: ['Using the same password everywhere', 'Real-time validation based on behavior, device, and location', 'Changing usernames daily', 'Anonymous login'], answer: 1, explanation: 'Adaptive Identity continuously assesses risk factors for authentication.' },
        { q: 'What is a Gap Analysis?', options: ['Comparing current state to desired state', 'Scanning for viruses', 'Analyzing network traffic', 'Auditing financial records'], answer: 0, explanation: 'Gap Analysis identifies the difference between where you are and where you want to be.' },
        { q: 'Which type of Gap Analysis evaluates infrastructure capabilities?', options: ['Business Gap Analysis', 'Technical Gap Analysis', 'Financial Gap Analysis', 'Personnel Gap Analysis'], answer: 1, explanation: 'Technical Gap Analysis focuses on hardware/software/infrastructure shortfalls.' },
        { q: 'Which type of Gap Analysis evaluates processes and workflows?', options: ['Business Gap Analysis', 'Technical Gap Analysis', 'Network Gap Analysis', 'Code Gap Analysis'], answer: 0, explanation: 'Business Gap Analysis looks at operational processes and alignment.' },
        { q: 'What is a POA&M?', options: ['Plan of Action and Milestones', 'Policy of Authentication and Management', 'Process of Authorization and Monitoring', 'Protocol of Access and Maintenance'], answer: 0, explanation: 'POA&M outlines how to address identified vulnerabilities (gaps).' },
        { q: 'Risk is the intersection of which two elements?', options: ['Threat and Vulnerability', 'Asset and Value', 'Cost and Benefit', 'Time and Money'], answer: 0, explanation: 'Risk exists where a Threat can exploit a Vulnerability.' },
        { q: 'If you have a vulnerability but no threat, do you have risk?', options: ['Yes', 'No', 'Maybe', 'Only if it is critical'], answer: 1, explanation: 'Without a threat to exploit it, a vulnerability does not constitute a risk.' },
        { q: 'Data Masking is a technique primarily used for?', options: ['Integrity', 'Availability', 'Confidentiality', 'Non-repudiation'], answer: 2, explanation: 'Masking hides sensitive data (like credit card numbers) from unauthorized view.' }
    ],
    "unit-3": [
        {
            "q": "Data exfiltration is best defined as _______.",
            "options": [
                "Encrypting data at rest",
                "Valid backup restoration",
                "Unauthorized transfer of data out of a system",
                "The lawful collection of telemetry"
            ],
            "answer": 2,
            "explanation": "Data exfiltration = unauthorized removal of data from a system."
        },
        {
            "q": "Which is a common destination for stolen PII after exfiltration?",
            "options": [
                "Public university archives",
                "Dark web marketplaces",
                "Corporate transparency reports",
                "Government FOIA portals"
            ],
            "answer": 1,
            "explanation": "PII is often sold on dark web marketplaces."
        },
        {
            "q": "Blackmail in cyber contexts typically leverages _______.",
            "options": [
                "TLS 1.3 handshake failures",
                "Untraceable cryptocurrencies for payment",
                "IPv6 multicast only",
                "Hardware TPMs for escrow"
            ],
            "answer": 1,
            "explanation": "Attackers often demand crypto payments during blackmail/extortion."
        },
        {
            "q": "Service disruption is commonly achieved via _______.",
            "options": [
                "Key stretching",
                "DDoS attacks",
                "RBAC policy",
                "Checksum comparison"
            ],
            "answer": 1,
            "explanation": "DDoS overwhelms services to make them unavailable."
        },
        {
            "q": "Hacktivism motivation primarily relates to _______.",
            "options": [
                "Regulatory compliance",
                "Ideological or political causes",
                "Quarterly earnings",
                "Bug bounty points"
            ],
            "answer": 1,
            "explanation": "Hacktivists act to promote social/political causes."
        },
        {
            "q": "Ethical hackers/pen testers are motivated to _______.",
            "options": [
                "Steal funds for profit",
                "Deface sites for notoriety",
                "Improve security by finding vulnerabilities",
                "Spread misinformation"
            ],
            "answer": 2,
            "explanation": "Authorized testing seeks to improve defenses."
        },
        {
            "q": "Revenge-motivated attacks are most associated with _______.",
            "options": [
                "Content delivery networks",
                "Insider threats",
                "Botnet herders",
                "PKI root CAs"
            ],
            "answer": 1,
            "explanation": "Disgruntled insiders often act out of revenge."
        },
        {
            "q": "Espionage as a motivation most often maps to _______.",
            "options": [
                "Open-source licensing",
                "Routine patch management",
                "Spam filtering",
                "Nation-state or competitor intelligence gathering"
            ],
            "answer": 3,
            "explanation": "Cyber espionage aims to gather sensitive intel."
        },
        {
            "q": "Nation-state “war” motivations emphasize _______.",
            "options": [
                "Retail loyalty programs",
                "SEO rankings",
                "Geopolitical objectives",
                "Printer ink savings"
            ],
            "answer": 2,
            "explanation": "Nation-states pursue strategic geopolitical goals."
        },
        {
            "q": "Internal vs external actors differ primarily by _______.",
            "options": [
                "Their relationship to the target organization",
                "Their preferred programming language",
                "Use of IPv4 vs IPv6",
                "Whether they own a data center"
            ],
            "answer": 0,
            "explanation": "Internal actors have legitimate organizational access; externals do not."
        },
        {
            "q": "Resources and funding affect a threat actor’s _______.",
            "options": [
                "Time zone",
                "Scale and sophistication of attacks",
                "Operating system theme",
                "Screen resolution"
            ],
            "answer": 1,
            "explanation": "More resources → larger, more sophisticated campaigns."
        },
        {
            "q": "Script kiddies typically use _______.",
            "options": [
                "Only zero-days they developed",
                "Pre-made tools with little understanding",
                "Quantum cryptanalysis",
                "Hardware implants exclusively"
            ],
            "answer": 1,
            "explanation": "They rely on existing scripts/exploits without deep expertise."
        },
        {
            "q": "Highly resourced, stealthy, long-term intrusions characterize _______.",
            "options": [
                "Spam lists",
                "Pen test scopes",
                "APTs",
                "Bug trackers"
            ],
            "answer": 2,
            "explanation": "Advanced Persistent Threats maintain undetected presence for long periods."
        },
        {
            "q": "Hacktivists most often target organizations they view as _______.",
            "options": [
                "Best at cybersecurity",
                "Low bandwidth only targets",
                "Outside their geography only",
                "Acting unethically or against their cause"
            ],
            "answer": 3,
            "explanation": "Targets are chosen based on ideological opposition."
        },
        {
            "q": "Organized cybercrime groups primarily seek _______.",
            "options": [
                "Standards compliance",
                "Financial gain",
                "Open research access",
                "Election oversight"
            ],
            "answer": 1,
            "explanation": "Their core driver is profit (ransomware, fraud, etc.)."
        },
        {
            "q": "Nation-state actors may conduct false flag attacks to _______.",
            "options": [
                "Aid lawful intercept",
                "Misattribute the source of an operation",
                "Increase CPU clock speeds",
                "Reduce DNS TTL values"
            ],
            "answer": 1,
            "explanation": "False flags try to blame another actor/group."
        },
        {
            "q": "Insider threats are potent because they _______.",
            "options": [
                "Only attack from home",
                "Always use zero-days",
                "Never make mistakes",
                "Have legitimate access and internal knowledge"
            ],
            "answer": 3,
            "explanation": "Legitimate credentials + process knowledge ⇒ higher potential damage."
        },
        {
            "q": "Shadow IT is best described as _______.",
            "options": [
                "Vendor-supported SaaS",
                "Unapproved IT systems/services used without explicit approval",
                "Open-source software in CI/CD",
                "External pen-test firms"
            ],
            "answer": 1,
            "explanation": "Shadow IT runs outside sanctioned IT governance."
        },
        {
            "q": "A common driver for shadow IT is _______.",
            "options": [
                "Abundance of GPUs",
                "Availability of IPv6",
                "Security processes that are overly complex or slow",
                "Excess office space"
            ],
            "answer": 2,
            "explanation": "Overly rigid processes lead users to bypass IT."
        },
        {
            "q": "Which example is shadow IT?",
            "options": [
                "FIPS-validated encryption",
                "Patching servers during a maintenance window",
                "Using personal cloud storage for work files without approval",
                "Documented MDM onboarding"
            ],
            "answer": 2,
            "explanation": "Unapproved cloud storage for org data = shadow IT."
        },
        {
            "q": "Threat vector refers to the _______.",
            "options": [
                "Means/pathway used to carry out an attack",
                "Legal framework for privacy",
                "Asset inventory",
                "Sum of all vulnerabilities"
            ],
            "answer": 0,
            "explanation": "Vector = pathway into the system (HOW)."
        },
        {
            "q": "Attack surface refers to the _______.",
            "options": [
                "Sum of potential entry/exit points",
                "Only external IPs",
                "CSP vendor SLAs",
                "Exact phishing email subject"
            ],
            "answer": 0,
            "explanation": "Attack surface = WHERE attacks could occur."
        },
        {
            "q": "Which increases an organization’s attack surface?",
            "options": [
                "Enabling instant messaging company-wide",
                "Patching to latest baseline",
                "Network segmentation",
                "Removing unused services"
            ],
            "answer": 0,
            "explanation": "More comms channels ⇒ more entry points."
        },
        {
            "q": "Message-based vectors frequently involve _______.",
            "options": [
                "Fiber tapping only",
                "Firmware reflashing only",
                "Only physical lock-picking",
                "Phishing via email/SMS/IM"
            ],
            "answer": 3,
            "explanation": "Messages are a common phish/malware delivery route."
        },
        {
            "q": "Image-based vectors often leverage _______.",
            "options": [
                "Rootkit drivers exclusively",
                "Only plaintext attachments",
                "Steganography or image-embedded code",
                "SMBv1 shares"
            ],
            "answer": 2,
            "explanation": "Malicious code can be hidden within images."
        },
        {
            "q": "File-based vectors commonly deliver _______.",
            "options": [
                "Malware disguised as legitimate files",
                "NTP offsets",
                "Certificate pinning",
                "Thermal telemetry"
            ],
            "answer": 0,
            "explanation": "Malicious docs/installers masquerade as legit content."
        },
        {
            "q": "Vishing is _______.",
            "options": [
                "Virtualization escape",
                "VPN tunneling",
                "Voice-call social engineering",
                "Video injection"
            ],
            "answer": 2,
            "explanation": "Vishing uses phone calls to elicit secrets or actions."
        },
        {
            "q": "A typical “baiting” technique uses _______.",
            "options": [
                "Randomized MAC addresses for privacy",
                "Malware-infected USB drives left for targets to find",
                "TLS mutual auth",
                "Full disk encryption"
            ],
            "answer": 1,
            "explanation": "Infected removable media tempt users to plug them in."
        },
        {
            "q": "Evil twin attacks relate to _______.",
            "options": [
                "ARP table aging",
                "Rogue Wi‑Fi APs mimicking legitimate networks",
                "RA Guard on switches",
                "UEFI Secure Boot"
            ],
            "answer": 1,
            "explanation": "Fake APs capture traffic/credentials."
        },
        {
            "q": "BlueBorne exploits target _______.",
            "options": [
                "Bluetooth vulnerabilities",
                "L2TP tunnels",
                "RAID controllers",
                "Only SMTP relays"
            ],
            "answer": 0,
            "explanation": "BlueBorne abuses Bluetooth stacks."
        },
        {
            "q": "A honeypot is _______.",
            "options": [
                "An IDS signature set",
                "A DLP policy engine",
                "A production backup server",
                "A decoy system to attract attackers and study TTPs"
            ],
            "answer": 3,
            "explanation": "Honeypots lure attackers to observe techniques."
        },
        {
            "q": "A honeynet differs from a honeypot by _______.",
            "options": [
                "Emulating an entire network of decoy systems",
                "Only running on mobile",
                "Requiring air-gaps",
                "Being cloud-only"
            ],
            "answer": 0,
            "explanation": "Honeynet = multiple coordinated decoys."
        },
        {
            "q": "A honeyfile typically includes _______.",
            "options": [
                "Physical key locks",
                "Firmware flashing tools",
                "Fake sensitive content with identifiers/watermarks",
                "CA root certs"
            ],
            "answer": 2,
            "explanation": "Honeyfiles alert on access and may be watermarked."
        },
        {
            "q": "A honeytoken is _______.",
            "options": [
                "A TPM NV index",
                "A TLS session ticket",
                "A FIDO2 hardware key",
                "Monitored fake data/credential with no legitimate use"
            ],
            "answer": 3,
            "explanation": "Any access to it is suspicious by definition."
        },
        {
            "q": "Bogus DNS entries are used to _______.",
            "options": [
                "Accelerate CDN caching",
                "Mislead and trap attackers while generating alerts",
                "Force OCSP stapling",
                "Enable DHCP snooping"
            ],
            "answer": 1,
            "explanation": "They waste attacker effort and signal probing."
        },
        {
            "q": "Decoy directories primarily _______.",
            "options": [
                "Lower MTTR automatically",
                "Divert intruders and trigger alerts on access",
                "Improve backup throughput",
                "Enforce MFA"
            ],
            "answer": 1,
            "explanation": "They distract and instrument attacker actions."
        },
        {
            "q": "Dynamic page generation can _______.",
            "options": [
                "Confuse scrapers/bots with ever-changing content",
                "Break PKI by default",
                "Disable TLS",
                "Replace WAFs entirely"
            ],
            "answer": 0,
            "explanation": "A tactic to slow/obscure automated collection."
        },
        {
            "q": "Port triggering helps by _______.",
            "options": [
                "Auto-rotating secrets hourly",
                "Keeping services closed until specific outbound patterns occur",
                "Performing code signing",
                "Enforcing SELinux"
            ],
            "answer": 1,
            "explanation": "Services remain hidden unless legitimately triggered."
        },
        {
            "q": "Spoofing fake telemetry during scans _______.",
            "options": [
                "Hardens ECC curves",
                "Prevents TLS renegotiation",
                "Optimizes BGP pathing",
                "Misleads attackers about OS/services to waste exploits"
            ],
            "answer": 3,
            "explanation": "False data frustrates recon and exploit selection."
        },
        {
            "q": "FIN7 and Carbanak are known for _______.",
            "options": [
                "Open-source defensive platforms",
                "Academic-only research",
                "Organized cybercrime operations with advanced phishing/malware",
                "Nation-state election monitoring"
            ],
            "answer": 2,
            "explanation": "Both exemplify organized, profit-driven cybercrime."
        },
        {
            "q": "Stuxnet is a classic example of _______.",
            "options": [
                "TLS downgrade attack",
                "Generic adware",
                "Spam botnet sinkholing",
                "Nation-state malware targeting industrial control systems"
            ],
            "answer": 3,
            "explanation": "It targeted Iranian nuclear centrifuges via ICS/air-gap bridging."
        },
        {
            "q": "An APT maintaining access for months undetected is focusing on _______.",
            "options": [
                "Persistence and stealth for espionage/sabotage",
                "License compliance",
                "Immediate ransom payout",
                "SEO ranking boosts"
            ],
            "answer": 0,
            "explanation": "Long dwell time supports espionage and staged objectives."
        },
        {
            "q": "The 2020 Twitter incident highlighted _______.",
            "options": [
                "Risks from insiders assisting external attackers",
                "Quantum key distribution",
                "Only firmware attacks",
                "TLS certificate revocation"
            ],
            "answer": 0,
            "explanation": "External attacker collab with insiders led to high‑profile account access."
        },
        {
            "q": "Reducing attack surface commonly involves _______.",
            "options": [
                "Relying on default passwords",
                "Adding random browser extensions",
                "Removing unnecessary services and standardizing builds",
                "Using shared admin accounts"
            ],
            "answer": 2,
            "explanation": "Hardening and standardization shrink exposure."
        },
        {
            "q": "Which BEST counters shadow IT data leakage?",
            "options": [
                "Disable all internet access always",
                "Only verbal reminders",
                "Approved cloud storage with DLP and training",
                "Allow unrestricted USB use"
            ],
            "answer": 2,
            "explanation": "Provide sanctioned alternatives + policy + DLP."
        },
        {
            "q": "Which statement about insider threats is MOST accurate?",
            "options": [
                "They are less dangerous than outsiders.",
                "They always require admin rights.",
                "They may be intentional or unintentional (careless).",
                "They are only possible in small companies."
            ],
            "answer": 2,
            "explanation": "Mistakes by well-meaning staff also create incidents."
        },
        {
            "q": "A false flag operation aims to _______.",
            "options": [
                "Lower latency to CDNs",
                "Cause investigators to blame another actor",
                "Increase entropy in keys",
                "Improve IDS recall"
            ],
            "answer": 1,
            "explanation": "Core purpose is misattribution."
        },
        {
            "q": "BlueSmack is a _______.",
            "options": [
                "VoIP SIP fuzzing tool",
                "Browser XSS filter",
                "Bluetooth-based DoS attack",
                "PDF macro payload"
            ],
            "answer": 2,
            "explanation": "BlueSmack floods Bluetooth logical link control."
        },
        {
            "q": "Evil twin defenses include _______.",
            "options": [
                "Wider channel bonding only",
                "Disabling DHCP globally",
                "Overclocking CPUs",
                "Wireless IDS/WIPS and user training"
            ],
            "answer": 3,
            "explanation": "WIDS/WIPS + awareness help detect/avoid rogue APs."
        },
        {
            "q": "Which example BEST illustrates vishing?",
            "options": [
                "Drive-by download via banner ad",
                "DNS cache poisoning",
                "Caller posing as a bank demanding SSN for “verification”",
                "HTML email with tracking pixel"
            ],
            "answer": 2,
            "explanation": "Voice-call social engineering for secrets."
        }
    ],
    "unit-4": [
        { q: 'What is the main purpose of fencing in physical security?', options: ['To deter and delay intruders', 'To improve building aesthetics', 'To mark company property for zoning compliance', 'To redirect vehicle traffic'], answer: 0, explanation: 'Fencing acts as a visual and physical barrier to delay intruders and define boundaries.' },
        { q: 'Which material is LEAST effective for high-security fencing?', options: ['Chain link', 'Reinforced concrete', 'Barbed wire', 'Electric fencing'], answer: 0, explanation: 'Chain link can be cut easily compared to reinforced or electrified options.' },
        { q: 'Bollards are primarily used to protect against _______.', options: ['Vehicular threats', 'Unauthorized personnel access', 'Fire hazards', 'Falling debris'], answer: 0, explanation: 'Bollards are short posts designed to block or redirect vehicles, not people.' },
        { q: 'A bollard rated ASTM F2656-07 M30 P1 can stop a 15,000-pound vehicle traveling at _______.', options: ['30 mph', '15 mph', '45 mph', '60 mph'], answer: 0, explanation: 'The M30 rating corresponds to stopping a 15,000 lb vehicle at 30 mph.' },
        { q: 'Which statement BEST distinguishes fencing from bollards?', options: ['Fencing stops people; bollards stop vehicles', 'Fencing is temporary; bollards are always permanent', 'Bollards require electricity; fences do not', 'Both are used only indoors'], answer: 0, explanation: 'Fencing is primarily for personnel boundaries, bollards for vehicular control.' },
        { q: 'In physical security, a brute-force attack commonly refers to _______.', options: ['Forcible entry through physical barriers', 'Guessing password combinations', 'Wireless jamming', 'Lock picking via code analysis'], answer: 0, explanation: 'In physical contexts, brute force means forcibly bypassing doors, windows, or barriers.' },
        { q: 'Which of the following is NOT considered a brute-force physical attack?', options: ['Ramming barriers with vehicles', 'Tampering with security cameras', 'Exploiting software vulnerabilities', 'Confronting security guards'], answer: 2, explanation: 'Software exploitation is a cyber attack, not a physical brute-force method.' },
        { q: 'Which feature most effectively resists door brute-force entry?', options: ['Metal frame with solid core and deadbolt', 'Glass paneling with decorative trim', 'Wood frame and standard knob lock', 'Automatic door closer'], answer: 0, explanation: 'Reinforced doors with deadbolts and metal frames resist impact and prying.' },
        { q: 'Tampering with security devices is best mitigated by _______.', options: ['Redundant sensors and cameras', 'Turning off lights at night', 'Limiting alarm notifications', 'Posting fewer warning signs'], answer: 0, explanation: 'Redundancy ensures continued protection if one device is disabled.' },
        { q: 'Ramming a barrier with a vehicle can be countered by _______.', options: ['Installing heavy-duty bollards', 'Reducing camera coverage', 'Training guards to retreat', 'Replacing glass with lighter material'], answer: 0, explanation: 'Bollards dissipate impact energy and block vehicles.' },
        { q: 'CCTV systems are classified as which type of control?', options: ['Detective', 'Preventive', 'Corrective', 'Compensating'], answer: 0, explanation: 'Surveillance systems detect and record events, making them detective controls.' },
        { q: 'What advantage do PTZ (Pan-Tilt-Zoom) cameras provide?', options: ['Active movement for broader coverage', 'Static footage for storage efficiency', 'Audio capture only', 'Higher encryption'], answer: 0, explanation: 'PTZ cameras can pan, tilt, and zoom to track activity dynamically.' },
        { q: 'Which condition makes wireless cameras less reliable?', options: ['Signal interference and jamming', 'Low battery drain', 'High-resolution capability', 'Ease of installation'], answer: 0, explanation: 'Wireless cameras can be jammed or disrupted via frequency interference.' },
        { q: 'Proper lighting supports surveillance by _______.', options: ['Reducing shadows and aiding visibility', 'Saving electricity', 'Preventing cyber intrusions', 'Eliminating sensor use'], answer: 0, explanation: 'Lighting improves camera visibility and deters intruders.' },
        { q: 'Pressure sensors detect _______.', options: ['Weight changes on a surface', 'Infrared radiation', 'Sound vibrations', 'Radio frequencies'], answer: 0, explanation: 'Pressure sensors trigger when weight is applied on floors or mats.' },
        { q: 'Spray painting a camera lens is an example of _______.', options: ['Visual obstruction', 'Infrared tampering', 'Acoustic interference', 'Electromagnetic jamming'], answer: 0, explanation: 'Covering or painting over lenses visually obstructs the camera.' },
        { q: 'Using a laser pointer to disable a camera temporarily exploits which vulnerability?', options: ['Blinding sensors', 'Cutting power', 'Network spoofing', 'Audio masking'], answer: 0, explanation: 'Bright lights or lasers overwhelm optical sensors.' },
        { q: 'Electromagnetic interference (EMI) attacks can disable _______.', options: ['Wireless surveillance links', 'Lock bolts', 'Concrete reinforcements', 'Badge laminations'], answer: 0, explanation: 'EMI disrupts wireless signals between sensors and control systems.' },
        { q: 'Which countermeasure helps prevent jamming attacks?', options: ['Frequency hopping and signal encryption', 'Installing more mirrors', 'Using fluorescent lighting', 'Disabling backup power'], answer: 0, explanation: 'Encrypted, frequency-hopping systems resist jamming and interference.' },
        { q: 'Tamper alarms on cameras primarily protect against _______.', options: ['Physical obstruction or disconnection', 'High humidity', 'Overheating', 'False negatives'], answer: 0, explanation: 'Tamper alarms alert when cameras are moved or blocked.' },
        { q: 'An access control vestibule ensures _______.', options: ['Only one door opens at a time', 'Both doors remain open for quick access', 'Unlimited simultaneous entry', 'Emergency power distribution'], answer: 0, explanation: 'Vestibules electronically restrict one door at a time for screening.' },
        { q: 'Piggybacking differs from tailgating because _______.', options: ['Piggybacking involves consent; tailgating does not', 'Both require collusion', 'Tailgating requires credentials', 'Piggybacking is unintentional'], answer: 0, explanation: 'Piggybacking is intentional assistance, tailgating is unintentional following.' },
        { q: 'Access badges use which technologies for authentication?', options: ['RFID, NFC, or magnetic strip', 'TLS certificates', 'Bluetooth LE only', 'Infrared pulses'], answer: 0, explanation: 'Modern badges rely on RFID, NFC, or magnetic strips for access control.' },
        { q: 'What log data is generated by access badge use?', options: ['Time and identity of entry', 'Camera footage', 'Network packet data', 'Thermal readings'], answer: 0, explanation: 'Access logs record who entered and when, providing audit trails.' },
        { q: 'Which combination offers multi-factor authentication?', options: ['Badge plus PIN', 'Two badges', 'Password only', 'Single RFID scan'], answer: 0, explanation: 'Badge (something you have) + PIN (something you know) = MFA.' },
        { q: 'Why are padlocks considered weak physical security?', options: ['They can be picked quickly with simple tools', 'They require unique keys', 'They are weatherproof', 'They prevent tailgating'], answer: 0, explanation: 'Padlocks use simple pin mechanisms easily bypassed by lockpicks.' },
        { q: 'Biometric locks verify users based on _______.', options: ['Physical characteristics', 'PIN length', 'Password strength', 'Badge color'], answer: 0, explanation: 'Biometric locks use fingerprints, facial recognition, or retinas.' },
        { q: 'Which metric compares false acceptance and false rejection rates?', options: ['Crossover Error Rate (CER)', 'Access Denial Ratio', 'Authentication Window Index', 'False Positive Index'], answer: 0, explanation: 'CER or Equal Error Rate indicates the balance of biometric accuracy.' },
        { q: 'A cipher lock operates using _______.', options: ['Mechanical push buttons with numeric codes', 'Magnetic field sensors', 'RF signals only', 'Bluetooth chips'], answer: 0, explanation: 'Cipher locks use numbered push buttons to open doors mechanically.' },
        { q: 'Combining a fingerprint and PIN to unlock a door represents _______.', options: ['Multi-factor authentication', 'Biometric spoofing', 'Single sign-on', 'One-time password'], answer: 0, explanation: 'Two authentication factors increase access security.' },
        { q: 'Access badge cloning copies data from _______.', options: ['RFID or NFC badges', 'Smartphone cameras', 'VPN tunnels', 'Encrypted ZIP files'], answer: 0, explanation: 'Badge cloning duplicates data from RFID or NFC systems.' },
        { q: 'Which device is known for RFID cloning in penetration testing?', options: ['Flipper Zero', 'HackRF One', 'YubiKey', 'TPM module'], answer: 0, explanation: 'Flipper Zero is a handheld tool often used to clone RFID tags.' },
        { q: 'Which step immediately follows badge data capture?', options: ['Data extraction', 'Writing firmware', 'Device encryption', 'Power calibration'], answer: 0, explanation: 'After reading a badge, data is extracted before cloning.' },
        { q: 'Which practice BEST mitigates cloning attacks?', options: ['Encrypting badge data and adding MFA', 'Using basic RFID tags', 'Reducing badge logging', 'Shorter antenna range only'], answer: 0, explanation: 'Encryption and MFA make cloned badges useless.' },
        { q: 'RFID shielded sleeves prevent _______.', options: ['Unauthorized scanning', 'Moisture buildup', 'Wear and tear', 'Badge aging'], answer: 0, explanation: 'Shielded sleeves block radio waves that could read a badge remotely.' }
    ],
    "unit-5": [
        { q: 'Social engineering primarily exploits _______.', options: ['Human psychology', 'Patch management gaps', 'Weak cryptography', 'Power redundancy'], answer: 0, explanation: 'Social engineering targets people, not just technology, to gain access or data.' },
        { q: 'Which channels can social engineering operate through?', options: ['Written communication and in‑person interaction', 'Written only', 'In‑person only', 'Encrypted channels only'], answer: 0, explanation: 'It includes email, SMS, calls, chats, and face‑to‑face interactions.' },
        { q: 'An email signed by the “CFO” ordering a wire transfer is abusing which trigger?', options: ['Authority', 'Scarcity', 'Likability', 'Social proof'], answer: 0, explanation: 'Perceived authority drives compliance even without verification.' },
        { q: '“Reset your password in the next 5 minutes or your account is deleted.” This leverages _______.', options: ['Urgency', 'Fear only', 'Social proof', 'Scarcity only'], answer: 0, explanation: 'Time pressure reduces scrutiny; often paired with fear.' },
        { q: '“Everyone in your team already completed this training—sign now.” is an example of _______.', options: ['Social proof', 'Authority', 'Scarcity', 'Likability'], answer: 0, explanation: 'People follow perceived group behavior.' },
        { q: '“Only 5 discounted licenses left—claim yours.” exploits _______.', options: ['Scarcity', 'Likability', 'Authority', 'Fear'], answer: 0, explanation: 'Limited availability pushes quick actions.' },
        { q: 'Flirtation and finding shared interests to lower suspicion is using _______.', options: ['Likability', 'Authority', 'Urgency', 'Scarcity'], answer: 0, explanation: 'Attackers seek to be liked to gain trust and information.' },
        { q: 'Ransomware threatening data loss unless paid relies on _______.', options: ['Fear (often with authority pretext)', 'Scarcity only', 'Social proof', 'Likability'], answer: 0, explanation: 'Fear of harm is a strong motivator; sometimes paired with faux authority.' },
        { q: 'Impersonation attacks are MOST effective when _______.', options: ['The attacker has org-specific details', 'They use only generic scripts', 'No pretext is provided', 'They avoid speaking to humans'], answer: 0, explanation: 'Specifics (names, offices, systems) increase credibility.' },
        { q: 'Brand impersonation commonly appears in _______.', options: ['Phishing emails and spoofed sites', 'Firmware flashing only', 'Physical badge cloning', 'DNSSEC key rollover'], answer: 0, explanation: 'Logos and language mimic legitimate brands to trick users.' },
        { q: 'Typosquatting best describes _______.', options: ['Registering look‑alike domains with common misspellings', 'Listening in on phone calls', 'Brute‑forcing a password', 'Abusing default certificates'], answer: 0, explanation: 'E.g., paypaI.com (capital i) vs paypal.com.' },
        { q: 'A watering‑hole attack compromises _______.', options: ['A site the target group already visits', 'The target’s MFA app directly', 'Only email MX records', 'An air‑gapped workstation'], answer: 0, explanation: 'Attackers poison trusted “watering” places used by victims.' },
        { q: 'Pretexting relies on _______.', options: ['A fabricated scenario to elicit info or actions', 'Packet injection into TLS', 'Lock picking with bump keys', 'Password spraying'], answer: 0, explanation: 'The story makes the request feel normal and urgent/important.' },
        { q: 'Which request is MOST indicative of a pretexting call to a help desk?', options: ['“Reset my password right now—CIO needs a report in 10 minutes.”', '“How is the weather?”', '“Please approve a routine change next week.”', '“What is your lunch order?”'], answer: 0, explanation: 'Combines authority/urgency to bypass normal verification.' },
        { q: 'Phishing differs from spear phishing because phishing is usually _______.', options: ['Mass, non‑targeted', 'Voice‑based only', 'SMS‑based only', 'Executive‑only'], answer: 0, explanation: 'Phishing casts a wide net; spear phishing is targeted.' },
        { q: 'Whaling specifically targets _______.', options: ['High‑profile executives (e.g., CEO/CFO)', 'New hires only', 'IT interns only', 'Any external vendor by default'], answer: 0, explanation: 'Executives approve big transactions; high payoff.' },
        { q: 'Business Email Compromise (BEC) typically involves _______.', options: ['Using a compromised internal account to request money/data', 'Only spoofed caller IDs', 'Only SMS lures', 'Exploiting default SNMP strings'], answer: 0, explanation: 'Legitimate accounts are used to send convincing requests.' },
        { q: 'Vishing primarily uses _______.', options: ['Phone/voice calls', 'QR codes', 'Forum DMs', 'USB drops'], answer: 0, explanation: 'Voice phishing leverages calls and IVR tricks.' },
        { q: 'Smishing primarily uses _______.', options: ['SMS/text messages', 'Voice calls', 'Email', 'NFC'], answer: 0, explanation: 'SMS delivery with links/numbers to call.' },
        { q: 'Which is the BEST first response to a suspected phishing email?', options: ['Report it per policy and avoid clicking links', 'Reply to verify sender identity', 'Open the attachment carefully', 'Forward to friends to ask opinions'], answer: 0, explanation: 'Follow reporting policy; do not interact with content.' },
        { q: 'Hovering over a link reveals a different destination than the display text. This is a _______.', options: ['Mismatched URL indicator', 'Normal branding practice', 'Benign tracking pixel', 'SPF alignment proof'], answer: 0, explanation: 'Display text may hide a malicious underlying URL.' },
        { q: 'Which sender detail is MOST suspicious?', options: ['Display name says “PayPal” but the actual address is random@yahoo.com', 'Display name matches the From domain', 'DMARC alignment passes', 'Signed with a valid corporate certificate'], answer: 0, explanation: 'Look beyond the display name to the real From address.' },
        { q: 'What is TRUE about grammar/spelling as a phishing signal today?', options: ['Still useful, but attackers can write clean emails too', 'It no longer occurs in phishing', 'Only non‑English emails contain errors', 'It guarantees the email is benign'], answer: 0, explanation: 'Errors are common but not required; treat clean emails with care also.' },
        { q: 'A company’s anti‑phishing program should include _______.', options: ['Ongoing training + simulated campaigns + remedial training', 'A single annual memo', 'Blocking all external mail', 'Replacing MFA'], answer: 0, explanation: 'Iterative training with tests and feedback drives improvement.' },
        { q: 'Identity fraud vs identity theft: which is MOST accurate?', options: ['Fraud may use pieces of identity for transactions; theft attempts to fully assume identity', 'They are unrelated', 'Fraud requires new SSN issuance', 'Theft always uses credit cards only'], answer: 0, explanation: 'Fraud often misuses credentials; theft impersonates the person.' },
        { q: 'A classic invoice scam tries to _______.', options: ['Trick orgs into paying for unordered goods/services', 'Exploit TLS renegotiation', 'Poison ARP caches', 'Replace backup tapes'], answer: 0, explanation: 'It fabricates legitimacy with calls/emails and inflated invoices.' },
        { q: 'Opening a phony PDF invoice that runs code is BEST described as _______.', options: ['Malicious attachment delivering a RAT', 'Benign previewing', 'Safe because it is a PDF', 'A watering‑hole attack'], answer: 0, explanation: 'PDFs can contain active content that drops malware.' },
        { q: 'Misinformation is _______.', options: ['False info shared without intent to deceive', 'Deliberate falsehoods to mislead', 'Always political', 'Only from nation‑states'], answer: 0, explanation: 'Intent distinguishes misinformation (no intent) from disinformation (intentional).' },
        { q: 'Disinformation is _______.', options: ['Deliberately false content intended to deceive', 'An email confidentiality label', 'Benign errors in data entry', 'Only health advice errors'], answer: 0, explanation: 'It’s false on purpose to manipulate opinions/behavior.' },
        { q: 'Which platform dynamic amplifies influence campaigns?', options: ['Rapid, unvetted social sharing', 'Air‑gapped networks', 'Tape backups', 'ECC RAM'], answer: 0, explanation: 'Virality enables quick spread of mis/disinformation.' },
        { q: 'Diversion theft in cyber contexts often uses _______.', options: ['DNS spoofing to redirect to fake sites', 'Upgrading Elliptic Curve Cryptography keys for better security', '802.1X NAC', 'RAID 10'], answer: 0, explanation: 'Traffic is diverted to attacker‑controlled destinations.' },
        { q: 'A hoax warning pop‑up about “Windows malware” on a Mac is BEST handled by _______.', options: ['Closing it and validating via trusted tools', 'Paying the fee to clean it', 'Calling the number in the pop‑up', 'Ignoring corporate policy to act quickly'], answer: 0, explanation: 'Treat as a hoax; verify via official channels only.' },
        { q: 'Shoulder surfing defenses include _______.', options: ['Privacy screens and keypad shields', 'Disabling HTTPS', 'Lowering monitor brightness only', 'Raising HVAC temperature'], answer: 0, explanation: 'Reduce visual exposure and observe surroundings.' },
        { q: 'Dumpster diving risk is reduced by _______.', options: ['Shredding + clean desk policy', 'Leaving bins unlocked', 'Relying on obscurity', 'Emailing documents to personal inboxes'], answer: 0, explanation: 'Shred sensitive docs; lock up material; minimize paper.' },
        { q: 'Digital “dumpster diving” is BEST mitigated by _______.', options: ['Secure deletion and retention policies', 'Hiding files with dots', 'Renaming extensions', 'Turning off the monitor'], answer: 0, explanation: 'Use proper wiping/versioning; manage lifecycle.' },
        { q: 'Eavesdropping on networks is also called _______.', options: ['On‑path / man‑in‑the‑middle interception', 'Sending unsolicited messages via Bluetooth connections', 'War‑driving', 'NFC beaming'], answer: 0, explanation: 'Adversary intercepts communications between parties.' },
        { q: 'Baiting commonly involves _______.', options: ['Malicious USB media left for victims to plug in', 'Only QR codes', 'Shoulder‑surfing', 'Cold‑boot attacks'], answer: 0, explanation: 'Curiosity lures victims to run malware.' },
        { q: 'Tailgating vs piggybacking: which is correct?', options: ['Tailgating = following without consent; piggybacking = allowed in by someone', 'They are identical', 'Both always require stolen badges', 'Piggybacking is always unintentional'], answer: 0, explanation: 'Consent of the authorized person distinguishes them.' },
        { q: 'Which combination MOST helps against BEC?', options: ['MFA, payment verification procedures, and user training', 'Blocking all attachments', 'VPN only', 'Weekly password changes only'], answer: 0, explanation: 'Out‑of‑band verification + MFA + awareness reduces BEC success.' },
        { q: 'To reduce watering‑hole risk, prioritize _______.', options: ['Patch hygiene and reputation/intel feeds', 'Disabling all browsers', 'Accepting unsigned code', 'Turning off logs'], answer: 0, explanation: 'Keep software updated; monitor TI for compromised sites.' },
        { q: 'A robust anti‑phishing culture encourages users to _______.', options: ['Report suspicious messages promptly', 'Self‑remediate silently', 'Forward to friends first', 'Disable spam filters'], answer: 0, explanation: 'Fast reporting allows quick enterprise triage.' },
        { q: 'The BEST way to check a “LinkedIn” email request is to _______.', options: ['Open a fresh browser and navigate directly to linkedin.com', 'Click the email’s link quickly', 'Reply with your password', 'Ignore policy if it seems urgent'], answer: 0, explanation: 'Validate via a known‑good path instead of embedded links.' },
        { q: 'A receptionist asked for a printer’s IP during a toner call should _______.', options: ['Refuse and route the request through policy/support channels', 'Read it over the phone', 'Email it to any requester', 'Post it on a wiki'], answer: 0, explanation: 'Never divulge internal info without verification and need‑to‑know.' },
        { q: 'Which statement about simulated phishing is MOST accurate?', options: ['It provides practical practice and identifies users needing remedial training', 'It guarantees zero phishing incidents', 'It replaces technical controls', 'It should be done once per decade'], answer: 0, explanation: 'Training + testing builds resilience; it complements controls.' },
        { q: 'A text “Your package failed to deliver—pay $1 to reschedule: <short link>.” is MOST likely _______.', options: ['Smishing', 'BEC', 'Whaling', 'Vishing'], answer: 0, explanation: 'SMS lure with a link: classic smishing.' },
        { q: 'Caller claims to be HR and asks for SSN to “verify your profile now.” This is _______.', options: ['Vishing with pretexting', 'Benign identity proofing', 'BEC by definition', 'A watering‑hole attack'], answer: 0, explanation: 'Telephone lure + fabricated scenario = vishing + pretexting.' },
        { q: 'You receive “CEO: urgent wire $95K to vendor today.” From address is legit CEO account. This indicates _______.', options: ['A likely BEC using a compromised mailbox', 'A harmless auto‑reply', 'A QR phishing attempt', 'A spear phish with spoofed domain only'], answer: 0, explanation: 'Compromised account makes the request highly convincing.' },
        { q: 'Employee holds the door for someone carrying boxes after badge swipe. This is _______.', options: ['Piggybacking', 'Tailgating', 'Dumpster diving', 'Diversion theft'], answer: 0, explanation: 'Attacker was let in with consent (helpfulness).' },
        { q: 'Unknown person slips in behind an employee without being noticed. This is _______.', options: ['Tailgating', 'Piggybacking', 'Baiting', 'Hoaxing'], answer: 0, explanation: 'No consent from the authorized person.' },
        { q: 'USB drives found in parking lot and later cause infections. What failed?', options: ['User awareness and removable‑media policy', 'TLS configuration', 'UPS capacity planning', 'NTP drift'], answer: 0, explanation: 'Policy/training should forbid using unknown media.' },
        { q: 'Which statement about brand impersonation is TRUE?', options: ['Logos and visual language are copied to gain trust', 'It always uses perfect domains', 'It cannot affect stock prices', 'It only occurs on email'], answer: 0, explanation: 'It happens across email/social/web and can impact markets.' },
        { q: 'Typosquatting countermeasures include _______.', options: ['Registering common misspellings and monitoring new domains', 'Relying on users to notice', 'Blocking all TLDs', 'Turning off DNS'], answer: 0, explanation: 'Proactive registrations + domain monitoring reduce risk.' },
        { q: 'Which is the BEST example of social proof abuse?', options: ['Fake testimonials/likes encouraging clicks', 'A hardware token prompt', 'A signed driver', 'A DMARC reject policy'], answer: 0, explanation: 'Fabricated consensus pressures action.' },
        { q: 'The MOST appropriate response to a suspected influence campaign at work is _______.', options: ['Report and rely on vetted sources/fact‑checking', 'Amplify to raise awareness without checking', 'Ignore policy and post rebuttals', 'Disable all internet access'], answer: 0, explanation: 'Route through communications/security with verified intel.' }
    ],
    ...newUnits
}
