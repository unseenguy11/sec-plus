
export const unit16Questions = [
    {
        id: 1601,
        question: "Which port is used by the Secure Shell (SSH) protocol for secure remote terminal access?",
        options: [
            "Port 21",
            "Port 22",
            "Port 23",
            "Port 25"
        ],
        correctAnswer: "Port 22",
        explanation: "SSH uses port 22 to provide secure remote terminal access and file transfer capabilities."
    },
    {
        id: 1602,
        question: "Which firewall type operates at Layer 7 of the OSI model and can inspect traffic based on specific applications?",
        options: [
            "Packet Filtering Firewall",
            "Stateful Firewall",
            "Application Level Proxy",
            "Circuit Level Gateway"
        ],
        correctAnswer: "Application Level Proxy",
        explanation: "An Application Level Proxy (or Layer 7 firewall) conducts deep packet inspection to filter traffic for specific applications."
    },
    {
        id: 1603,
        question: "What is the primary function of a Screened Subnet (DMZ)?",
        options: [
            "To encrypt all internal network traffic",
            "To act as a buffer between the untrusted public network and the trusted internal network",
            "To replace the need for a firewall",
            "To store all sensitive internal data"
        ],
        correctAnswer: "To act as a buffer between the untrusted public network and the trusted internal network",
        explanation: "A Screened Subnet (formerly DMZ) provides a layer of security by isolating public-facing services from the internal network."
    },
    {
        id: 1604,
        question: "Which port is associated with the Domain Name System (DNS)?",
        options: [
            "Port 53",
            "Port 67",
            "Port 80",
            "Port 110"
        ],
        correctAnswer: "Port 53",
        explanation: "DNS uses port 53 (UDP and TCP) to translate domain names into IP addresses."
    },
    {
        id: 1605,
        question: "What is the main disadvantage of using a Packet Filtering Firewall?",
        options: [
            "It is very slow and resource-intensive",
            "It cannot prevent IP spoofing or complex attacks",
            "It requires a high-end server to run",
            "It blocks all traffic by default"
        ],
        correctAnswer: "It cannot prevent IP spoofing or complex attacks",
        explanation: "Packet filtering firewalls only inspect headers (IP/port) and cannot detect payload-based attacks or IP spoofing."
    },
    {
        id: 1606,
        question: "Which protocol is used for secure web browsing and operates on port 443?",
        options: [
            "HTTP",
            "FTP",
            "HTTPS",
            "SMTP"
        ],
        correctAnswer: "HTTPS",
        explanation: "HTTPS (Hypertext Transfer Protocol Secure) uses port 443 to encrypt web traffic."
    },
    {
        id: 1607,
        question: "What is the purpose of a Unified Threat Management (UTM) device?",
        options: [
            "To only filter email spam",
            "To combine multiple security functions (firewall, IDS/IPS, antivirus) into a single appliance",
            "To route traffic between different ISPs",
            "To manage physical door locks"
        ],
        correctAnswer: "To combine multiple security functions (firewall, IDS/IPS, antivirus) into a single appliance",
        explanation: "UTM devices integrate various security features like firewalls, intrusion prevention, and content filtering into one hardware solution."
    },
    {
        id: 1608,
        question: "Which port does the Remote Desktop Protocol (RDP) use by default?",
        options: [
            "3389",
            "1433",
            "445",
            "22"
        ],
        correctAnswer: "3389",
        explanation: "Microsoft's RDP uses port 3389 for remote desktop connections."
    },
    {
        id: 1609,
        question: "What is the difference between an inbound and an outbound port?",
        options: [
            "Inbound ports are for sending data, outbound are for receiving",
            "Inbound ports listen for connections, outbound ports are opened to initiate connections",
            "Inbound ports are always encrypted, outbound are not",
            "There is no difference"
        ],
        correctAnswer: "Inbound ports listen for connections, outbound ports are opened to initiate connections",
        explanation: "Servers keep inbound ports open to listen for requests, while clients open random outbound ports to initiate communication."
    },
    {
        id: 1610,
        question: "Which protocol is used for sending emails and operates on port 25?",
        options: [
            "POP3",
            "IMAP",
            "SMTP",
            "SNMP"
        ],
        correctAnswer: "SMTP",
        explanation: "SMTP (Simple Mail Transfer Protocol) is used for sending emails and typically uses port 25."
    },
    {
        id: 1611,
        question: "What is a 'Next-Generation Firewall' (NGFW) capable of that a traditional firewall is not?",
        options: [
            "Filtering traffic based on IP address",
            "Application awareness and deep packet inspection",
            "Blocking ports",
            "Routing packets"
        ],
        correctAnswer: "Application awareness and deep packet inspection",
        explanation: "NGFWs can identify specific applications (e.g., Facebook vs. LinkedIn) and inspect packet payloads, not just headers."
    },
    {
        id: 1612,
        question: "Which port is used by LDAP (Lightweight Directory Access Protocol)?",
        options: [
            "389",
            "636",
            "443",
            "80"
        ],
        correctAnswer: "389",
        explanation: "LDAP uses port 389 for directory service queries."
    },
    {
        id: 1613,
        question: "What does 'fail-open' mean for a security device?",
        options: [
            "The device shuts down completely",
            "The device allows traffic to pass through if it fails",
            "The device blocks all traffic if it fails",
            "The device restarts automatically"
        ],
        correctAnswer: "The device allows traffic to pass through if it fails",
        explanation: "Fail-open means that if the security control fails, it defaults to allowing access (prioritizing availability over security)."
    },
    {
        id: 1614,
        question: "Which secure file transfer protocol uses SSH and operates on port 22?",
        options: [
            "FTPS",
            "TFTP",
            "SFTP",
            "FTP"
        ],
        correctAnswer: "SFTP",
        explanation: "SFTP (SSH File Transfer Protocol) uses the SSH tunnel (port 22) to transfer files securely."
    },
    {
        id: 1615,
        question: "What is the function of an Intrusion Prevention System (IPS)?",
        options: [
            "To only log suspicious activity",
            "To detect and actively block malicious traffic",
            "To encrypt data at rest",
            "To manage user passwords"
        ],
        correctAnswer: "To detect and actively block malicious traffic",
        explanation: "Unlike an IDS which only alerts, an IPS sits inline and can actively block or drop malicious packets."
    },
    {
        id: 1616,
        question: "Which port is used for secure LDAP (LDAPS)?",
        options: [
            "389",
            "636",
            "993",
            "995"
        ],
        correctAnswer: "636",
        explanation: "LDAPS (LDAP over SSL) uses port 636."
    },
    {
        id: 1617,
        question: "What technology allows for the prioritization of network traffic to improve performance, often used in SD-WANs?",
        options: [
            "Quality of Service (QoS)",
            "VPN",
            "NAT",
            "DHCP"
        ],
        correctAnswer: "Quality of Service (QoS)",
        explanation: "QoS and traffic shaping allow networks to prioritize critical traffic (like voice or video) over less critical data."
    },
    {
        id: 1618,
        question: "Which protocol is used to retrieve email and leaves a copy on the server, allowing sync across multiple devices?",
        options: [
            "POP3",
            "SMTP",
            "IMAP",
            "SNMP"
        ],
        correctAnswer: "IMAP",
        explanation: "IMAP (Internet Message Access Protocol) allows users to view email on the server, supporting multiple device synchronization."
    },
    {
        id: 1619,
        question: "What is the purpose of a 'jump server' or 'jump box'?",
        options: [
            "To speed up internet connection",
            "To act as a secure gateway for administrators to access sensitive internal zones",
            "To host public websites",
            "To store backups"
        ],
        correctAnswer: "To act as a secure gateway for administrators to access sensitive internal zones",
        explanation: "A jump server is a hardened host used to access and manage devices in a separate security zone."
    },
    {
        id: 1620,
        question: "Which port is used by the SMB (Server Message Block) protocol for file sharing?",
        options: [
            "445",
            "139",
            "137",
            "21"
        ],
        correctAnswer: "445",
        explanation: "Modern SMB uses port 445 (Direct TCP) for file and printer sharing."
    },
    {
        id: 1621,
        question: "What is the main benefit of SASE (Secure Access Service Edge)?",
        options: [
            "It replaces all local hardware with cloud services",
            "It integrates network security and WAN capabilities into a cloud-native service",
            "It is free to use",
            "It only works for wired networks"
        ],
        correctAnswer: "It integrates network security and WAN capabilities into a cloud-native service",
        explanation: "SASE combines SD-WAN with security services (SWG, CASB, FWaaS) delivered from the cloud."
    },
    {
        id: 1622,
        question: "Which port is used by Telnet, an insecure remote access protocol?",
        options: [
            "21",
            "22",
            "23",
            "25"
        ],
        correctAnswer: "23",
        explanation: "Telnet uses port 23 and sends data in cleartext, making it insecure."
    },
    {
        id: 1623,
        question: "What is 'East-West' traffic in a data center?",
        options: [
            "Traffic entering from the internet",
            "Traffic leaving to the internet",
            "Traffic moving laterally between servers within the data center",
            "Traffic from the user to the server"
        ],
        correctAnswer: "Traffic moving laterally between servers within the data center",
        explanation: "East-West traffic refers to data flow between servers inside the data center, as opposed to North-South (client-server) traffic."
    },
    {
        id: 1624,
        question: "Which protocol uses ports 161 and 162 to manage network devices?",
        options: [
            "SMTP",
            "SNMP",
            "SSH",
            "SIP"
        ],
        correctAnswer: "SNMP",
        explanation: "SNMP (Simple Network Management Protocol) uses port 161 for queries and 162 for traps."
    },
    {
        id: 1625,
        question: "What is a 'sinkhole' in network security?",
        options: [
            "A physical hole in the server room",
            "A DNS server that redirects malicious traffic to a non-existent or controlled address",
            "A type of malware",
            "A backup location"
        ],
        correctAnswer: "A DNS server that redirects malicious traffic to a non-existent or controlled address",
        explanation: "DNS sinkholing is a technique to intercept DNS requests for known malicious domains and return a false IP address."
    },
    {
        id: 1626,
        question: "Which port is used by SQL Server (Microsoft)?",
        options: [
            "3306",
            "1433",
            "5432",
            "1521"
        ],
        correctAnswer: "1433",
        explanation: "Microsoft SQL Server listens on port 1433 by default."
    },
    {
        id: 1627,
        question: "What does 'fail-closed' mean?",
        options: [
            "The system remains open during a failure",
            "The system denies all traffic/access during a failure",
            "The system reboots",
            "The system alerts the admin"
        ],
        correctAnswer: "The system denies all traffic/access during a failure",
        explanation: "Fail-closed ensures that if a security control fails, no access is granted, prioritizing security over availability."
    },
    {
        id: 1628,
        question: "Which protocol is used for time synchronization across a network?",
        options: [
            "NTP",
            "FTP",
            "HTTP",
            "SSH"
        ],
        correctAnswer: "NTP",
        explanation: "NTP (Network Time Protocol) uses port 123 to synchronize clocks on network devices."
    },
    {
        id: 1629,
        question: "What is the purpose of a 'tap' in network monitoring?",
        options: [
            "To block traffic",
            "To copy traffic from a network link for analysis without interrupting the flow",
            "To amplify the signal",
            "To encrypt the traffic"
        ],
        correctAnswer: "To copy traffic from a network link for analysis without interrupting the flow",
        explanation: "A network tap is a hardware device that provides a way to access the data flowing across a computer network."
    },
    {
        id: 1630,
        question: "Which port is used by POP3 for unencrypted email retrieval?",
        options: [
            "110",
            "143",
            "995",
            "25"
        ],
        correctAnswer: "110",
        explanation: "POP3 uses port 110 for unencrypted connections."
    },
    {
        id: 1631,
        question: "What is the difference between a stateful and a stateless firewall?",
        options: [
            "Stateless is faster but less secure; Stateful tracks active connections",
            "Stateful is faster; Stateless tracks connections",
            "There is no difference",
            "Stateless firewalls are for home use only"
        ],
        correctAnswer: "Stateless is faster but less secure; Stateful tracks active connections",
        explanation: "Stateful firewalls maintain a state table of active connections to make decisions, while stateless (packet filtering) examine each packet in isolation."
    },
    {
        id: 1632,
        question: "Which port is used by TFTP (Trivial File Transfer Protocol)?",
        options: [
            "21",
            "69",
            "22",
            "80"
        ],
        correctAnswer: "69",
        explanation: "TFTP uses port 69 (UDP) and is often used for booting diskless workstations."
    },
    {
        id: 1633,
        question: "What is the primary security risk of using FTP (File Transfer Protocol)?",
        options: [
            "It is too slow",
            "It transmits credentials and data in cleartext",
            "It only works on Linux",
            "It cannot transfer large files"
        ],
        correctAnswer: "It transmits credentials and data in cleartext",
        explanation: "Standard FTP (port 21) sends usernames, passwords, and data unencrypted."
    },
    {
        id: 1634,
        question: "Which protocol is used for secure remote access VPNs and web traffic?",
        options: [
            "TLS/SSL",
            "PPTP",
            "L2TP",
            "WEP"
        ],
        correctAnswer: "TLS/SSL",
        explanation: "TLS (Transport Layer Security) is the standard for securing web traffic (HTTPS) and many VPNs."
    },
    {
        id: 1635,
        question: "What is the purpose of Port Security on a switch?",
        options: [
            "To physically lock the switch ports",
            "To restrict access to a port based on MAC addresses",
            "To encrypt traffic on the port",
            "To speed up the port"
        ],
        correctAnswer: "To restrict access to a port based on MAC addresses",
        explanation: "Port security allows an administrator to specify which MAC addresses are allowed to connect to a specific switch port."
    },
    {
        id: 1636,
        question: "Which port is used by NetBIOS Session Service?",
        options: [
            "137",
            "138",
            "139",
            "445"
        ],
        correctAnswer: "139",
        explanation: "NetBIOS Session Service uses port 139."
    },
    {
        id: 1637,
        question: "What is a 'honeypot'?",
        options: [
            "A sweet snack",
            "A decoy system designed to attract and monitor attackers",
            "A type of firewall",
            "A password manager"
        ],
        correctAnswer: "A decoy system designed to attract and monitor attackers",
        explanation: "A honeypot is a system set up to look like a legitimate target to lure attackers and study their methods."
    },
    {
        id: 1638,
        question: "Which protocol uses port 5060/5061 for Voice over IP (VoIP) signaling?",
        options: [
            "RTP",
            "SIP",
            "H.323",
            "MGCP"
        ],
        correctAnswer: "SIP",
        explanation: "SIP (Session Initiation Protocol) uses ports 5060 (unencrypted) and 5061 (encrypted/TLS) for signaling."
    },
    {
        id: 1639,
        question: "What is the function of a Load Balancer?",
        options: [
            "To weigh the servers",
            "To distribute network traffic across multiple servers to ensure availability",
            "To encrypt traffic",
            "To block traffic"
        ],
        correctAnswer: "To distribute network traffic across multiple servers to ensure availability",
        explanation: "Load balancers distribute incoming traffic among multiple servers to prevent overload and ensure high availability."
    },
    {
        id: 1640,
        question: "Which port is used by FTPS (FTP over SSL)?",
        options: [
            "21",
            "22",
            "990",
            "443"
        ],
        correctAnswer: "990",
        explanation: "Implicit FTPS typically uses port 990, while explicit FTPS uses port 21."
    }
];

export const unit17Questions = [
    {
        id: 1701,
        question: "What are the four main processes of Identity and Access Management (IAM)?",
        options: [
            "Identification, Authentication, Authorization, Accounting",
            "Identification, Encryption, Hashing, Salting",
            "Detection, Prevention, Correction, Recovery",
            "Planning, Doing, Checking, Acting"
        ],
        correctAnswer: "Identification, Authentication, Authorization, Accounting",
        explanation: "IAM consists of Identification (who you are), Authentication (proving it), Authorization (what you can do), and Accounting (tracking what you did)."
    },
    {
        id: 1702,
        question: "Which authentication factor category does a password belong to?",
        options: [
            "Something you have",
            "Something you are",
            "Something you know",
            "Something you do"
        ],
        correctAnswer: "Something you know",
        explanation: "Passwords, PINs, and security answers are 'Something you know' (Knowledge factor)."
    },
    {
        id: 1703,
        question: "What is the primary benefit of Multi-Factor Authentication (MFA)?",
        options: [
            "It is faster than single-factor",
            "It requires less user interaction",
            "It provides a layered defense, making it harder for attackers to compromise an account",
            "It eliminates the need for passwords"
        ],
        correctAnswer: "It provides a layered defense, making it harder for attackers to compromise an account",
        explanation: "MFA requires two or more different types of factors, significantly increasing security."
    },
    {
        id: 1704,
        question: "Which of the following is an example of 'Something you are'?",
        options: [
            "Smart card",
            "Fingerprint scan",
            "Password",
            "GPS location"
        ],
        correctAnswer: "Fingerprint scan",
        explanation: "Biometrics like fingerprints, facial recognition, and iris scans are 'Something you are' (Inherence factor)."
    },
    {
        id: 1705,
        question: "What is 'Single Sign-On' (SSO)?",
        options: [
            "Using the same password for everything",
            "A service that allows a user to log in once and access multiple applications",
            "Logging in with only one factor",
            "A password manager"
        ],
        correctAnswer: "A service that allows a user to log in once and access multiple applications",
        explanation: "SSO allows users to authenticate once and gain access to multiple systems without re-authenticating."
    },
    {
        id: 1706,
        question: "What is the concept of 'Least Privilege'?",
        options: [
            "Giving users the maximum access possible",
            "Giving users only the permissions necessary to perform their job functions",
            "Giving all users administrator access",
            "Restricting access based on time of day"
        ],
        correctAnswer: "Giving users only the permissions necessary to perform their job functions",
        explanation: "Least Privilege ensures users have the minimum necessary rights to do their work, reducing the attack surface."
    },
    {
        id: 1707,
        question: "Which protocol is commonly used for Federation and SSO?",
        options: [
            "SAML",
            "FTP",
            "SMTP",
            "SNMP"
        ],
        correctAnswer: "SAML",
        explanation: "SAML (Security Assertion Markup Language) is an XML-based standard for exchanging authentication and authorization data for SSO."
    },
    {
        id: 1708,
        question: "What is a 'False Acceptance Rate' (FAR) in biometrics?",
        options: [
            "The rate at which legitimate users are denied access",
            "The rate at which unauthorized users are incorrectly granted access",
            "The speed of the scanner",
            "The cost of the system"
        ],
        correctAnswer: "The rate at which unauthorized users are incorrectly granted access",
        explanation: "FAR measures how often a biometric system incorrectly identifies an unauthorized user as a valid user (Type II error)."
    },
    {
        id: 1709,
        question: "What is 'Provisioning' in the context of IAM?",
        options: [
            "Buying new hardware",
            "The process of creating and managing user accounts and access rights",
            "Deleting user accounts",
            "Monitoring user activity"
        ],
        correctAnswer: "The process of creating and managing user accounts and access rights",
        explanation: "Provisioning involves setting up user accounts and assigning appropriate permissions when they join or change roles."
    },
    {
        id: 1710,
        question: "Which of the following is a 'Possession' factor?",
        options: [
            "Password",
            "Retina scan",
            "Hardware token (Key fob)",
            "Typing rhythm"
        ],
        correctAnswer: "Hardware token (Key fob)",
        explanation: "A hardware token or smart card is something you physically possess."
    },
    {
        id: 1711,
        question: "What is the purpose of 'Just-in-Time' (JIT) access?",
        options: [
            "To grant permanent admin rights",
            "To grant privileges only for the specific time they are needed",
            "To speed up login times",
            "To bypass authentication"
        ],
        correctAnswer: "To grant privileges only for the specific time they are needed",
        explanation: "JIT access minimizes risk by granting elevated permissions only when required and revoking them immediately after."
    },
    {
        id: 1712,
        question: "Which access control model uses labels (e.g., Top Secret) to determine access?",
        options: [
            "DAC (Discretionary Access Control)",
            "MAC (Mandatory Access Control)",
            "RBAC (Role-Based Access Control)",
            "ABAC (Attribute-Based Access Control)"
        ],
        correctAnswer: "MAC (Mandatory Access Control)",
        explanation: "MAC uses security labels (classification) and clearance levels to control access, often used in military/government."
    },
    {
        id: 1713,
        question: "What is 'Credential Stuffing'?",
        options: [
            "Creating strong passwords",
            "Automated injection of breached username/password pairs into login forms",
            "Storing passwords in a text file",
            "Sharing passwords with coworkers"
        ],
        correctAnswer: "Automated injection of breached username/password pairs into login forms",
        explanation: "Credential stuffing exploits password reuse by trying credentials stolen from one breach on other sites."
    },
    {
        id: 1714,
        question: "Which of the following is an example of 'Something you do'?",
        options: [
            "Facial recognition",
            "Keystroke dynamics",
            "PIN code",
            "ID card"
        ],
        correctAnswer: "Keystroke dynamics",
        explanation: "Behavioral biometrics like keystroke dynamics or gait analysis fall under 'Something you do'."
    },
    {
        id: 1715,
        question: "What is the function of a 'Password Manager'?",
        options: [
            "To generate and store complex, unique passwords for each site",
            "To reset forgotten passwords",
            "To share passwords publicly",
            "To bypass MFA"
        ],
        correctAnswer: "To generate and store complex, unique passwords for each site",
        explanation: "Password managers allow users to use strong, unique passwords for every account without having to memorize them."
    },
    {
        id: 1716,
        question: "What is 'OAuth' used for?",
        options: [
            "Encrypting hard drives",
            "Delegated authorization (allowing an app to access resources on your behalf)",
            "Biometric scanning",
            "Firewall rules"
        ],
        correctAnswer: "Delegated authorization (allowing an app to access resources on your behalf)",
        explanation: "OAuth is an open standard for access delegation, commonly used for 'Log in with Google/Facebook'."
    },
    {
        id: 1717,
        question: "What is a 'Crossover Error Rate' (CER) in biometrics?",
        options: [
            "The point where FAR and FRR are equal",
            "The highest possible error rate",
            "The speed of the system",
            "The cost of the sensor"
        ],
        correctAnswer: "The point where FAR and FRR are equal",
        explanation: "CER (or EER) is the point where the False Acceptance Rate and False Rejection Rate intersect; lower CER indicates a more accurate system."
    },
    {
        id: 1718,
        question: "Which attack involves an attacker trying every possible combination of characters to guess a password?",
        options: [
            "Dictionary attack",
            "Brute-force attack",
            "Phishing",
            "Rainbow table attack"
        ],
        correctAnswer: "Brute-force attack",
        explanation: "A brute-force attack systematically tries all possible combinations until the correct one is found."
    },
    {
        id: 1719,
        question: "What is 'Role-Based Access Control' (RBAC)?",
        options: [
            "Access is based on the user's job function or group membership",
            "Access is decided by the owner of the object",
            "Access is based on time of day",
            "Access is based on security labels"
        ],
        correctAnswer: "Access is based on the user's job function or group membership",
        explanation: "RBAC assigns permissions to roles (e.g., Manager, HR), and users are assigned to those roles."
    },
    {
        id: 1720,
        question: "What is the purpose of 'Salting' passwords?",
        options: [
            "To make them taste better",
            "To add random data to the password before hashing to defend against rainbow table attacks",
            "To encrypt them with a public key",
            "To compress them"
        ],
        correctAnswer: "To add random data to the password before hashing to defend against rainbow table attacks",
        explanation: "Salting ensures that the same password results in a different hash, preventing the use of pre-computed rainbow tables."
    },
    {
        id: 1721,
        question: "Which of the following describes 'Discretionary Access Control' (DAC)?",
        options: [
            "The system determines access",
            "The data owner decides who has access",
            "Access is based on roles",
            "Access is based on attributes"
        ],
        correctAnswer: "The data owner decides who has access",
        explanation: "In DAC, the owner of the resource (e.g., file creator) has the discretion to grant access to others."
    },
    {
        id: 1722,
        question: "What is a 'TOTP' (Time-based One-Time Password)?",
        options: [
            "A password that never expires",
            "A temporary code generated based on the current time, often used in MFA apps",
            "A password sent via mail",
            "A biometric factor"
        ],
        correctAnswer: "A temporary code generated based on the current time, often used in MFA apps",
        explanation: "TOTP algorithms (like Google Authenticator) generate a code that is valid for a short window (e.g., 30 seconds)."
    },
    {
        id: 1723,
        question: "What is 'Identity Proofing'?",
        options: [
            "Verifying a user's identity before issuing credentials (e.g., checking ID)",
            "Logging in",
            "Resetting a password",
            "Deleting an account"
        ],
        correctAnswer: "Verifying a user's identity before issuing credentials (e.g., checking ID)",
        explanation: "Identity proofing is the initial validation of a person's identity (e.g., showing a passport) before giving them an account."
    },
    {
        id: 1724,
        question: "Which of the following is a 'Location' factor?",
        options: [
            "GPS coordinates",
            "Password",
            "Fingerprint",
            "Smart card"
        ],
        correctAnswer: "GPS coordinates",
        explanation: "Somewhere you are involves geolocation, IP address, or specific network location."
    },
    {
        id: 1725,
        question: "What is 'Privileged Access Management' (PAM)?",
        options: [
            "Managing regular user accounts",
            "Securing and monitoring accounts with elevated permissions (admin accounts)",
            "Managing printer access",
            "Managing physical keys"
        ],
        correctAnswer: "Securing and monitoring accounts with elevated permissions (admin accounts)",
        explanation: "PAM focuses on protecting accounts that have critical access to systems, often using vaults and session recording."
    },
    {
        id: 1726,
        question: "What is a 'Rainbow Table'?",
        options: [
            "A colorful spreadsheet",
            "A pre-computed table of hash values used to crack passwords",
            "A list of usernames",
            "A firewall rule"
        ],
        correctAnswer: "A pre-computed table of hash values used to crack passwords",
        explanation: "Rainbow tables allow attackers to reverse hashes quickly by looking them up in a pre-generated list."
    },
    {
        id: 1727,
        question: "What is 'Attribute-Based Access Control' (ABAC)?",
        options: [
            "Access based on roles only",
            "Access based on complex policies combining user, resource, and environment attributes",
            "Access based on owner discretion",
            "Access based on labels"
        ],
        correctAnswer: "Access based on complex policies combining user, resource, and environment attributes",
        explanation: "ABAC is a fine-grained model that uses attributes (e.g., user department, time of day, file sensitivity) to make decisions."
    },
    {
        id: 1728,
        question: "What is 'Deprovisioning'?",
        options: [
            "Creating accounts",
            "Revoking access and disabling accounts when a user leaves or changes roles",
            "Upgrading software",
            "Backing up data"
        ],
        correctAnswer: "Revoking access and disabling accounts when a user leaves or changes roles",
        explanation: "Deprovisioning ensures that former employees or users no longer have access to organizational resources."
    },
    {
        id: 1729,
        question: "Which of the following is a common defense against Brute-Force attacks?",
        options: [
            "Account lockout policies",
            "Short passwords",
            "Using only numbers",
            "Disabling encryption"
        ],
        correctAnswer: "Account lockout policies",
        explanation: "Locking an account after a certain number of failed attempts prevents attackers from trying endless combinations."
    },
    {
        id: 1730,
        question: "What is 'Passkey' authentication?",
        options: [
            "A physical key",
            "A passwordless standard using public key cryptography and device biometrics",
            "A very long password",
            "A shared secret"
        ],
        correctAnswer: "A passwordless standard using public key cryptography and device biometrics",
        explanation: "Passkeys replace passwords with cryptographic key pairs, authenticated via the user's device (e.g., FaceID)."
    },
    {
        id: 1731,
        question: "What is a 'Dictionary Attack'?",
        options: [
            "Throwing a book at the server",
            "Trying words from a predefined list (dictionary) to guess a password",
            "Guessing random characters",
            "Stealing the database"
        ],
        correctAnswer: "Trying words from a predefined list (dictionary) to guess a password",
        explanation: "Dictionary attacks use lists of common words and passwords, which is faster than pure brute-force."
    },
    {
        id: 1732,
        question: "What is 'Federated Identity'?",
        options: [
            "A government ID",
            "Linking a user's identity across multiple distinct security domains",
            "Using different usernames for every site",
            "An anonymous account"
        ],
        correctAnswer: "Linking a user's identity across multiple distinct security domains",
        explanation: "Federation allows a user to use their credentials from one organization (IdP) to access services in another (SP)."
    },
    {
        id: 1733,
        question: "Which protocol is used by Windows for authentication in a domain environment?",
        options: [
            "Kerberos",
            "RADIUS",
            "TACACS+",
            "SSH"
        ],
        correctAnswer: "Kerberos",
        explanation: "Kerberos is the default authentication protocol for Active Directory, using tickets to prevent replay attacks."
    },
    {
        id: 1734,
        question: "What is 'Password Spraying'?",
        options: [
            "Trying one common password against many different accounts",
            "Trying many passwords against one account",
            "Writing passwords on a whiteboard",
            "Emailing passwords to everyone"
        ],
        correctAnswer: "Trying one common password against many different accounts",
        explanation: "Password spraying avoids account lockouts by trying a single common password (e.g., 'Password123') across many users."
    },
    {
        id: 1735,
        question: "What is 'Geofencing'?",
        options: [
            "Building a physical fence",
            "Creating a virtual perimeter to trigger alerts or controls based on location",
            "Blocking all internet traffic",
            "Locking devices in a safe"
        ],
        correctAnswer: "Creating a virtual perimeter to trigger alerts or controls based on location",
        explanation: "Geofencing uses GPS or RFID to define geographical boundaries for access control or device management."
    },
    {
        id: 1736,
        question: "What is the 'False Rejection Rate' (FRR)?",
        options: [
            "The rate at which legitimate users are incorrectly denied access",
            "The rate at which attackers get in",
            "The failure rate of the hardware",
            "The cost of the scanner"
        ],
        correctAnswer: "The rate at which legitimate users are incorrectly denied access",
        explanation: "FRR (Type I error) measures how often the system fails to recognize an authorized user, causing inconvenience."
    },
    {
        id: 1737,
        question: "What is 'OpenID Connect' (OIDC)?",
        options: [
            "A VPN protocol",
            "An identity layer built on top of OAuth 2.0",
            "A database standard",
            "A firewall type"
        ],
        correctAnswer: "An identity layer built on top of OAuth 2.0",
        explanation: "OIDC provides authentication on top of OAuth 2.0's authorization, allowing clients to verify the identity of the user."
    },
    {
        id: 1738,
        question: "Which of the following is a 'Behavioral' biometric?",
        options: [
            "Fingerprint",
            "Iris scan",
            "Gait analysis (walking style)",
            "DNA"
        ],
        correctAnswer: "Gait analysis (walking style)",
        explanation: "Behavioral biometrics measure how a person acts (typing, walking, voice patterns) rather than physical traits."
    },
    {
        id: 1739,
        question: "What is 'Implicit Deny'?",
        options: [
            "Everything is allowed unless forbidden",
            "Everything is denied unless explicitly allowed",
            "Only admins are denied",
            "Only guests are denied"
        ],
        correctAnswer: "Everything is denied unless explicitly allowed",
        explanation: "Implicit deny is a fundamental security principle where access is blocked by default if no rule explicitly permits it."
    },
    {
        id: 1740,
        question: "What is 'Continuous Authentication'?",
        options: [
            "Logging in once a year",
            "Constantly verifying the user's identity throughout the session (e.g., via behavioral biometrics)",
            "Asking for a password every minute",
            "Never logging out"
        ],
        correctAnswer: "Constantly verifying the user's identity throughout the session (e.g., via behavioral biometrics)",
        explanation: "Continuous authentication monitors user behavior to ensure the person using the device is still the authenticated user."
    }
];

export const unit18Questions = [
    {
        id: 1801,
        question: "What is a 'Zero-Day' vulnerability?",
        options: [
            "A vulnerability that has been known for zero days",
            "A vulnerability discovered by attackers before the vendor has a patch",
            "A vulnerability that causes zero damage",
            "A vulnerability that is fixed immediately"
        ],
        correctAnswer: "A vulnerability discovered by attackers before the vendor has a patch",
        explanation: "Zero-day vulnerabilities are exploited before the developer is aware or has released a fix."
    },
    {
        id: 1802,
        question: "What type of attack involves injecting malicious SQL commands into a database query?",
        options: [
            "Cross-Site Scripting (XSS)",
            "SQL Injection (SQLi)",
            "Buffer Overflow",
            "Man-in-the-Middle"
        ],
        correctAnswer: "SQL Injection (SQLi)",
        explanation: "SQL Injection exploits unsanitized user input to manipulate backend database queries."
    },
    {
        id: 1803,
        question: "What is 'Bluejacking'?",
        options: [
            "Stealing data via Bluetooth",
            "Sending unsolicited messages to a Bluetooth-enabled device",
            "Taking control of a Bluetooth device",
            "Crashing a Bluetooth device"
        ],
        correctAnswer: "Sending unsolicited messages to a Bluetooth-enabled device",
        explanation: "Bluejacking is a relatively harmless prank where unsolicited messages are sent to nearby Bluetooth devices."
    },
    {
        id: 1804,
        question: "Which attack involves an attacker intercepting and possibly altering communication between two parties?",
        options: [
            "On-Path Attack (Man-in-the-Middle)",
            "DoS Attack",
            "Phishing",
            "Ransomware"
        ],
        correctAnswer: "On-Path Attack (Man-in-the-Middle)",
        explanation: "An On-Path attack (formerly MITM) occurs when an attacker sits between two communicating parties to eavesdrop or manipulate data."
    },
    {
        id: 1805,
        question: "What is 'Bluesnarfing'?",
        options: [
            "Sending messages via Bluetooth",
            "Unauthorized access to a device via Bluetooth to steal data (contacts, messages)",
            "Crashing a device via Bluetooth",
            "Pairing with a headset"
        ],
        correctAnswer: "Unauthorized access to a device via Bluetooth to steal data (contacts, messages)",
        explanation: "Bluesnarfing is the theft of information from a wireless device through a Bluetooth connection."
    },
    {
        id: 1806,
        question: "What is a 'Buffer Overflow'?",
        options: [
            "When a hard drive is full",
            "When a program writes more data to a memory buffer than it can hold, overwriting adjacent memory",
            "When network traffic is too high",
            "When a printer runs out of paper"
        ],
        correctAnswer: "When a program writes more data to a memory buffer than it can hold, overwriting adjacent memory",
        explanation: "Buffer overflows can cause crashes or allow attackers to execute arbitrary code."
    },
    {
        id: 1807,
        question: "What is 'Cross-Site Scripting' (XSS)?",
        options: [
            "Injecting malicious scripts into trusted websites viewed by other users",
            "Attacking the database directly",
            "Guessing passwords",
            "Encrypting files"
        ],
        correctAnswer: "Injecting malicious scripts into trusted websites viewed by other users",
        explanation: "XSS allows attackers to execute scripts in the victim's browser, often to steal cookies or session tokens."
    },
    {
        id: 1808,
        question: "What is 'Sideloading' on a mobile device?",
        options: [
            "Charging the device from the side",
            "Installing applications from unofficial sources (bypassing the app store)",
            "Transferring files to a PC",
            "Rotating the screen"
        ],
        correctAnswer: "Installing applications from unofficial sources (bypassing the app store)",
        explanation: "Sideloading bypasses official app store security checks, increasing the risk of installing malware."
    },
    {
        id: 1809,
        question: "What is 'Jailbreaking' (iOS) or 'Rooting' (Android)?",
        options: [
            "Breaking the screen",
            "Removing manufacturer restrictions to gain elevated privileges",
            "Locking the device remotely",
            "Encrypting the storage"
        ],
        correctAnswer: "Removing manufacturer restrictions to gain elevated privileges",
        explanation: "Jailbreaking/Rooting gives the user full control (root access) but compromises the device's security model."
    },
    {
        id: 1810,
        question: "What is a 'Race Condition'?",
        options: [
            "A competition between hackers",
            "A vulnerability where the outcome depends on the timing or order of events",
            "A fast network connection",
            "A type of virus"
        ],
        correctAnswer: "A vulnerability where the outcome depends on the timing or order of events",
        explanation: "Race conditions (like TOCTOU) occur when a system attempts to perform two or more operations at the same time, leading to unexpected behavior."
    },
    {
        id: 1811,
        question: "What is 'Cross-Site Request Forgery' (CSRF/XSRF)?",
        options: [
            "Stealing cookies",
            "Tricking a user into performing an unwanted action on a site where they are authenticated",
            "Crashing a server",
            "Fake login page"
        ],
        correctAnswer: "Tricking a user into performing an unwanted action on a site where they are authenticated",
        explanation: "CSRF exploits the trust a site has in a user's browser, forcing them to execute actions (like changing a password) without their consent."
    },
    {
        id: 1812,
        question: "What is 'Blueborne'?",
        options: [
            "A Bluetooth headset brand",
            "A set of airborne Bluetooth vulnerabilities that can spread malware without pairing",
            "A blue screen error",
            "A water-based attack"
        ],
        correctAnswer: "A set of airborne Bluetooth vulnerabilities that can spread malware without pairing",
        explanation: "Blueborne is a critical vector that allows attackers to take control of devices via Bluetooth without user interaction."
    },
    {
        id: 1813,
        question: "What is 'Firmware'?",
        options: [
            "Soft clothing",
            "Permanent software programmed into a read-only memory",
            "A temporary file",
            "A virus"
        ],
        correctAnswer: "Permanent software programmed into a read-only memory",
        explanation: "Firmware provides low-level control for a device's specific hardware."
    },
    {
        id: 1814,
        question: "What is the risk of 'End of Life' (EOL) systems?",
        options: [
            "They are too fast",
            "They no longer receive security updates or support from the vendor",
            "They use too much power",
            "They are too expensive"
        ],
        correctAnswer: "They no longer receive security updates or support from the vendor",
        explanation: "EOL systems are vulnerable because new exploits will not be patched by the manufacturer."
    },
    {
        id: 1815,
        question: "What is 'XML Injection'?",
        options: [
            "Injecting malicious XML content to interfere with an application's logic",
            "Injecting SQL code",
            "Injecting HTML code",
            "Injecting binary code"
        ],
        correctAnswer: "Injecting malicious XML content to interfere with an application's logic",
        explanation: "XML injection targets XML parsers, potentially leading to data exposure or denial of service."
    },
    {
        id: 1816,
        question: "What is 'Bluebugging'?",
        options: [
            "A software bug",
            "Taking full control of a device via Bluetooth to make calls or send messages",
            "Listening to music",
            "Blocking Bluetooth"
        ],
        correctAnswer: "Taking full control of a device via Bluetooth to make calls or send messages",
        explanation: "Bluebugging is a more severe attack than Bluejacking/Bluesnarfing, allowing full device control."
    },
    {
        id: 1817,
        question: "What is a 'Logic Bomb'?",
        options: [
            "A physical explosive",
            "Malicious code set to execute when specific conditions are met (e.g., a date or event)",
            "A logical puzzle",
            "A failed login attempt"
        ],
        correctAnswer: "Malicious code set to execute when specific conditions are met (e.g., a date or event)",
        explanation: "Logic bombs lie dormant until a trigger (like a specific time or an employee being fired) activates them."
    },
    {
        id: 1818,
        question: "What is 'Driver Shimming'?",
        options: [
            "Fixing a car",
            "Inserting malicious code between the OS and a driver to intercept or manipulate data",
            "Updating drivers",
            "Deleting drivers"
        ],
        correctAnswer: "Inserting malicious code between the OS and a driver to intercept or manipulate data",
        explanation: "Shimming involves creating a compatibility layer that can be exploited to run malicious code."
    },
    {
        id: 1819,
        question: "What is 'Refactoring' in the context of malware?",
        options: [
            "Cleaning up code",
            "Modifying the internal structure of malware code to evade signature-based detection",
            "Deleting the code",
            "Compressing the code"
        ],
        correctAnswer: "Modifying the internal structure of malware code to evade signature-based detection",
        explanation: "Refactoring changes the code's appearance (signature) without changing its function, helping it bypass antivirus."
    },
    {
        id: 1820,
        question: "What is 'Integer Overflow'?",
        options: [
            "Too many numbers",
            "When an arithmetic operation attempts to create a numeric value that is too large to be represented",
            "A database error",
            "A network error"
        ],
        correctAnswer: "When an arithmetic operation attempts to create a numeric value that is too large to be represented",
        explanation: "Integer overflows can lead to unexpected behavior or vulnerabilities if the wrapped-around value is used in memory allocation."
    },
    {
        id: 1821,
        question: "What is 'Pointer/Object Dereference' vulnerability?",
        options: [
            "Pointing at the screen",
            "When a program attempts to access memory using a NULL or invalid pointer",
            "Deleting a file",
            "Renaming a file"
        ],
        correctAnswer: "When a program attempts to access memory using a NULL or invalid pointer",
        explanation: "Dereferencing a null or invalid pointer can cause a crash (DoS) or potentially allow code execution."
    },
    {
        id: 1822,
        question: "What is 'Directory Traversal'?",
        options: [
            "Walking through a building",
            "Manipulating file paths (e.g., ../../) to access files outside the intended directory",
            "Listing files",
            "Creating folders"
        ],
        correctAnswer: "Manipulating file paths (e.g., ../../) to access files outside the intended directory",
        explanation: "Directory traversal allows attackers to access restricted files on the server by stepping out of the web root."
    },
    {
        id: 1823,
        question: "What is 'Resource Exhaustion'?",
        options: [
            "Running out of coffee",
            "Depleting system resources (CPU, memory, disk) to cause a Denial of Service",
            "Deleting resources",
            "Upgrading resources"
        ],
        correctAnswer: "Depleting system resources (CPU, memory, disk) to cause a Denial of Service",
        explanation: "Resource exhaustion attacks aim to make a system unavailable by consuming all available resources."
    },
    {
        id: 1824,
        question: "What is 'Memory Leak'?",
        options: [
            "Forgetting things",
            "When a program fails to release memory it no longer needs, eventually consuming all available RAM",
            "Downloading RAM",
            "A hardware failure"
        ],
        correctAnswer: "When a program fails to release memory it no longer needs, eventually consuming all available RAM",
        explanation: "Memory leaks can lead to resource exhaustion and system crashes over time."
    },
    {
        id: 1825,
        question: "What is 'DLL Injection'?",
        options: [
            "Injecting a vaccine",
            "Forcing a process to load a malicious Dynamic Link Library (DLL)",
            "Deleting a DLL",
            "Renaming a DLL"
        ],
        correctAnswer: "Forcing a process to load a malicious Dynamic Link Library (DLL)",
        explanation: "DLL injection allows attackers to run their code within the address space of another process."
    },
    {
        id: 1826,
        question: "What is 'Time of Check to Time of Use' (TOCTOU)?",
        options: [
            "A race condition where the state of a resource changes between checking it and using it",
            "A clock error",
            "A scheduling conflict",
            "A timeout error"
        ],
        correctAnswer: "A race condition where the state of a resource changes between checking it and using it",
        explanation: "TOCTOU is a specific type of race condition where security controls are bypassed by changing the resource after it's checked but before it's used."
    },
    {
        id: 1827,
        question: "What is 'Pass-the-Hash'?",
        options: [
            "Passing a joint",
            "An attack where an attacker uses a captured password hash to authenticate without knowing the plaintext password",
            "Sharing passwords",
            "Hashing a file"
        ],
        correctAnswer: "An attack where an attacker uses a captured password hash to authenticate without knowing the plaintext password",
        explanation: "Pass-the-hash exploits authentication protocols (like NTLM) that accept the hash directly."
    },
    {
        id: 1828,
        question: "What is 'Clickjacking'?",
        options: [
            "Stealing a mouse",
            "Tricking a user into clicking on something different from what they perceive (using transparent layers)",
            "Double clicking",
            "Right clicking"
        ],
        correctAnswer: "Tricking a user into clicking on something different from what they perceive (using transparent layers)",
        explanation: "Clickjacking uses invisible iframes to hijack user clicks for malicious actions."
    },
    {
        id: 1829,
        question: "What is 'Session Hijacking'?",
        options: [
            "Stealing a meeting room",
            "Taking over a user's active session by stealing their session ID/token",
            "Logging out a user",
            "Creating a new session"
        ],
        correctAnswer: "Taking over a user's active session by stealing their session ID/token",
        explanation: "Session hijacking allows an attacker to impersonate a user after they have authenticated."
    },
    {
        id: 1830,
        question: "What is 'URL Encoding' abuse?",
        options: [
            "Writing long URLs",
            "Using percent-encoding (e.g., %20) to bypass filters or obfuscate malicious payloads",
            "Shortening URLs",
            "Clicking links"
        ],
        correctAnswer: "Using percent-encoding (e.g., %20) to bypass filters or obfuscate malicious payloads",
        explanation: "Attackers use URL encoding to hide malicious characters from security filters."
    },
    {
        id: 1831,
        question: "What is 'Replay Attack'?",
        options: [
            "Watching a video again",
            "Capturing and retransmitting valid data (like authentication tokens) to gain unauthorized access",
            "Playing a game",
            "Backing up data"
        ],
        correctAnswer: "Capturing and retransmitting valid data (like authentication tokens) to gain unauthorized access",
        explanation: "Replay attacks use valid credentials captured from the network to impersonate the user."
    },
    {
        id: 1832,
        question: "What is 'SSL Stripping'?",
        options: [
            "Removing clothes",
            "Downgrading a connection from HTTPS to HTTP to intercept traffic",
            "Updating SSL certificates",
            "Encrypting data"
        ],
        correctAnswer: "Downgrading a connection from HTTPS to HTTP to intercept traffic",
        explanation: "SSL stripping forces a victim's browser to communicate in cleartext (HTTP) instead of encrypted (HTTPS)."
    },
    {
        id: 1833,
        question: "What is 'Typosquatting'?",
        options: [
            "Sitting incorrectly",
            "Registering domains similar to popular ones (e.g., goggle.com) to catch users who make typing errors",
            "Typing fast",
            "Breaking a keyboard"
        ],
        correctAnswer: "Registering domains similar to popular ones (e.g., goggle.com) to catch users who make typing errors",
        explanation: "Typosquatting (URL hijacking) relies on user mistakes to serve malware or phishing sites."
    },
    {
        id: 1834,
        question: "What is 'Domain Hijacking'?",
        options: [
            "Stealing a server",
            "Unauthorized changing of a domain's registration information to take control of it",
            "Buying a domain",
            "Selling a domain"
        ],
        correctAnswer: "Unauthorized changing of a domain's registration information to take control of it",
        explanation: "Domain hijacking involves taking control of the domain name itself, often by compromising the registrar account."
    },
    {
        id: 1835,
        question: "What is 'ARP Poisoning'?",
        options: [
            "Poisoning food",
            "Sending fake ARP messages to link the attacker's MAC address with a legitimate IP address",
            "Blocking ARP",
            "Updating ARP tables"
        ],
        correctAnswer: "Sending fake ARP messages to link the attacker's MAC address with a legitimate IP address",
        explanation: "ARP poisoning allows an attacker to intercept traffic on a local network (LAN) by redirecting it to their machine."
    },
    {
        id: 1836,
        question: "What is 'DNS Poisoning'?",
        options: [
            "Corrupting the DNS cache to redirect users to malicious websites",
            "Deleting DNS records",
            "Speeding up DNS",
            "Encrypting DNS"
        ],
        correctAnswer: "Corrupting the DNS cache to redirect users to malicious websites",
        explanation: "DNS poisoning (or cache poisoning) inserts fake DNS entries, sending users to attacker-controlled sites."
    },
    {
        id: 1837,
        question: "What is 'MAC Flooding'?",
        options: [
            "Spilling water on a Mac",
            "Flooding a switch's CAM table with fake MAC addresses to force it into fail-open (hub) mode",
            "Blocking MAC addresses",
            "Filtering MAC addresses"
        ],
        correctAnswer: "Flooding a switch's CAM table with fake MAC addresses to force it into fail-open (hub) mode",
        explanation: "MAC flooding exhausts the switch's memory, causing it to broadcast traffic to all ports, allowing sniffing."
    },
    {
        id: 1838,
        question: "What is 'VLAN Hopping'?",
        options: [
            "Jumping over a cable",
            "Attacking network resources on a different VLAN than the one the attacker is connected to",
            "Creating VLANs",
            "Deleting VLANs"
        ],
        correctAnswer: "Attacking network resources on a different VLAN than the one the attacker is connected to",
        explanation: "VLAN hopping exploits switch misconfigurations (like DTP) to access traffic on other VLANs."
    },
    {
        id: 1839,
        question: "What is 'Evil Twin'?",
        options: [
            "A bad sibling",
            "A rogue Wi-Fi access point that mimics a legitimate one to intercept traffic",
            "A virus",
            "A firewall"
        ],
        correctAnswer: "A rogue Wi-Fi access point that mimics a legitimate one to intercept traffic",
        explanation: "An Evil Twin uses the same SSID as a trusted network to trick users into connecting to it."
    },
    {
        id: 1840,
        question: "What is 'Rogue Access Point'?",
        options: [
            "An unauthorized wireless access point connected to the corporate network",
            "A broken AP",
            "A new AP",
            "A secure AP"
        ],
        correctAnswer: "An unauthorized wireless access point connected to the corporate network",
        explanation: "A rogue AP is installed without authorization, creating a backdoor into the network."
    }
];
