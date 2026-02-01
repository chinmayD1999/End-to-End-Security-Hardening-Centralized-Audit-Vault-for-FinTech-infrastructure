
# End to End Security Hardening Centralized Audit Vault for FinTech infrastructure

### Designed a Zero Trust, secure and isolated Linux fintech infrastructure, separating the architecture into a Control Plane (Infra) and a Workload Node (Web Client). Enforced strict security controls requiring cryptographic authorization from the central infrastructure for all boot, operational, and data access activities, ensuring complete dependency on the secure core.
 

## 📑 Table of Contents

[**1. Project Overview**](#1project-overview)

* 1.1 Introduction
* 1.2 Objective: Zero Trust & Centralized Security
* 1.3 Scope of Work

[**2. System Architecture & Design**](#2System-Architecture-&-Design)

* 2.1 High-Level Architecture (The "Control Plane" vs. "Workload Node")
* 2.2 Network Topology: The offline Environment (192.168.70.0/24)
* 2.3 Component Breakdown (Infra Server vs. Web Client)
* 2.4 Software & Tools Specification

**3. Phase 1: Infrastructure Foundation**

* 3.1 Environment Setup (VMware Host-Only Network)
* 3.2 Infra Server Deployment (RHEL 9)
* 3.3 Web Client Deployment (RHEL 9)
* 3.4 Local Repository Configuration (HTTP/YUM)

**4. Phase 2: Centralized Identity Management (IAM)**

* 4.1 Installing Red Hat IdM (FreeIPA)
* 4.2 Configuring DNS & User Policies
* 4.3 Domain Joining the Web Client (SSSD)
* 4.4 Implementing HBAC (Host-Based Access Control)

**5. Phase 3: Zero-Trust Storage (NBDE & LUKS)**

* 5.1 Disk Partitioning & LUKS2 Encryption
* 5.2 Deploying the Tang Key Server (Infra)
* 5.3 Configuring Clevis for Automated Decryption (Client)
* 5.4 Security Validation: Network Bound Disk Encryption (NBDE) Workflow

**6. Phase 4: Secure Data Transmission**

* 6.1 Setting up NFSv4 with Kerberos (krb5p)
* 6.2 Exporting Secure Shares from Infra Server
* 6.3 Mounting & Verifying Encrypted Shares on Web Client

**7. Phase 5: Forensics & Auditing (The "Black Box")**

* 7.1 Configuring Linux Audit Daemon (`auditd`) on Client
* 7.2 Implementing Remote Logging via Rsyslog
* 7.3 Creating the Encrypted Audit Vault on Infra Server
* 7.4 Real-time Intrusion Detection Testing

**8. Testing & Validation**

* 8.1 The "Reboot Test" (Automated Decryption)
* 8.2 The "Hacker Test" (Audit Log Forwarding)
* 8.3 The "Encryption Test" (Kerberos Verification)

**9. Conclusion & Future Enhancements**

* 9.1 Summary of Achievements
* 9.2 Potential Improvements (SELinux, Ansible, Cockpit)

**10. References & Appendix**

* 10.1 Command Reference Cheat Sheet
* 10.2 Troubleshooting Logs

------------------------------------------------------------

## 1.Project Overview


### 1.1 Introduction

In modern enterprise environments, traditional "castle-and-moat" security models—where everything inside the network is trusted—are no longer sufficient. Sophisticated threats often originate from compromised internal nodes or stolen physical hardware.

This project, **"End to End Security Hardening Centralized Audit Vault for FinTech infrastructure"** simulates a high-security, critical infrastructure environment typical of the Fintech or Defense sectors. By deploying a strictly **Offline** network, the project completely isolates sensitive data from the public internet. It utilizes **Red Hat Enterprise Linux 9 (RHEL 9)** to build a robust architecture that prioritizes identity governance, immutable logging, and automated encryption over convenience.

### 1.2 Objective: Zero Trust & Centralized Security

The primary objective is to implement a **Zero Trust Architecture (ZTA)** where no device is implicitly trusted, even if it is physically located inside the secure datacenter.

The system is designed around two core security pillars:

1. **Centralized Dependency:** The Workload Node (Web Client) is intentionally "helpless." It cannot resolve users, unlock its own hard drives, or store logs without active authorization from the Control Plane (Infra Server).
2. **Cryptographic Verification:** Every interaction—whether it is a user logging in, a disk unlocking, or a file being shared—is verified using military-grade cryptography (Kerberos, LUKS, RSA).

**Key Security Goals:**

* **Data at Rest:** Ensure data on stolen physical disks is unreadable (via NBDE).
* **Data in Transit:** Ensure network traffic cannot be sniffed or spoofed (via Kerberized NFS).
* **Non-Repudiation:** Ensure that if a breach occurs, the attacker cannot delete the forensic evidence (via Remote Audit Logging).

### 1.3 Scope of Work

This project encompasses the full lifecycle of designing, deploying, and hardening a Linux infrastructure. The scope includes:

* **Network Design:** Implementation of an isolated Host-Only network (`192.168.70.0/24`) with strict firewalling.
* **Identity Management:** Deployment of Red Hat IdM (FreeIPA) for centralized authentication and policy enforcement.
* **Storage Automation:** Configuration of Network Bound Disk Encryption (NBDE) using Tang and Clevis.
* **Forensics Engineering:** Setup of `auditd` for deep system monitoring and `rsyslog` for centralized log aggregation.
* **Vulnerability Testing:** Execution of simulated "theft" and "intrusion" scenarios to validate the security controls.

**Out of Scope:**

* Connecting the infrastructure to the public internet.
* Deployment of user-facing web applications (the focus is on the *infrastructure*, not the website content).
* Cloud-based integration (AWS/Azure) – this is strictly an on-premise simulation.

------------------------------------------------------------

## 2.System Architecture & Design

### 2.1 High-Level Architecture (The "Control Plane" vs. "Workload Node")

<p align="center">
  <img src="Architecture.png" width="850">
</p>

<p align="center">
  <em>Zero Trust Isolated Architecture</em>
</p>

Here is the drafted content for **Section 2.2**, detailing the specific network layer of your infrastructure.

---

### 2.2 Network Topology: The Offline Environment (192.168.70.0/24)

To adhere to the strict "Zero Trust" requirement, the infrastructure is deployed within a fully isolated **Host-Only Network**. This topology simulates a high-security "Dark Site" or air-gapped datacenter where servers have no physical or logical path to the public internet.

#### **Network Specifications**

* **Network Type:** Host-Only (VMware VMnet2)
* **Subnet CIDR:** `192.168.70.0/24`
* **Broadcast Address:** `192.168.70.255`
* **Default Gateway:** None (Intentionally omitted to prevent internet routing).

#### **IP Addressing Scheme**

Static IP addresses were assigned to ensure consistent connectivity for cryptographic services (Kerberos/Tang) which rely on DNS stability.

| Device Role | Hostname | IP Address | Description |
| --- | --- | --- | --- |
| **Management Host** | *Physical Laptop* | `192.168.70.1` | The "Jump Box" or Admin workstation. It is the only device capable of SSHing into the environment. |
| **Control Plane** | `infra.chinmaytech.local` | `192.168.70.10` | The primary DNS and Identity server. |
| **Workload Node** | `web01.chinmaytech.local` | `192.168.70.20` | The application server. |

Here is the drafted content for **Section 2.3**. This section dives deep into the specific software stack installed on each server, explaining *what* is running and *why*.

---

### 2.3 Component Breakdown

This section details the software stack and service roles configured on each node. The architecture relies on specific Red Hat Enterprise Linux (RHEL) subsystems to enforce the Zero Trust model.

#### **2.3.1 Infra Server (Control Plane)**

* **Hostname:** `infra.chinmaytech.local`
* **Role:** The immutable "Trust Anchor." It hosts the authoritative source for all data, identities, and keys.

| Component / Service | Daemon Name | Function in Zero Trust Architecture |
| --- | --- | --- |
| **Red Hat IdM** | `ipa-server` | The Centralized Identity Provider. It combines LDAP (User DB), MIT Kerberos (Authentication), and BIND (DNS) into a single controller. |
| **Tang Server** | `tangd` | The "Key Escrow" service. It listens on Port 7500 and serves cryptographic keys to authorized clients, enabling Network Bound Disk Encryption (NBDE). |
| **NFS Server** | `nfs-server` | Provides the network file share (`/share/finance`). Configured with `sec=krb5p` to enforce strict Kerberos ticket validation and packet encryption. |
| **Rsyslog Receiver** | `rsyslog` | Configured as a centralized log collector (TCP/UDP 514). It receives security alerts from the client and stores them in the immutable vault. |
| **Secure Vault** | `dm-crypt` | A 10GB LUKS-encrypted partition (`/secure_audit`) unlocked via a local root-protected keyfile, ensuring sensitive logs are encrypted at rest. |
| **Local Repo** | `httpd` | A local HTTP server hosting the RHEL 9 ISO content, allowing the Web Client to install software without internet access. |

---

#### **2.3.2 Web Client (Workload Node)**

* **Hostname:** `web01.chinmaytech.local`
* **Role:** The "Application Node." It is stateless and dependent on the Infra Server for operational security.

| Component / Service | Daemon Name | Function in Zero Trust Architecture |
| --- | --- | --- |
| **SSSD** | `sssd` | The Client Side Agent. It connects to the Infra Server to cache user credentials and enforce login policies (HBAC). |
| **Apache Web Server** | `httpd` | The business application. Runs on Port 80. Access to the underlying OS is restricted via sudo rules managed by IdM. |
| **Clevis** | `clevis-luks` | The "Unlocker." A client-side framework that contacts the Tang server during boot to automatically decrypt the LUKS partition. |
| **NFS Security** | `rpc-gssd` | The RPC GSS Daemon. It handles the Kerberos context switching, allowing the NFS client to present a "Ticket" instead of just an IP address. |
| **Linux Audit** | `auditd` | The "Camera." Configured with kernel-level rules to watch specific files (`/etc/shadow`, `/etc/sysconfig/network`) for unauthorized changes. |
| **Log Forwarder** | `rsyslog` | Configured to forward `*.*` (all logs) to `192.168.70.10:514` immediately, ensuring no evidence remains solely on the compromised host. |

---

### **2.3.3 The Dependency Map**

The breakdown highlights the **Critical Dependencies** created by this design:

1. If **Tang (`tangd`)** stops, the Web Client cannot boot (Disk Encryption fails).
2. If **IdM (`ipa-server`)** stops, no one can log in to the Web Client (Authentication fails).
3. If **RPC GSS (`rpc-gssd`)** stops, the File Share vanishes (Decryption fails).

This centralization reduces the "Attack Surface" of the Web Client to near zero, as it holds no persistent secrets.

Here is the drafted content for **Section 2.4**. This section provides a technical inventory of the specific software versions and tools used to build the solution.

---

### 2.4 Software & Tools Specification

The solution utilizes a standard Red Hat Enterprise Linux 9 software stack, leveraging native kernel capabilities to minimize reliance on third-party tools.

#### **2.4.1 Core Infrastructure**

| Category | Software / Tool | Version | Purpose in Architecture |
| --- | --- | --- | --- |
| **Operating System** | **Red Hat Enterprise Linux** | **9.3** | The base OS chosen for its "Secure by Design" defaults and support for FIPS-140-3 validation. |
| **Kernel** | **Linux Kernel** | **5.14+** | Provides the underlying `dm-crypt` (encryption) and `audit` (logging) subsystems. |
| **Virtualization** | **VMware Workstation Pro** | **17.x** | The hypervisor used to host the air-gapped environment and manage the virtual Host-Only network (`VMnet2`). |

#### **2.4.2 Security & Cryptography Stack**

| Tool | Component Role | Description |
| --- | --- | --- |
| **LUKS2** | *Disk Encryption* | **Linux Unified Key Setup (v2).** Used to encrypt the partition headers. Unlike LUKS1, it supports Argon2id hashing for resistance against GPU brute-force attacks. |
| **Tang** | *Key Escrow Server* | A lightweight web service (running on `infra`) that binds data to the network presence. It uses **Jose** (JSON Object Signing and Encryption). |
| **Clevis** | *Decryption Client* | The "glue" framework that runs at boot time. It automates the unlocking process by solving the cryptographic puzzle presented by Tang. |
| **GnuPG** | *Key Management* | Used for generating and managing the SSH keys and verifying package signatures from the local repository. |

#### **2.4.3 Identity & Access Management (IAM)**

| Tool | Component Role | Description |
| --- | --- | --- |
| **Red Hat IdM** | *Domain Controller* | Powered by **FreeIPA**. It manages the centralized HBAC (Host-Based Access Control) rules, ensuring only specific users can login to specific terminals. |
| **MIT Kerberos** | *Authentication Protocol* | Eliminates the transmission of passwords over the network. It issues "Tickets" (TGT) that allow services to trust each other without exchanging secrets. |
| **SSSD** | *Client Agent* | **System Security Services Daemon.** It handles the offline caching of credentials, allowing a user to login even if the IdM server is temporarily unreachable (cached credentials). |

#### **2.4.4 Forensics & Networking**

| Tool | Component Role | Description |
| --- | --- | --- |
| **Auditd** | *Kernel Auditing* | The Linux Audit Framework. It intercepts system calls directly from the kernel (e.g., `open`, `execve`) to generate immutable evidence of user activity. |
| **Rsyslog** | *Log Transport* | Configured with the **RELP (Reliable Event Logging Protocol)** concept to ensure logs are successfully transmitted to the Infra server before being discarded from the client buffer. |
| **Firewalld** | *Network Defense* | Uses **Rich Rules** to enforce granular traffic control (e.g., "Allow Port 80 only from Subnet X") rather than simple zone-based blocking. |

#### **2.4.5 Management Utilities**

* **Cockpit:** A web-based graphical interface used for performance monitoring and visualizing the storage logs.
* **LVM2:** Logical Volume Manager, used to create flexible storage groups for the encrypted vaults.
* **OpenSSH:** Configured with strict `PermitRootLogin no` (except via console) to enforce the use of unprivileged accounts.

Here is the drafted content for **Section 3: Phase 1 - Infrastructure Foundation**. This section documents the initial build-out of the "Dark Site" environment.

---

## 3. Phase 1: Infrastructure Foundation

The first phase focused on establishing a secure, isolated baseline. Before deploying any security tools, we built the "Digital Bunker"—an environment physically disconnected from the public internet but fully functional internally.

### 3.1 Environment Setup (VMware Host-Only Network)

To simulate a true air-gapped datacenter, we configured a dedicated virtualization network that prohibits all external traffic (NAT/Bridged).

* **Virtual Switch:** VMware **VMnet2**
* **Mode:** **Host-Only** (No routing to physical NIC)
* **Subnet:** `192.168.70.0/24`
* **Rationale:** This creates a strict boundary. Even if the host machine has internet, the VMs cannot route traffic out, and external attackers cannot route traffic in.

### 3.2 Infra Server Deployment (Control Plane)

The **Infra Server** was deployed first to serve as the backbone of the network.

* **OS:** Red Hat Enterprise Linux 9.3
* **Hostname:** `infra.chinmaytech.local`
* **IP Configuration:**
* **IP Address:** `192.168.70.10`
* **Gateway:** None (Blank)
* **DNS:** `127.0.0.1` (It is its own DNS server)


* **Post-Install Hardening:**
* Set **SELinux** to Enforcing.
* Configured **Firewalld** to drop all incoming connections except SSH from the Management IP (`192.168.70.1`).



### 3.3 Web Client Deployment (Workload Node)

The **Web Client** was deployed as a minimal "consumer" node.

* **OS:** Red Hat Enterprise Linux 9.3
* **Hostname:** `web01.chinmaytech.local`
* **IP Configuration:**
* **IP Address:** `192.168.70.20`
* **DNS:** `192.168.70.10` (Crucial: It must rely on Infra for name resolution)


* **Partitioning Strategy:**
* During installation, we reserved free space on the volume group (`vg_rhel`) to allow for the creation of separate encrypted partitions in Phase 3.



### 3.4 Local Repository Configuration (HTTP/YUM)

Since the environment has no internet access, the servers cannot reach standard repositories like `cdn.redhat.com`. We solved this by creating a **Local Software Depot** on the Infra Server.

```ini
ISO / Synced RPMs
        ↓
   Repo Server
 (Apache HTTP)
        ↓
 Internal Clients
     (DNF/YUM)
```

### **3.4 Local Repository Configuration (HTTP/YUM)**

Think of this as setting up a private grocery store for your Linux hosts. Shelves stocked once, customers fetch fast, no trips to the outside world 🏪🐧

---

## **Purpose**

Configure a **local YUM/DNF repository** served over **HTTP** so internal systems can install and update packages without internet access. Common in air-gapped, banking, or high-security environments.

---

## **Architecture Flow**

```ini
ISO / Synced RPMs
        ↓
   Repo Server
 (Apache HTTP)
        ↓
 Internal Clients
     (DNF/YUM)
```

---

## **Step 1: Prepare Repository Content**

Mount ISO or sync RPMs to a directory:

```ini
# 2. Create a directory to hold the disc data
mkdir -p /var/www/html/rhel9

# 3. Mount the CDROM to that directory
mount /dev/cdrom /var/www/html/rhel9

# 4. Verify you see files (BaseOS and AppStream)
ls /var/www/html/rhel9

```

Generate metadata:

```ini
dnf install -y createrepo_c
createrepo /var/www/html/rhel9/BaseOS
createrepo /var/www/html/rhel9/AppStream
```

---

## **Step 2: Configure HTTP Server**

Install and start Apache:

```ini
dnf install -y httpd
systemctl enable --now httpd
```

Firewall (if enabled):

```ini
firewall-cmd --permanent --add-service=http
firewall-cmd --reload
```

Verify access:

```ini
http://<repo-server-ip>/rhel9/BaseOS/
http://<repo-server-ip>/rhel9/AppStream/
```

---

## **Step 3: Client-Side YUM Repository Configuration**

Create repo file on client:

```ini
vi /etc/yum.repos.d/local.repo
```

```ini
[Local-BaseOS]
name=RHEL 9 BaseOS
baseurl=http://<repo-server-ip>/rhel9/BaseOS
enabled=1
gpgcheck=0

[Local-AppStream]
name=RHEL 9 AppStream
baseurl=http://<repo-server-ip>/rhel9/AppStream
enabled=1
gpgcheck=0
```

Clean and test:

```ini
dnf clean all
dnf repolist
dnf install vim -y
```

**4. Phase 2: Centralized Identity Management (IAM)**

Here is the drafted content for **Section 4: Phase 2 - Centralized Identity Management**. This section documents the transition from standalone servers to a managed "Zero Trust" domain architecture.

---

## 4. Phase 2: Centralized Identity Management (IAM)

To eliminate the security risks associated with decentralized local accounts (e.g., weak passwords, orphaned accounts, lack of audit trails), we deployed **Red Hat Identity Management (IdM)**. This establishes a Single Source of Truth for all users, hosts, and authentication policies across the air-gapped environment.

### 4.1 Installing Red Hat IdM (FreeIPA)

We promoted the **Infra Server (`192.168.70.10`)** to serve as the Domain Controller for the environment. This replaces the standard `/etc/passwd` local files with a centralized LDAP directory and Kerberos Key Distribution Center (KDC).

* **Software Stack:** `ipa-server`, `ipa-server-dns`, `389-ds` (Directory Server).
* **Installation Command:**
We initialized the realm using the interactive setup:
```bash
ipa-server-install --setup-dns

```


* **Configuration Parameters:**
* **Realm Name:** `CHINMAYTECH.LOCAL` (The Kerberos authentication boundary)
* **Domain Name:** `chinmaytech.local` (The DNS suffix)
* **DNS Forwarders:** `no` (Explicitly disabled to maintain air-gap isolation)
* **NetBIOS Name:** `CHINMAYTECH`



### 4.2 Configuring DNS & User Policies

Since the environment is isolated, the IdM server also acts as the authoritative **DNS Server**. This is critical because the Kerberos protocol relies on accurate DNS SRV records to locate authentication services.

1. **DNS Configuration:**
We manually created the A-record for the client to ensure the domain controller could resolve it before joining.
```bash
ipa dnsrecord-add chinmaytech.local web01 --a-rec=192.168.70.20

```


2. **User Provisioning:**
We transitioned away from the root user by creating a named administrator account (`sysadmin`) for daily operations.
```bash
ipa user-add sysadmin --first=System --last=Admin --password

```


3. **Password Policy:**
The system automatically enforced a strict global password policy (Minimum 8 characters, expiration set to 90 days) on the new user, ensuring compliance with security standards.

### 4.3 Domain Joining the Web Client (SSSD)

We connected the **Web Client (`192.168.70.20`)** to the domain, effectively turning it into a "managed node." This process configured the **System Security Services Daemon (SSSD)** to route all login requests to the Infra Server.

* **Prerequisites:** Updated `/etc/resolv.conf` on the client to point to `192.168.70.10`.
* **Join Command:**
```bash
ipa-client-install --mkhomedir --enable-dns-updates

```


* **`--mkhomedir`**: Configured PAM to automatically create a home directory for network users upon their first valid login.
* **Result:** The Web Client no longer stores local password hashes. Authentication is now handled exclusively via Kerberos tickets over the network.



### 4.4 Implementing HBAC (Host-Based Access Control)

To strictly limit movement within the network ("Lateral Movement Prevention"), we utilized HBAC rules. This ensures that a valid username and password are **not sufficient** to access a server; the user must also satisfy a specific policy rule.

1. **Enforcing "Deny by Default":**
We disabled the default rule that allowed all users to access all hosts.
```bash
ipa hbacrule-disable allow_all

```


2. **Creating the "SysAdmin" Allow Rule:**
We created a specific rule permitting *only* the System Administrators group to access the Web Client via SSH.
* **Rule:** `allow_sysadmin_web`
* **User Group:** `sysadmins`
* **Host:** `web01.chinmaytech.local`
* **Service:** `sshd`


Here is the drafted content for **Section 5: Phase 3 - Zero-Trust Storage**. This section documents the implementation of Network-Bound Disk Encryption (NBDE), ensuring that sensitive data is encrypted at rest but automatically accessible *only* when the server is safely inside the secure network environment.

---

## 5. Phase 3: Zero-Trust Storage (NBDE & LUKS)

To protect sensitive data against physical theft (e.g., a hard drive being removed from the datacenter), we implemented strict **Disk Encryption**. However, to avoid the operational bottleneck of typing a password manually every time a server reboots, we utilized **Network-Bound Disk Encryption (NBDE)**.

This creates a dependency: **The data can only be decrypted if the Web Client can "see" the Infra Server.** If the server is stolen and taken off-site, it cannot contact the key server, and the data remains permanently locked.

### 5.1 Deploying the Tang Server (Key Escrow)

We configured the **Infra Server** to act as the "Tang" server. Tang is a stateless web service that advertises cryptographic keys to authorized clients.

1. **Installation:**
```bash
[root@infra ~]# dnf install tang -y

```


2. **Port Configuration (Avoiding Conflict):**
Since Port 80 is already used by our HTTP Repository, we configured Tang to listen on **Port 8080**.
```bash
systemctl edit tangd.socket
# Added:
# [Socket]
# ListenStream=
# ListenStream=8080

```


3. **Activation:**
```bash
systemctl enable --now tangd.socket
firewall-cmd --add-port=8080/tcp --permanent
firewall-cmd --reload

```



### 5.2 Creating the Encrypted Vault (LUKS2)

On the **Web Client**, we utilized the free space reserved during the OS installation to create a new, encrypted partition for sensitive application logs.

1. **Create the Partition:**
We created a 5GB Logical Volume named `lv_vault`.
```bash
lvcreate -n lv_vault -L 5G vg_rhel

```


2. **Encrypt the Volume:**
We initialized the volume with **LUKS2** encryption. This required setting a temporary manual passphrase (a "Recovery Key").
```bash
cryptsetup luksFormat /dev/vg_rhel/lv_vault

```


3. **Open and Format:**
We unlocked the volume to create the filesystem.
```bash
cryptsetup luksOpen /dev/vg_rhel/lv_vault secure_vault
mkfs.xfs /dev/mapper/secure_vault

```


4. **Mounting:**
Mounted the secure volume to `/opt/secure_data`.

### 5.3 Implementing Automated Unlocking (Clevis)

We installed the **Clevis** client on the Web Client to "bind" the encrypted volume to the Tang server. This acts as the automated key turner.

1. **Installation:**
```bash
[root@web01 ~]# dnf install clevis clevis-luks clevis-dracut -y

```


2. **Binding the Volume:**
We ran the binding command, which links the LUKS volume to the Tang advertisement.
```bash
clevis luks bind -d /dev/vg_rhel/lv_vault tang '{"url":"http://192.168.70.10:8080"}'

```


* **Trust Mechanism:** The client downloaded the signing key from the Tang server and added it as a new "Keyslot" in the LUKS header.


3. **Persistence:**
We enabled `clevis-luks-askpass.path` to ensure this process runs automatically during boot.
```bash
systemctl enable clevis-luks-askpass.path

```



### 5.4 Verification (The "Pull the Plug" Test)

To validate the Zero Trust architecture, we performed two boot tests:

1. **The "Happy Path" (Network Connected):**
* **Action:** Rebooted `web01` while connected to the internal LAN.
* **Result:** Clevis contacted the Infra Server, retrieved the key, and unlocked `/opt/secure_data` automatically. The server booted without user intervention.


2. **The "Theft Scenario" (Network Disconnected):**
* **Action:** Disconnected the virtual network adapter on `web01` and rebooted.
* **Result:** The boot process **paused indefinitely** at the encryption password prompt. Because the client could not reach `192.168.70.10:8080`, it refused to unlock the data, simulating total data protection in a theft scenario.
