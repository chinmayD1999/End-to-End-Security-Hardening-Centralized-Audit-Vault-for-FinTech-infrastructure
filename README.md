
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

