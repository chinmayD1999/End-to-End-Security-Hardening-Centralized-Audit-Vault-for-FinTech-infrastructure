## 📑 Table of Contents

**1. Project Overview**

* 1.1 Introduction
* 1.2 Objective: Zero Trust & Centralized Security
* 1.3 Scope of Work

**2. System Architecture & Design**

* 2.1 High-Level Architecture (The "Control Plane" vs. "Workload Node")
* 2.2 Network Topology: The Air-Gapped Environment (192.168.70.0/24)
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

### End to End Security Hardening Centralized Audit Vault for FinTech infrastructure

------------------------------------------------------------

#### Designed a Zero Trust, secure and isolated Linux fintech infrastructure, separating the architecture into a Control Plane (Infra) and a Workload Node (Web Client). Enforced strict security controls requiring cryptographic authorization from the central infrastructure for all boot, operational, and data access activities, ensuring complete dependency on the secure core.

------------------------------------------------------------

<p align="center">
  <img src="Architecture.png" width="850">
</p>

<p align="center">
  <em>Isolated Zero Trust Architecture for FinTech Environment</em>
</p>

