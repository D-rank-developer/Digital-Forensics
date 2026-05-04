# Digital Forensics Report — Windows Registry and Memory Analysis

## Overview

A multi-part forensic investigation conducted under a single case reference (**DF-2026-001**), covering three distinct evidence sources from a suspected insider incident. The investigation was performed on forensic copies of the original media in line with **ACPO principles** and **NIST SP 800-86** guidance, with full chain of custody maintained throughout.

The report brings together three correlated examinations:

1. **USB Forensic Image Analysis** — recovery of a hidden VeraCrypt container.
2. **Memory Forensics** — volatile memory analysis of a Windows 10 host.
3. **Windows Registry Forensics** — persistence and execution timeline reconstruction from a system image.

Each examination stands on its own, but read together they reconstruct a coherent picture of the suspect's actions: data concealment on removable media, live execution of an attack-simulation framework, and persistence mechanisms designed to survive reboot.

---

## Evidence

| Source | File | Description |
|--------|------|-------------|
| USB drive | `USB_01.E01` | Kingston Traveller 3.0 image — MD5 `f8aeafc1f97573f068ec3c1ad9787d4c`, SHA1 `c926fbceea5058fa1cb5db99c30b816521734545` |
| Memory capture | `MemoryEvidenceP2.raw` | Windows 10 RAM dump — SHA1 `ca3ded67e46d17662af5e568c5c8fd965a4c396b`, captured 2024-03-22 18:51:26 UTC |
| Disk image | `WinRegEvidenceP3.vhd` | Windows 10 Enterprise Evaluation VM, hostname `DESKTOP-2GA7FPC`, primary user *Student* |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| **FTK Imager** | Image verification, evidence properties inspection, registry hive export |
| **Autopsy 4.20** | File system analysis, keyword search, timeline reconstruction |
| **PowerShell** | SHA-256 hash generation for password derivation, timestamp decoding |
| **VeraCrypt** | Decryption and mounting of the recovered encrypted container |
| **Volatility 3** | Memory analysis — OS identification, process listing, service enumeration, SID extraction |
| **AccessData Registry Viewer** | Parsing SAM, SYSTEM, SOFTWARE, and NTUSER.DAT hives |
| **Kali Linux** | Analysis environment for Volatility and supporting CLI utilities |

---

## Part 1 — USB Forensic Image Analysis

Forensic examination of `USB_01.E01` to verify integrity, identify deleted content, and determine whether a suspected encrypted container could be accessed.

**Key work:**
- Image verification via MD5 and SHA1 hash matching.
- Identification of allocated, unallocated, carved, and orphaned files in Autopsy.
- Detection of a high-entropy file `Tom&` (entropy 7.999999, no extension) flagged as a likely encrypted container.
- Password derivation by hashing candidate filenames in the Pictures directory — `Jerry.jpg` produced the SHA-256 used as the VeraCrypt password.
- Successful decryption and mounting of a hidden volume containing concealed property images, plans, maps, and documents.

**Outcome:** Anti-forensic activity confirmed — encrypted storage, deliberate concealment, and a secondary hidden volume embedded within the USB device.

---

## Part 2 — Memory Forensics

Volatile memory analysis of `MemoryEvidenceP2.raw` to identify suspicious process activity and reconstruct the order of execution.

**Key work:**
- Integrity verification via SHA1 hash comparison.
- OS identification (Windows 10, Build 10.0.19041, x64).
- Process timeline reconstruction using PID/PPID relationships:
  - `Sysmon.exe` (PID 3752) — 18:44:38 UTC
  - `powershell.exe` (PID 4364) — 18:46:29 UTC
  - `AtomicService.exe` (PID 2200) — 18:48:07 UTC
  - `notepad.exe` (PID 916) — 18:48:10 UTC
- Identification of `AtomicService.exe` as a .NET-based Windows service linked to the **Atomic Red Team framework** and **MITRE ATT&CK technique T1543.003** (Windows Service — persistence and privilege escalation).
- Privilege analysis showing escalation from user context (`Student`, `S-1-5-21-...-1001`) to **Local System** (`S-1-5-18`).
- Memory dump extraction and string analysis confirming `mscoree.dll`, `System.ServiceProcess`, and `ServiceBase` references.

**Outcome:** Behaviour consistent with a deliberate Atomic Red Team simulation rather than opportunistic malware — high-privilege Windows service execution preceded by user-context PowerShell activity.

---

## Part 3 — Windows Registry Forensics

Registry and disk artefact analysis of `WinRegEvidenceP3.vhd` to reconstruct user activity and corroborate the memory findings.

**Key work:**
- System information extracted from registry: OS, hostname, registered owner, time zone, machine ID, network configuration.
- User account analysis from SAM hive — 6 accounts identified, *Student* as the primary user (RID 1001, 41 logons).
- Detection of a newly created `art-test` account at 18:47:50 UTC, immediately preceding suspicious activity.
- Identification of Atomic Red Team artefacts: `ART-attack.ps1`, `Invoke-AtomicRedTeam.psd1`, `T1055.exe` (Process Injection), `T1036.003.exe` (Masquerading), AdFind.
- Persistence mechanisms identified: `batstartup.bat` in the user Startup folder, scheduled tasks under `HKLM\Software\...\TaskCache`, and `AtomicService.exe` registered in run keys.
- Execution evidence from BAM and Prefetch: PowerShell ran 10 times, cmd.exe 7 times, alongside `HxD64.exe` activity by the Student account.

**Outcome:** Structured, intentional activity consistent with an Atomic Red Team attack simulation. Registry, file system, and execution evidence corroborate the memory findings — same Student account, same 22 March 2024 18:44–18:48 UTC window, same `AtomicService.exe` payload.

---

## Cross-Source Correlation

The three examinations independently support the same conclusion:

- The **USB** demonstrates the suspect's capability and intent to conceal data using anti-forensic techniques (encrypted containers).
- The **memory capture** shows live execution of a privileged service tied to Atomic Red Team during a specific window on 22 March 2024.
- The **registry image** corroborates that timeline with disk-resident artefacts and demonstrates that persistence mechanisms were configured to re-execute on logon.

Timestamps, the Student account SID, and the `AtomicService.exe` payload appear consistently across the memory and registry sources.

---

## Repository Contents

- `Report.pdf` — full digital forensics report covering all three examinations
- `chain_of_custody.pdf` — CoC tracking form
- `screenshots/` — supporting evidence images organised by part
  - `usb/` — FTK Imager properties, hash verification, Autopsy ingest, decrypted volume contents
  - `memory/` — Volatility output, hash comparisons, process trees, SID and privilege tables
  - `registry/` — Registry Viewer extracts, Autopsy timelines, Prefetch entries, BAM records

---

## Conclusion

The combined evidence supports a finding of structured, intentional activity consistent with an internal attack simulation using the Atomic Red Team framework, alongside use of anti-forensic techniques on removable media. Evidence preservation followed forensic best practice throughout, and the conclusions drawn are limited strictly to the artefacts examined.
