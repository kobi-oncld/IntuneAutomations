# Intune Automations

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Graph API](https://img.shields.io/badge/Microsoft%20Graph-beta-0078d4?logo=microsoft)
![Platform](https://img.shields.io/badge/Platform-Windows%20%C2%B7%20macOS%20%C2%B7%20iOS%20%C2%B7%20Android-lightgrey)

PowerShell scripts that deploy hardened Microsoft Intune policies to an Entra ID-connected tenant via the Microsoft Graph API. All scripts are **idempotent**, log every action to a timestamped file, and support a `-Force` flag to delete and recreate existing policies.

## Repository Structure

```
IntuneAutomations/
├── ASR/
│   ├── Deploy-ASRPolicy.ps1            # Endpoint Security > Attack Surface Reduction policy
│   ├── asr-settings.json               # Generated settings audit file
│   └── README.md
│
├── BitLocker/
│   ├── Deploy-BitLockerPolicy.ps1      # Endpoint Security > Disk Encryption policy
│   ├── BitLocker-Policy.json           # Policy body template (templateId injected at runtime)
│   └── README.md
│
├── Compliance/
│   ├── Deploy-WindowsCompliancePolicy.ps1   # Windows 10/11 compliance policy
│   ├── Deploy-macOSCompliancePolicy.ps1     # macOS compliance policy
│   ├── README.md                            # Windows compliance docs
│   └── README-macOS.md                      # macOS compliance docs
│
├── MAMPolicies/
│   ├── New-MAMPolicies.ps1             # iOS + Android app protection policies
│   ├── MAM_Deployment_Log.txt          # Auto-generated run log
│   └── README.md
│
└── SecurityBaseline/
    ├── Windows/
    │   ├── Deploy-WindowsSecurityBaseline.ps1
    │   ├── baseline-settings.json          # Generated settings audit file
    │   ├── SecurityBaseline_Deployment_Log.txt
    │   └── README.md
    ├── MDE/
    │   ├── Deploy-MDESecurityBaseline.ps1
    │   ├── mde-baseline-settings.json      # Generated settings audit file
    │   ├── MDE_Baseline_Deployment_Log.txt
    │   └── README.md
    ├── M365/
    │   ├── Deploy-M365AppsSecurityBaseline.ps1
    │   └── README.md
    ├── baseline-comparison.txt         # Overlap analysis between Windows and MDE baselines
    └── README.md
```

## Policy Summary

| Area | Script | Policy Created in Intune | Platform |
|---|---|---|---|
| **Disk Encryption** | `BitLocker/Deploy-BitLockerPolicy.ps1` | Endpoint Security > Disk Encryption > *OnCloud - Bitlocker* | Windows 10/11 |
| **ASR Rules (Block)** | `ASR/Deploy-ASRPolicy.ps1` | Endpoint Security > Attack Surface Reduction > *OnCloud - ASR Rules* | Windows 10/11 |
| **ASR Rules (Audit)** | `ASR/Deploy-ASRPolicy.ps1 -AuditMode` | Endpoint Security > Attack Surface Reduction > *OnCloud - ASR Rules (Audit)* | Windows 10/11 |
| **Windows Compliance** | `Compliance/Deploy-WindowsCompliancePolicy.ps1` | Devices > Compliance > *OnCloud - Windows Compliance* | Windows 10/11 |
| **macOS Compliance** | `Compliance/Deploy-macOSCompliancePolicy.ps1` | Devices > Compliance > *OnCloud - macOS Compliance* | macOS 14+ |
| **MAM – iOS** | `MAMPolicies/New-MAMPolicies.ps1` | Apps > App protection > *MAM - iOS - Core Microsoft Apps* | iOS/iPadOS |
| **MAM – Android** | `MAMPolicies/New-MAMPolicies.ps1` | Apps > App protection > *MAM - Android - Core Microsoft Apps* | Android |
| **Windows Security Baseline** | `SecurityBaseline/Windows/Deploy-WindowsSecurityBaseline.ps1` | Endpoint Security > Security baselines > *OnCloud - Windows Security Baseline* | Windows 10/11 |
| **MDE Security Baseline** | `SecurityBaseline/MDE/Deploy-MDESecurityBaseline.ps1` | Endpoint Security > Security baselines > *OnCloud - MDE Security Baseline* | Windows 10/11 |
| **M365 Apps Security Baseline** | `SecurityBaseline/M365/Deploy-M365AppsSecurityBaseline.ps1` | Endpoint Security > Security baselines > *OnCloud - M365 Apps Security Baseline* | Windows 10/11 |

## Prerequisites

All scripts share the following requirements:

| Requirement | Detail |
|---|---|
| PowerShell | 5.1 or later (PowerShell 7+ recommended) |
| PowerShell Module | `Microsoft.Graph.Authentication` — auto-installed if missing |
| Entra ID Role | **Intune Administrator** or **Global Administrator** |
| Graph Permissions | Varies per script — see each folder's README |
| Execution Policy | `Set-ExecutionPolicy RemoteSigned -Scope Process` |

## Deployment Order

Deploy in this order to avoid policy conflicts. Each area manages its own settings and the baselines are configured to avoid overlap.

```
1.  Deploy-BitLockerPolicy.ps1              (Disk Encryption)
2.  Deploy-WindowsSecurityBaseline.ps1      (OS hardening — excludes BitLocker/Defender/Firewall/ASR)
3.  Deploy-MDESecurityBaseline.ps1          (Defender AV + Firewall — excludes ASR/BitLocker/WHfB)
4.  Deploy-M365AppsSecurityBaseline.ps1     (Office app hardening)
5.  Deploy-ASRPolicy.ps1 -AuditMode         (ASR + Network Protection in Audit — assess impact first)
6.  Deploy-WindowsCompliancePolicy.ps1      (Compliance gate — depends on BitLocker + Defender being deployed)
7.  Deploy-macOSCompliancePolicy.ps1        (macOS compliance gate)
8.  New-MAMPolicies.ps1                     (MAM for BYOD/mobile — independent of above)
```

> [!NOTE]
> After 2–4 weeks, switch ASR from Audit to Block: `Deploy-ASRPolicy.ps1 -Force -AssignToAllDevices`

## Quick Start

```powershell
# Example: deploy all policies without assignments (review before assigning)
Set-ExecutionPolicy RemoteSigned -Scope Process

.\BitLocker\Deploy-BitLockerPolicy.ps1
.\SecurityBaseline\Windows\Deploy-WindowsSecurityBaseline.ps1
.\SecurityBaseline\MDE\Deploy-MDESecurityBaseline.ps1
.\SecurityBaseline\M365\Deploy-M365AppsSecurityBaseline.ps1
.\ASR\Deploy-ASRPolicy.ps1 -AuditMode
.\Compliance\Deploy-WindowsCompliancePolicy.ps1 -SkipMdeRiskScore
.\Compliance\Deploy-macOSCompliancePolicy.ps1   -SkipMdeRiskScore
.\MAMPolicies\New-MAMPolicies.ps1
```

> [!TIP]
> Remove `-SkipMdeRiskScore` from the compliance scripts once Microsoft Defender for Endpoint is integrated with Intune.

After creation, assign each policy to the appropriate Entra ID groups from the Intune admin center.

## Policy Overlap Design

The three security baselines are deliberately scoped to avoid conflicts.

| Setting Area | Windows Baseline | MDE Baseline | Owner |
| :--- | :---: | :---: | :--- |
| OS Hardening (UAC, SMB, RPC…) | ✅ | — | Windows Baseline |
| Microsoft Defender Antivirus | — | ✅ | MDE Baseline |
| Windows Firewall | — | ✅ | MDE Baseline |
| M365 Apps (macros, ActiveX, add-ins) | — | — | M365 Baseline |
| Attack Surface Reduction (ASR) | — | — | `ASR/` |
| Network Protection | — | — | `ASR/` |
| BitLocker / Disk Encryption | — | — | `BitLocker/` |
| Windows Hello for Business | — | — | *Separate identity policy* |

> [!NOTE]
> `SecurityBaseline/baseline-comparison.txt` contains the full overlap analysis between the Windows and MDE baselines. Eight settings appear in both with identical values — no conflicts.

## Graph API Endpoints

| Operation | Endpoint |
| :--- | :--- |
| Create configuration policy | `POST /beta/deviceManagement/configurationPolicies` |
| Delete configuration policy | `DELETE /beta/deviceManagement/configurationPolicies/{id}` |
| Discover baseline templates | `GET /beta/deviceManagement/configurationPolicyTemplates` |
| Create compliance policy | `POST /beta/deviceManagement/deviceCompliancePolicies` |
| Create app protection (iOS) | `POST /beta/deviceAppManagement/iosManagedAppProtections` |
| Create app protection (Android) | `POST /beta/deviceAppManagement/androidManagedAppProtections` |
| Discover ASR/Baseline template | `GET /beta/deviceManagement/configurationPolicyTemplates` |

---

> [!CAUTION]
> Review and test all scripts in a non-production tenant before deploying to production.
