# Security Baselines

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Graph API](https://img.shields.io/badge/Microsoft%20Graph-beta-0078d4?logo=microsoft)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078d4?logo=windows)

Three Security Baseline deployment scripts, each targeting a distinct area of the Windows security configuration. The baselines are intentionally scoped to avoid overlap, ensuring no policy conflicts when all three are deployed simultaneously.

## Baselines at a Glance

| Script | Intune Policy Name | What It Covers |
|---|---|---|
| `Windows/Deploy-WindowsSecurityBaseline.ps1` | *OnCloud - Windows Security Baseline* | OS hardening: UAC, SMB, RPC, network, credential protection, audit, power, autoplay, lock screen, and more |
| `MDE/Deploy-MDESecurityBaseline.ps1` | *OnCloud - MDE Security Baseline* | Microsoft Defender Antivirus + Windows Firewall settings from the MDE baseline |
| `M365/Deploy-M365AppsSecurityBaseline.ps1` | *OnCloud - M365 Apps Security Baseline* | Microsoft 365 Apps for Enterprise hardening: macros, ActiveX, add-ins, connected experiences |

## Scope Design

Each baseline excludes areas managed by another policy to prevent conflicts. The table shows which policy owns each setting area.

| Setting Area | Windows | MDE | M365 Apps | Owner |
| :--- | :---: | :---: | :---: | :--- |
| OS hardening (UAC, SMB, RPC, network) | ✅ | — | — | Windows Baseline |
| Microsoft Defender Antivirus | — | ✅ | — | MDE Baseline |
| Windows Firewall | — | ✅ | — | MDE Baseline |
| Microsoft 365 Apps for Enterprise | — | — | ✅ | M365 Baseline |
| Attack Surface Reduction (ASR) rules | — | — | — | `ASR/Deploy-ASRPolicy.ps1` |
| Network Protection | — | — | — | `ASR/Deploy-ASRPolicy.ps1` |
| BitLocker / Disk Encryption | — | — | — | `BitLocker/` |
| Windows Hello for Business | — | — | — | *Separate identity policy* |

> [!NOTE]
> `baseline-comparison.txt` documents the overlap analysis between the Windows and MDE baselines. Eight settings appear in both with identical values — no conflicts exist.

## Deployment Order

```
1. Deploy-WindowsSecurityBaseline.ps1   — OS hardening layer
2. Deploy-MDESecurityBaseline.ps1       — Defender AV + Firewall layer
3. Deploy-M365AppsSecurityBaseline.ps1  — Office application hardening layer
```

All three can be deployed in the same session and assigned to the same device groups. Re-running any script is safe — each checks for an existing policy before creating one.

## Prerequisites

| Requirement | Detail |
| :--- | :--- |
| PowerShell | 5.1 or later |
| Module | `Microsoft.Graph.Authentication` — auto-installed if missing |
| Graph permission | `DeviceManagementConfiguration.ReadWrite.All` |
| Role | Intune Administrator or Global Administrator |
| Platform | Windows 10 (version 1903+) or Windows 11 |

## Files

| File | Purpose |
|---|---|
| `Windows/Deploy-WindowsSecurityBaseline.ps1` | Windows MDM Security Baseline deployment |
| `Windows/baseline-settings.json` | Generated audit file of all settings deployed by the Windows baseline script |
| `Windows/SecurityBaseline_Deployment_Log.txt` | Timestamped run log |
| `Windows/README.md` | Full documentation including settings breakdown |
| `MDE/Deploy-MDESecurityBaseline.ps1` | MDE Security Baseline deployment |
| `MDE/mde-baseline-settings.json` | Generated audit file of all settings deployed by the MDE baseline script |
| `MDE/MDE_Baseline_Deployment_Log.txt` | Timestamped run log |
| `MDE/README.md` | Full documentation including settings breakdown |
| `M365/Deploy-M365AppsSecurityBaseline.ps1` | M365 Apps Security Baseline deployment |
| `M365/README.md` | Full documentation |
| `baseline-comparison.txt` | Cross-baseline overlap analysis (Windows vs MDE) |
| `m365-templates.txt` | M365 Apps template metadata retrieved from the tenant |
