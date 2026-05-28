# ASR Rules Policy

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Graph API](https://img.shields.io/badge/Microsoft%20Graph-beta-0078d4?logo=microsoft)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078d4?logo=windows)

Deploys the **OnCloud - ASR Rules** policy to Microsoft Intune as an **Endpoint Security > Attack Surface Reduction > Attack Surface Reduction Rules** profile using the modern `configurationPolicies` API. The script targets the **Attack Surface Reduction Rules** template specifically (and excludes sibling profile types like App and Browser Isolation, Device Control, and Exploit Protection). All 17 ASR rules are set to **Block** by default, and Controlled Folder Access is set to **Audit**. A dedicated `-AuditMode` flag deploys all ASR rules in Audit mode for safe initial rollout.

> [!TIP]
> Deploy in Audit mode first (`-AuditMode`), monitor for 2–4 weeks, then switch to Block. See [Audit to Block Migration](#audit-to-block-migration) below.

> [!NOTE]
> Network Protection is **not** part of this template — it is deployed via the MDE Security Baseline (`SecurityBaseline/MDE/`).

## Files

| File | Purpose |
| :--- | :--- |
| `Deploy-ASRPolicy.ps1` | Deployment script |
| `asr-settings.json` *(generated)* | Auto-generated audit file of all compiled settings (created on each run) |
| `ASR_Deployment_Log.txt` *(generated)* | Auto-generated timestamped run log |

## What the Policy Configures

<details>
<summary>Expand — 17 ASR rules + Controlled Folder Access (Audit)</summary>

### ASR Rules (17)

All rules are set to **Block** (or **Audit** when `-AuditMode` is used).

| # | Rule | Notes |
| :--- | :--- | :--- |
| 1 | Block abuse of exploited vulnerable signed drivers | Prevents drivers with known vulnerabilities from being loaded |
| 2 | Block Adobe Reader from creating child processes | Prevents PDF exploits from spawning processes |
| 3 | Block all Office applications from creating child processes | Prevents Office from launching unexpected child processes |
| 4 | Block credential stealing from LSASS | Blocks LSASS memory dumping tools (Mimikatz, etc.) |
| 5 | Block executable content from email client and webmail | Blocks executables and scripts launched directly from email |
| 6 | Block executable files unless they meet prevalence/age/trusted list criteria | Cloud-backed block on low-prevalence files |
| 7 | Block execution of potentially obfuscated scripts | Detects and blocks obfuscated PowerShell/JS/VBS |
| 8 | Block JavaScript or VBScript from launching downloaded executable content | Prevents script-based dropper payloads |
| 9 | Block Office applications from creating executable content | Prevents Office from writing and running executables |
| 10 | Block Office applications from injecting code into other processes | Prevents process injection from Office apps |
| 11 | Block Office communication application from creating child processes | Prevents Outlook from spawning child processes |
| 12 | Block persistence through WMI event subscription | Blocks WMI-based persistence mechanisms |
| 13 | Block process creations originating from PSExec and WMI commands | Blocks lateral movement via PSExec/WMI |
| 14 | Block untrusted and unsigned processes that run from USB | Blocks autoruns and unsigned binaries from removable media |
| 15 | Block Win32 API calls from Office macros | Prevents Office macros from making direct Win32 API calls |
| 16 | Use advanced protection against ransomware | Heuristic ransomware detection using cloud intelligence |
| 17 | Block Web Shell creation for Servers | Prevents web shell scripts from being created on IIS/web servers |

### Controlled Folder Access

| Setting | Value |
| :--- | :--- |
| Enable Controlled Folder Access | **Audit (always)** |

Controlled Folder Access is set to **Audit** regardless of `-AuditMode`. In Audit mode it logs which apps would have been blocked without actually blocking anything, so no allow-list is needed. Once you've reviewed the audit logs and built an allow-list for your environment, you can change this to Block in a separate CFA policy.

> [!NOTE]
> **Network Protection** is not included in this template. It is deployed via the MDE Security Baseline (`SecurityBaseline/MDE/`).

</details>

## Prerequisites

| Requirement | Detail |
| :--- | :--- |
| PowerShell | 5.1 or later |
| Module | `Microsoft.Graph.Authentication` — auto-installed if missing |
| Graph permission | `DeviceManagementConfiguration.ReadWrite.All` |
| Role | Intune Administrator or Global Administrator |
| OS | Windows 10 1709 (RS3) or later; Windows 11 |
| Defender AV | Microsoft Defender Antivirus must be in **active mode** |

## Usage

```powershell
# Create in Audit mode (recommended first step)
.\Deploy-ASRPolicy.ps1 -AuditMode -AssignToAllDevices

# Create in Block mode after audit assessment
.\Deploy-ASRPolicy.ps1 -AssignToAllDevices

# Assign to a specific Entra ID group
.\Deploy-ASRPolicy.ps1 -AssignToGroupId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Recreate if a policy with the same name already exists
.\Deploy-ASRPolicy.ps1 -Force -AssignToAllDevices

# Switch from Audit to Block: force-recreate the Block policy
# (run after the Audit policy has been deployed and monitored)
.\Deploy-ASRPolicy.ps1 -Force -AssignToAllDevices
```

> [!NOTE]
> Audit mode and Block mode create **separately named policies** (`OnCloud - ASR Rules (Audit)` vs `OnCloud - ASR Rules`), so both can coexist in the tenant during the transition period. Delete the Audit policy once Block is confirmed stable.

## Audit to Block Migration

1. **Deploy Audit mode** — `.\Deploy-ASRPolicy.ps1 -AuditMode -AssignToAllDevices`
2. **Monitor** for 2–4 weeks using:
   - MDE Advanced Hunting: query `DeviceEvents | where ActionType startswith "Asr"`
   - Event Viewer: `Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational` (Event ID 1121 = Block, 1122 = Audit)
   - MDE portal: **Reports > Attack surface reduction rules**
3. **Investigate** any triggered events. Common false positives:
   - `Block process creations from PSExec/WMI` — may affect IT management tools (SCCM, RMM agents)
   - `Block Win32 API calls from Office macros` — may break legacy Office automation/macros
4. **Switch to Block** — `.\Deploy-ASRPolicy.ps1 -Force -AssignToAllDevices`
5. **Delete the Audit policy** — remove `OnCloud - ASR Rules (Audit)` from the Intune admin center.

> [!WARNING]
> The rules **Block process creations from PSExec/WMI** and **Block Win32 API calls from Office macros** are the most likely to cause false positives in environments using IT management tools or Office macros. Review Audit mode results carefully before switching to Block.

## How It Works

1. Installs `Microsoft.Graph.Authentication` if not present.
2. Connects to Microsoft Graph with `DeviceManagementConfiguration.ReadWrite.All`.
3. Queries all configuration policy templates and selects the `endpointSecurityAttackSurfaceReduction` template with `lifecycleState = active` and the highest version.
4. Fetches all setting templates from the selected template via `/settingTemplates`.
5. Processes setting types: group setting collections (ASR rules) and standalone choice settings (CFA).
6. For each ASR rule, overrides the value to Block (`_block`) or Audit (`_audit`) based on `-AuditMode`. CFA is always set to Audit (`_2`).
7. Exclusion and allow-list collection settings are skipped (empty by design).
8. Attempts to POST the compiled settings to `/beta/deviceManagement/configurationPolicies`.
9. If the API returns a dependency error (a parent setting requires missing child settings), the script resolves the child definition and retries — looping for up to 300 attempts.
10. Saves compiled settings as `asr-settings.json` for audit.

## API Reference

| Operation | Endpoint |
| :--- | :--- |
| Discover ASR template | `GET /beta/deviceManagement/configurationPolicyTemplates` |
| Fetch setting templates | `GET /beta/deviceManagement/configurationPolicyTemplates/{id}/settingTemplates` |
| Create policy | `POST /beta/deviceManagement/configurationPolicies` |
| Delete policy | `DELETE /beta/deviceManagement/configurationPolicies/{id}` |
| Assign policy | `POST /beta/deviceManagement/configurationPolicies/{id}/assign` |
| Resolve child setting | `GET /beta/deviceManagement/configurationSettings/{id}` |

## Troubleshooting

| Symptom | Resolution |
| :--- | :--- |
| `Policy already exists` warning | Run with `-Force` to delete and recreate |
| `No Attack Surface Reduction template found` | Verify the tenant has an Intune licence and the Endpoint Security workload is enabled |
| Rules not applying to devices | Confirm Defender AV is in active mode (not passive or disabled). ASR rules require active AV |
| High false positive rate after switching to Block | Switch back to Audit mode (`-Force -AuditMode`), investigate triggered events, add exclusions if needed |
| Dependency error not resolving | Check `ASR_Deployment_Log.txt` for the unresolved `settingDefinitionId` |
| Authentication fails | Ensure the account has the Intune Administrator role and `DeviceManagementConfiguration.ReadWrite.All` is consented |
