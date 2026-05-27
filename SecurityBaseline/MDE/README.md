# MDE Security Baseline

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Graph API](https://img.shields.io/badge/Microsoft%20Graph-beta-0078d4?logo=microsoft)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078d4?logo=windows)

Deploys the **OnCloud - MDE Security Baseline** policy to Microsoft Intune as an Endpoint Security configuration policy using the modern `configurationPolicies` API. The profile is built from the latest active **Microsoft Defender for Endpoint (MDE) Security Baseline** template and includes Defender Antivirus and Windows Firewall settings. Settings managed by other dedicated policies (ASR, BitLocker, Windows Hello) are excluded to prevent conflicts.

## Files

| File | Purpose |
| :--- | :--- |
| `Deploy-MDESecurityBaseline.ps1` | Deployment script |
| `mde-baseline-settings.json` | Auto-generated audit file of all compiled settings (created on each run) |
| `MDE_Baseline_Deployment_Log.txt` | Auto-generated timestamped run log |

## Scope

| Category | Status | Owner |
| :--- | :---: | :--- |
| Microsoft Defender Antivirus | ✅ Included | This policy |
| Windows Firewall | ✅ Included | This policy |
| SmartScreen (Explorer, IE, Edge) | ✅ Included | This policy |
| Device Guard (Credential Guard / LSA) | ✅ Included | This policy |
| DMA Guard | ✅ Included | This policy |
| Device Installation restrictions | ✅ Included | This policy |
| Attack Surface Reduction (ASR) rules | — Excluded | Dedicated ASR policy |
| Network Protection | — Excluded | Deployed with ASR policy |
| BitLocker / Device Encryption | — Excluded | `BitLocker/Deploy-BitLockerPolicy.ps1` |
| Windows Hello for Business | — Excluded | Dedicated identity / enrollment config |

## Settings Breakdown

<details>
<summary>Expand — all configured settings by category</summary>

### Microsoft Defender Antivirus

| Setting | Value | Description |
| :--- | :--- | :--- |
| Allow Archive Scanning | **Enabled** | Scans archive files (ZIP, CAB, etc.) |
| Allow Behavior Monitoring | **Enabled** | Real-time monitoring of behavioral anomalies |
| Allow Cloud Protection | **Enabled** | MAPS cloud-based protection |
| Allow Email Scanning | **Enabled** | Scans email body and attachments |
| Allow Full Scan on Removable Drives | **Enabled** | Removable drives included in full scan |
| Allow On-Access Protection | **Enabled** | Scans files when opened or modified |
| Allow Real-Time Monitoring | **Enabled** | Real-time protection is always on |
| Allow Scanning Network Files | **Enabled** | Scans files accessed over network shares |
| Allow IOAV Protection | **Enabled** | Scans files downloaded from the internet |
| Allow Script Scanning | **Enabled** | Scans scripts before execution |
| Allow User UI Access | **Enabled** | Users can see the Defender UI (not hidden) |
| Check Signatures Before Running Scan | **Enabled** | Forces a signature update before each scan |
| Cloud Block Level | **High (2)** | Aggressive cloud-based blocking threshold |
| Cloud Extended Timeout | **50 seconds** | Extra time for cloud analysis before allowing a suspicious file |
| Disable Local Admin Merge | **Disabled (0)** | Local admin exclusion lists are merged with policy |
| Hide Exclusions from Local Admins | **Enabled** | Local administrators cannot view the exclusion list |
| Hide Exclusions from Local Users | **Enabled** | Standard users cannot view the exclusion list |
| OOBE: Enable RTP and Signature Update | **Enabled** | Real-time protection and signature updates activated during out-of-box experience |
| PUA Protection | **Enabled (Block)** | Potentially Unwanted Applications are blocked |
| Real-Time Scan Direction | **Both (0)** | Monitors both incoming and outgoing files |
| Scan Type | **Quick Scan (1)** | Scheduled scans use quick scan |
| Schedule Quick Scan Time | **02:00 (120 min)** | Quick scan runs daily at 2:00 AM |
| Schedule Scan Day | **Every Day (0)** | Scheduled scan runs daily |
| Schedule Scan Time | **02:00 (120 min)** | Full scheduled scan time (if triggered) |
| Signature Update Interval | **Every 4 hours** | Signature updates checked every 4 hours |
| Submit Samples Consent | **Send safe samples (3)** | Safe samples sent to Microsoft automatically; unsafe require consent |

### Windows Firewall

| Setting | Value | Description |
| :--- | :--- | :--- |
| Domain Profile: Firewall Enabled | **true** | Windows Firewall active on domain-joined networks |
| Private Profile: Firewall Enabled | **true** | Windows Firewall active on private networks |
| Public Profile: Firewall Enabled | **true** | Windows Firewall active on public/untrusted networks |
| Pre-shared Key Encoding | **UTF-8 (1)** | IPsec pre-shared key encoding |
| Disable Stateful FTP | **true** | FTP stateful packet inspection disabled (more secure) |
| CRL Check | **None (0)** | No CRL check for firewall certificates |
| SA Idle Time | **300 seconds (5 min)** | Security association idle timeout |

### SmartScreen

| Setting | Value | Description |
| :--- | :--- | :--- |
| Windows Explorer SmartScreen | **Enabled** | SmartScreen filter active in File Explorer |
| IE: Block bypass of SmartScreen warnings for uncommon files (Device) | **Enabled** | Users cannot bypass SmartScreen warnings in IE (device policy) |
| IE: Block bypass of SmartScreen warnings for uncommon files (User) | **Enabled** | Users cannot bypass SmartScreen warnings in IE (user policy) |
| IE: Prevent managing SmartScreen filter | **Enabled** | Users cannot disable the IE SmartScreen filter |
| Microsoft Edge: SmartScreen Enabled | **Enabled** | SmartScreen active in Edge |
| Microsoft Edge: SmartScreen PUA Enabled | **Enabled** | Potentially unwanted app blocking active in Edge |
| Microsoft Edge: SmartScreen DNS Requests Enabled | **Enabled** | DNS-based SmartScreen lookup in Edge |
| Microsoft Edge: New SmartScreen Library Enabled | **Enabled** | Updated SmartScreen engine active in Edge |
| Microsoft Edge: SmartScreen for Trusted Downloads | **Enabled** | SmartScreen checks even trusted download sources |
| Microsoft Edge: Prevent SmartScreen Prompt Override | **Enabled** | Users cannot bypass SmartScreen warnings in Edge |

### Device Guard / Credential Guard

| Setting | Value | Description |
| :--- | :--- | :--- |
| LSA Config Flags | **Enabled with UEFI lock (1)** | Credential Guard enabled and locked in UEFI — cannot be disabled without physical access |

### DMA Guard

| Setting | Value | Description |
| :--- | :--- | :--- |
| Device Enumeration Policy | **Block all (0)** | All external DMA-capable devices blocked until explicitly authorized by an administrator |

### Device Installation

| Setting | Value | Description |
| :--- | :--- | :--- |
| Prevent Installation of Matching Device Setup Classes | **Enabled** | Blocks installation of devices matching the configured setup class GUIDs |

</details>

## Prerequisites

| Requirement | Detail |
|---|---|
| PowerShell | 5.1 or later |
| Module | `Microsoft.Graph.Authentication` — auto-installed if missing |
| Graph permission | `DeviceManagementConfiguration.ReadWrite.All` |
| Role | Intune Administrator or Global Administrator |
| Platform | Windows 10 (version 1903+) or Windows 11 |

## Usage

```powershell
# Create the policy (no assignment)
.\Deploy-MDESecurityBaseline.ps1

# Delete and recreate if a policy with the same name already exists
.\Deploy-MDESecurityBaseline.ps1 -Force
```

After creation, assign the policy to the target device groups in the Intune admin center:
**Endpoint Security > Security baselines > OnCloud - MDE Security Baseline > Properties > Assignments**

## How It Works

1. Installs `Microsoft.Graph.Authentication` if not present.
2. Connects to Microsoft Graph with `DeviceManagementConfiguration.ReadWrite.All`.
3. Queries **all** configuration policy templates (no OData filter) and logs every MDE-matching template. The `lifecycleState = active` template with the highest version is selected. This approach handles Microsoft's non-monotonic version numbering across lifecycle transitions.
4. Fetches all setting templates from the selected template via `/settingTemplates`.
5. Processes three setting types:
   - **Packed choice settings** — a single API response token that encodes all choice settings in a space-separated string; each token is split and decoded.
   - **Unpacked choice settings** — standard `ChoiceSettingInstanceTemplate` objects.
   - **Simple settings** — integer or string values with a constant default.
   - **Simple setting collections** — array-typed settings (e.g., SID lists).
6. Filters out settings matching exclusion keywords (`attacksurface`, `asr`, `networkprotection`, `bitlocker`, `passportforwork`, `windowshello`, `helloforbusiness`).
7. Attempts to POST the compiled settings to `/beta/deviceManagement/configurationPolicies`.
8. If the API returns a dependency error (a parent setting requires a child setting not yet included), the script resolves the missing child definition via `/beta/deviceManagement/configurationSettings/{id}`, injects it into the settings tree, and retries. This loop continues for up to 300 attempts.
9. Saves the compiled settings as `mde-baseline-settings.json` for audit.

## Dependency Resolution

> [!NOTE]
> The Microsoft Graph API enforces parent–child setting dependencies at submission time. If a parent setting (such as *Hardened UNC Paths*) requires child sub-settings not present in the payload, the API returns an error listing the missing IDs. The script parses this error, fetches the required definitions from the Graph catalog, injects them, and retries automatically — looping for up to 300 attempts.

## Post-Deployment Verification

1. Navigate to **Endpoint Security > Security baselines** in the Intune admin center.
2. Locate **OnCloud - MDE Security Baseline**.
3. Verify that ASR rules, Network Protection, BitLocker, and Windows Hello for Business show as **Not Configured**.
4. Verify that Defender Antivirus and Firewall settings are configured.
5. Assign the profile to the target group.

## Troubleshooting

| Symptom | Resolution |
| :--- | :--- |
| `Policy already exists` warning | Run with `-Force` to delete and recreate |
| `No MDE Security Baseline template found` | Verify the tenant has an Intune licence; check if `Defender for Endpoint` or `MDE` appear in `/beta/deviceManagement/configurationPolicyTemplates` |
| Dependency error not resolving after many attempts | Check `MDE_Baseline_Deployment_Log.txt` for the exact unresolved `settingDefinitionId` and verify it exists in the tenant's settings catalog |
| Authentication fails | Ensure the account has the Intune Administrator role and `DeviceManagementConfiguration.ReadWrite.All` is consented |
