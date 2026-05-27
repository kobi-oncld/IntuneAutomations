# M365 Apps Security Baseline

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Graph API](https://img.shields.io/badge/Microsoft%20Graph-beta-0078d4?logo=microsoft)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078d4?logo=windows)

Deploys the **OnCloud - M365 Apps Security Baseline** policy to Microsoft Intune as an Endpoint Security configuration policy. The profile is built from the latest active **Microsoft 365 Apps for Enterprise Security Baseline** template and covers Office application hardening: macro settings, ActiveX controls, add-in trust, connected experiences, and more. All settings from the template are included by default.

## Files

| File | Purpose |
| :--- | :--- |
| `Deploy-M365AppsSecurityBaseline.ps1` | Deployment script |
| `m365-baseline-settings.json` *(generated)* | Auto-generated audit file of all compiled settings (created on each run) |
| `M365_Baseline_Deployment_Log.txt` *(generated)* | Auto-generated timestamped run log |

## What the Baseline Covers

The Microsoft 365 Apps for Enterprise Security Baseline hardens the Office application suite. Key areas include:

| Area | Examples |
| :--- | :--- |
| **Macro security** | Block VBA macros from untrusted locations; require macros to be signed; disable macros in Office files from the internet |
| **ActiveX controls** | Disable ActiveX in Office documents |
| **Add-in trust** | Require add-ins to be signed by a trusted publisher; disable untrusted add-ins |
| **Connected experiences** | Restrict optional connected experiences that share diagnostic data |
| **External content** | Disable automatic loading of external content in documents |
| **Protected View** | Enforce Protected View for files from the internet, unsafe locations, and Outlook attachments |
| **Attack Surface Reduction** | Disable legacy file formats known to carry macro attacks |
| **Telemetry** | Configure Office diagnostic data level |

> [!TIP]
> The script deploys the **full** template without exclusions. To exclude specific settings, add lowercase keyword fragments to the `$excludeKeywords` array before running.

## Template Versions

Two template versions exist in the tenant (captured in `../m365-templates.txt`):

| Template ID | Version | Lifecycle State |
| :--- | :---: | :--- |
| `90316f12-246d-44c6-a767-f87692e86083_1` | 1 | Superseded |
| `90316f12-246d-44c6-a767-f87692e86083_2` | **2** | **Active** ← *script selects this* |

> [!NOTE]
> The script always selects the `lifecycleState = active` template with the highest version. Superseded templates are automatically skipped.

## Prerequisites

| Requirement | Detail |
| :--- | :--- |
| PowerShell | 5.1 or later |
| Module | `Microsoft.Graph.Authentication` — auto-installed if missing |
| Graph permission | `DeviceManagementConfiguration.ReadWrite.All` |
| Role | Intune Administrator or Global Administrator |
| Platform | Windows 10 (version 1903+) or Windows 11 with Microsoft 365 Apps installed |

## Usage

```powershell
# Create the policy (no assignment)
.\Deploy-M365AppsSecurityBaseline.ps1

# Delete and recreate if a policy with the same name already exists
.\Deploy-M365AppsSecurityBaseline.ps1 -Force
```

After creation, assign the policy to the target device groups in the Intune admin center:
**Endpoint Security > Security baselines > OnCloud - M365 Apps Security Baseline > Properties > Assignments**

## How It Works

1. Installs `Microsoft.Graph.Authentication` if not present.
2. Connects to Microsoft Graph with `DeviceManagementConfiguration.ReadWrite.All`.
3. Queries **all** configuration policy templates and logs every M365 Apps-matching template. The `lifecycleState = active` template with the highest version is selected.
4. Fetches all setting templates from the selected template via `/settingTemplates`.
5. Processes three setting types:
   - **Packed choice settings** — space-separated token list encoding all choice settings.
   - **Unpacked choice settings** — standard `ChoiceSettingInstanceTemplate` objects.
   - **Simple settings** — integer or string scalar values.
   - **Simple setting collections** — array-typed settings.
6. Applies the `$excludeKeywords` filter (empty by default — all settings included).
7. POSTs the compiled settings to `/beta/deviceManagement/configurationPolicies`.
8. On dependency errors (parent setting requires missing child), the script resolves the child definition and retries (up to 300 attempts).
9. Saves the compiled settings as `m365-baseline-settings.json` for audit.

## Customization

> [!TIP]
> To exclude specific settings (e.g., telemetry-related settings), edit the `$excludeKeywords` array in the script before running:

```powershell
$excludeKeywords = @(
    'telemetry'    # Excludes all settings whose definition ID contains 'telemetry'
)
```

Keywords are matched case-insensitively against the full `settingDefinitionId` string.

## Post-Deployment Verification

1. Navigate to **Endpoint Security > Security baselines** in the Intune admin center.
2. Locate **OnCloud - M365 Apps Security Baseline**.
3. Review the settings to confirm the macro, ActiveX, and add-in hardening settings are configured.
4. Assign the profile to the target device group.
5. On a target device, open any Office application and verify that macro execution from untrusted sources is blocked.

## Overlap with Other Baselines

> [!NOTE]
> The M365 Apps baseline does not overlap with the Windows MDM Security Baseline or the MDE Security Baseline. It is entirely scoped to Office application behaviour and can be deployed alongside both without conflict.

## Troubleshooting

| Symptom | Resolution |
| :--- | :--- |
| `Policy already exists` warning | Run with `-Force` to delete and recreate |
| `No M365 Apps Security Baseline template found` | Verify the tenant has a Microsoft 365 Apps licence; check if `Microsoft 365 Apps for Enterprise` appears in `/beta/deviceManagement/configurationPolicyTemplates` |
| Settings not applying to Office | Confirm the policy is assigned to the device group and the device has checked in since assignment; verify Microsoft 365 Apps is deployed via Intune or existing installation |
| Authentication fails | Ensure the account has the Intune Administrator role and `DeviceManagementConfiguration.ReadWrite.All` is consented |
