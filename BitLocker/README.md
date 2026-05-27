# BitLocker Disk Encryption Policy

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Graph API](https://img.shields.io/badge/Microsoft%20Graph-beta-0078d4?logo=microsoft)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078d4?logo=windows)

Deploys the **OnCloud - Bitlocker** policy to Microsoft Intune as an **Endpoint Security > Disk Encryption** profile using the modern Settings Catalog API. The policy enforces silent, TPM-only, XTS-AES 256-bit full-disk encryption with mandatory Entra ID recovery key backup before encryption starts.

## Files

| File | Purpose |
|---|---|
| `Deploy-BitLockerPolicy.ps1` | Deployment script — discovers the BitLocker template dynamically and creates the policy |
| `BitLocker-Policy.json` | Policy body in Settings Catalog format (the `templateId` is injected at runtime by the script) |

## Policy Settings

<details>
<summary>Click to expand — full settings breakdown</summary>

### General

| Setting | Value | Notes |
| :--- | :--- | :--- |
| Require device encryption | **Enabled** | BitLocker must be active on all OS drives |
| Silent encryption (no warning) | **Enabled** | No user prompt when another encryption tool is present; MDM-driven silent encryption |
| Standard user encryption | **Enabled** | Standard (non-admin) accounts can trigger silent encryption |
| Recovery password rotation | **Entra ID + Hybrid joined** | Recovery key automatically rotated after each use on Entra ID and Hybrid Entra ID joined devices |

### Encryption Methods

| Drive | Algorithm | CSP Value |
| :--- | :--- | :---: |
| OS drive | **XTS-AES 256-bit** | `7` |
| Fixed data drive | **XTS-AES 256-bit** | `7` |
| Removable drive | **AES-CBC 256-bit** | `4` |

> XTS-AES is preferred for fixed drives (Windows 10 1511+). AES-CBC is used for removable drives to maintain compatibility with older Windows versions.

### Startup Authentication (OS Drive)

| Setting | Value | Notes |
| :--- | :--- | :--- |
| Startup authentication | **TPM Only** | No PIN, no USB key — clean TPM-only boot |
| Non-TPM devices | **Blocked** | BitLocker will not enable on devices without a TPM |
| TPM startup key | **Do Not Allow** | External USB key not permitted at startup |
| Startup PIN | **Do Not Allow** | No PIN required at boot |

### Recovery Options (OS Drive)

| Setting | Value | Notes |
| :--- | :--- | :--- |
| Data Recovery Agent (DRA) | **Disabled** | No certificate-based DRA |
| Recovery password (48-digit) | **Allowed** | 48-digit numerical recovery password generated |
| Recovery key (256-bit) | **Allowed** | 256-bit recovery key file generated |
| Hide recovery page in wizard | **Enabled** | Users cannot configure recovery options during BitLocker setup |
| Entra ID backup | **Required** | Recovery key + password backed up **before** encryption starts |
| Backup scope | **Password + Key Package** | Both the recovery password and full key package are escrowed |
| Require backup before enabling | **Yes** | Encryption **will not start** unless the recovery key is successfully backed up |

### Fixed Data Drives

| Setting | Value |
| :--- | :--- |
| Require encryption | **Enabled** |
| Recovery options | Same as OS drive (DRA disabled, Entra ID backup required) |

</details>

## Prerequisites

| Prerequisites |
| :--- |
| PowerShell 5.1 or later |
| `Microsoft.Graph.Authentication` — auto-installed if not present |
| `DeviceManagementConfiguration.ReadWrite.All` and `DeviceManagementEndpointSecurity.ReadWrite.All` |
| Windows 10 version 1703 or later / Windows 11 |
| TPM 1.2 or TPM 2.0 |
| Entra ID joined or Hybrid Entra ID joined |

## Usage

```powershell
# Create the policy (no assignment)
.\Deploy-BitLockerPolicy.ps1

# Create and assign to a specific Entra ID group
.\Deploy-BitLockerPolicy.ps1 -AssignToGroupId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Create and assign to the built-in All Devices group
.\Deploy-BitLockerPolicy.ps1 -AssignToAllDevices

# Delete and recreate if the policy already exists
.\Deploy-BitLockerPolicy.ps1 -Force

# Force recreate and assign to All Devices
.\Deploy-BitLockerPolicy.ps1 -Force -AssignToAllDevices

# Inspect all available BitLocker settings in this tenant's template (no policy created)
.\Deploy-BitLockerPolicy.ps1 -ShowTemplateSettings
```


## Parameters

| Parameter | Type | Description |
|---|---|---|
| `-AssignToGroupId` | `String` (GUID) | Entra ID group Object ID to assign the policy to after creation |
| `-AssignToAllDevices` | `Switch` | Assign to the built-in *All Devices* virtual group |
| `-Force` | `Switch` | Delete and recreate the policy if one with the same name already exists |
| `-ShowTemplateSettings` | `Switch` | Print all available BitLocker template settings from the tenant. No policy is created |

## How It Works

1. Installs `Microsoft.Graph.Authentication` if not present.
2. Authenticates interactively with the required Graph scopes.
3. Discovers the Endpoint Security > Disk Encryption (BitLocker) template for Windows 10 by querying `/beta/deviceManagement/configurationPolicyTemplates` — the template ID is tenant-specific and never hardcoded.
4. Checks for an existing policy named `OnCloud - Bitlocker`.
   - If found and `-Force` is not set: exits without changes.
   - If found and `-Force` is set: deletes the existing policy.
5. Builds the policy settings array from the definitions in `BitLocker-Policy.json`, injects the discovered `templateId`, and POSTs to `/beta/deviceManagement/configurationPolicies`.
6. Optionally assigns the policy to a group or virtual target.

## Important Notes

> [!IMPORTANT]
> **Silent encryption** (`AllowWarningForOtherDiskEncryption = 0`) requires the device to be **Entra ID joined** (not just registered) and `AllowStandardUserEncryption = 1` (already set in this policy). Entra ID **registered** (BYOD) devices will fail silent encryption — scope this policy to corporate-owned devices.

> [!IMPORTANT]
> **Recovery key backup** — encryption will not start on a device until the recovery key is successfully escrowed in Entra ID. If network connectivity is unavailable during enrollment, BitLocker provisioning is deferred until the backup succeeds.

> [!WARNING]
> **Non-TPM devices** — `ConfigureNonTPMStartupKeyUsage = 0` blocks BitLocker on any device without a TPM. Those devices will appear in Intune with an error. Virtual machines without a virtual TPM will also fail.

> [!NOTE]
> **Policy location** — this policy lands under **Endpoint Security > Disk Encryption**, not Device Configuration, because `templateFamily: endpointSecurityDiskEncryption` is set.

## Post-Deployment Verification

1. Navigate to **Endpoint Security > Disk Encryption** in the Intune admin center.
2. Locate **OnCloud - Bitlocker**.
3. Assign the policy to the target device group if not done during deployment.
4. On a target device, run `manage-bde -status` to verify BitLocker status, or check **Devices > [device name] > Recovery keys** to confirm the key has been escrowed in Entra ID.

## Troubleshooting

| Symptom | Cause | Resolution |
|---|---|---|
| Policy already exists — skipping | A policy with the same name exists | Run with `-Force` |
| Devices report encryption error | Device is not Entra ID joined, or has no TPM | Verify join type and TPM presence; scope policy to compliant devices |
| Recovery key not appearing in Entra ID | Network unavailable during enrollment | Device will retry at next Intune sync; check `Devices > [device name] > Recovery keys` |
| `-ShowTemplateSettings` returns no results | Template not found in tenant | Ensure the tenant has an Intune licence and the Endpoint Security workload is enabled |
| `templateId` is blank in JSON | Expected — the script populates it at runtime | Do not set `templateId` manually in the JSON file |

## API Reference

| Operation | Endpoint |
|---|---|
| Discover BitLocker template | `GET /beta/deviceManagement/configurationPolicyTemplates?$filter=templateFamily eq 'endpointSecurityDiskEncryption'` |
| Create policy | `POST /beta/deviceManagement/configurationPolicies` |
| Delete policy | `DELETE /beta/deviceManagement/configurationPolicies/{id}` |
| Assign policy | `POST /beta/deviceManagement/configurationPolicies/{id}/assign` |
| List template settings | `GET /beta/deviceManagement/configurationPolicyTemplates/{id}/settingTemplates?$expand=settingDefinitions` |
