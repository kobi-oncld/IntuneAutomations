# Windows Compliance Policy

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Graph API](https://img.shields.io/badge/Microsoft%20Graph-beta-0078d4?logo=microsoft)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078d4?logo=windows)

Deploys a best-practice Windows device compliance policy to Microsoft Intune via the Microsoft Graph API.

## Policy Settings

| Setting | Value | Notes |
| :--- | :--- | :--- |
| Secure Boot | **Required** | |
| Trusted Platform Module (TPM) | **Required** | TPM 1.2 or 2.0 |
| Code Integrity (HVCI) | **Required** | |
| BitLocker | **Required** | |
| Storage encryption | Not configured | Covered by BitLocker above |
| Minimum OS version | **10.0.19045.0** | Windows 10 22H2 (parameter) |
| Password required | **Yes** | |
| Simple passwords blocked | **Yes** | |
| Windows Firewall | **Required** | |
| Antivirus (WSC registered) | **Required** | |
| Antispyware (WSC registered) | Not configurable via API | Covered by `defenderEnabled`; Defender registers as antispyware in WSC |
| Microsoft Defender Antimalware | **Required** | |
| Defender minimum platform version | **4.18.2001.10** | Parameter |
| Defender security intelligence up-to-date | **Required** | |
| Defender real-time protection | **Required** | |
| MDE maximum machine risk score | **High** | Requires MDE ↔ Intune connector |
| Mark device noncompliant | **Immediately** | 0-hour grace period |
| Email notification to user | **Immediately** | Auto-creates notification template |

## Prerequisites

| Requirement | Detail |
| :--- | :--- |
| PowerShell | 5.1 or later (PowerShell 7+ recommended) |
| PowerShell module | `Microsoft.Graph.Authentication` — auto-installed if missing |
| Graph permissions | `DeviceManagementConfiguration.ReadWrite.All` |
| Device OS | Windows 10 1703+ or Windows 11 |
| TPM | TPM 1.2 or TPM 2.0 required on target devices |
| MDE (optional) | Microsoft Defender for Endpoint Intune connector for risk score check |

## Files

| File | Purpose |
| :--- | :--- |
| `Deploy-WindowsCompliancePolicy.ps1` | Main deployment script |

## Usage

```powershell
# Create the policy (no assignment)
.\Deploy-WindowsCompliancePolicy.ps1

# Create and assign to all devices
.\Deploy-WindowsCompliancePolicy.ps1 -AssignToAllDevices

# Create and assign to all users
.\Deploy-WindowsCompliancePolicy.ps1 -AssignToAllUsers

# Create and assign to a specific Entra ID group
.\Deploy-WindowsCompliancePolicy.ps1 -AssignToGroupId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Overwrite if a policy with the same name already exists
.\Deploy-WindowsCompliancePolicy.ps1 -Force

# Overwrite and assign to all devices
.\Deploy-WindowsCompliancePolicy.ps1 -Force -AssignToAllDevices

# Require a newer minimum OS version (Windows 11 22H2)
.\Deploy-WindowsCompliancePolicy.ps1 -OsMinimumVersion "10.0.22621.0" -AssignToAllDevices

# Create without MDE risk score check (if MDE not connected to Intune)
.\Deploy-WindowsCompliancePolicy.ps1 -SkipMdeRiskScore -AssignToAllDevices
```

> [!TIP]
> Use `-SkipMdeRiskScore` if MDE is not yet integrated with Intune. Once onboarded, recreate the policy without that flag.

On first run you will be prompted for interactive Graph authentication in a browser window. Subsequent runs in the same PowerShell session reuse the existing connection.

## How It Works

1. Installs `Microsoft.Graph.Authentication` if not present.
2. Connects to Microsoft Graph with `DeviceManagementConfiguration.ReadWrite.All`.
3. Checks for an existing notification message template named `OnCloud - Device Noncompliance Notification`. Creates one with a default English message if not found.
4. Checks whether a policy named `OnCloud - Windows Compliance` already exists.
   - If it does and `-Force` is not specified, the script exits without making changes.
   - If `-Force` is specified, the existing policy is deleted and recreated.
5. Posts the policy body to `POST /beta/deviceManagement/deviceCompliancePolicies`.
6. Optionally assigns the policy to a group, all devices, or all users.

## Noncompliance Actions

Two actions fire immediately (0-hour grace period) when a device falls out of compliance:

| Action | Behaviour |
| :--- | :--- |
| `block` | Marks the device as noncompliant in Intune. Conditional Access policies targeting compliant devices will block access. |
| `notification` | Sends an email to the device's primary user via the `OnCloud - Device Noncompliance Notification` template. |

The notification template is created automatically on first run if it does not already exist in the tenant.

## API Property Reference

| Intune UI label | Graph API property | Value |
| :--- | :--- | :--- |
| Secure Boot | `secureBootEnabled` | `true` |
| TPM | `tpmRequired` | `true` |
| Code Integrity | `codeIntegrityEnabled` | `true` |
| BitLocker | `bitLockerEnabled` | `true` |
| Minimum OS version | `osMinimumVersion` | `"10.0.19045.0"` |
| Password required | `passwordRequired` | `true` |
| Block simple passwords | `passwordBlockSimple` | `true` |
| Firewall | `activeFirewallRequired` | `true` |
| Antivirus (WSC) | `antivirusRequired` | `true` |
| Defender Antimalware | `defenderEnabled` | `true` |
| Defender minimum version | `defenderVersion` | `"4.18.2001.10"` |
| Signatures up-to-date | `signatureOutOfDate` | `true` (non-compliant when signatures ARE out of date) |
| Real-time protection | `rtpEnabled` | `true` |
| MDE risk score | `deviceThreatProtectionRequiredSecurityLevel` | `"high"` |

> [!NOTE]
> `antispywareRequired` was removed from the Intune backend API. Windows Defender registers itself as antispyware in Windows Security Center, so any device with Defender running and `defenderEnabled` compliant will also satisfy the WSC antispyware check.

## Troubleshooting

| Symptom | Resolution |
| :--- | :--- |
| Policy already exists warning | Run with `-Force` to delete and recreate it |
| 400 Bad Request — property does not exist | The `windows10CompliancePolicy` API type evolves independently from the portal. Remove the rejected property and check the [Graph API changelog](https://learn.microsoft.com/graph/changelog) |
| Devices marking noncompliant due to MDE risk score | MDE is not integrated with Intune, or devices don’t have a risk score yet. Use `-SkipMdeRiskScore` while onboarding MDE |
| Antispyware shows “Not configured” in portal | Expected — `antispywareRequired` was removed from the API backend. Devices running Defender satisfy the WSC antispyware check |
| Email notifications not being sent | Ensure `OnCloud - Device Noncompliance Notification` exists in `Tenant admin > Notifications`. Users need an active Exchange Online licence |
| Graph authentication fails | Ensure your account has the Intune Administrator or Global Administrator role, or `DeviceManagementConfiguration.ReadWrite.All` consented |
