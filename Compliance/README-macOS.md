# macOS Compliance Policy

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Graph API](https://img.shields.io/badge/Microsoft%20Graph-beta-0078d4?logo=microsoft)
![Platform](https://img.shields.io/badge/Platform-macOS%2014%2B-lightgrey?logo=apple)

Deploys a best-practice macOS device compliance policy to Microsoft Intune via the Microsoft Graph API.

## Policy Settings

| Setting | Value | Notes |
| :--- | :--- | :--- |
| FileVault encryption | **Required** | |
| System Integrity Protection (SIP) | **Required** | |
| Gatekeeper | **App Store + identified developers** | |
| Firewall | **Required** | |
| Firewall stealth mode | **Enabled** | No response to port scans or probing |
| Firewall block all incoming | Not configured | Too restrictive for most environments |
| Minimum macOS version | **14.0** (Sonoma) | Parameter |
| Password required | **Yes** | |
| Simple passwords blocked | **Yes** | |
| Minimum password length | **12 characters** | |
| Password type | **Alphanumeric** | Letters + numbers required |
| Screen lock inactivity timeout | **15 minutes** | |
| Previous passwords blocked | **5** | |
| MDE maximum machine risk score | **High** | Requires MDE ↔ Intune connector |
| Mark device noncompliant | **Immediately** | 0-hour grace period |
| Email notification to user | **Immediately** | Auto-creates notification template |

## Prerequisites

| Requirement | Detail |
| :--- | :--- |
| PowerShell | 5.1 or later (PowerShell 7+ recommended) |
| PowerShell module | `Microsoft.Graph.Authentication` — auto-installed if missing |
| Graph permissions | `DeviceManagementConfiguration.ReadWrite.All` |
| Device OS | macOS 12 Monterey or later (policy targets macOS 14+ by default) |
| MDE (optional) | Microsoft Defender for Endpoint Intune connector for risk score check |

## Files

| File | Purpose |
| :--- | :--- |
| `Deploy-macOSCompliancePolicy.ps1` | Main deployment script |

## Usage

```powershell
# Create the policy (no assignment)
.\Deploy-macOSCompliancePolicy.ps1

# Create and assign to all devices
.\Deploy-macOSCompliancePolicy.ps1 -AssignToAllDevices

# Create and assign to all users
.\Deploy-macOSCompliancePolicy.ps1 -AssignToAllUsers

# Create and assign to a specific Entra ID group
.\Deploy-macOSCompliancePolicy.ps1 -AssignToGroupId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Overwrite if a policy with the same name already exists
.\Deploy-macOSCompliancePolicy.ps1 -Force

# Overwrite and assign to all devices
.\Deploy-macOSCompliancePolicy.ps1 -Force -AssignToAllDevices

# Require macOS 15 Sequoia as minimum
.\Deploy-macOSCompliancePolicy.ps1 -OsMinimumVersion "15.0" -AssignToAllDevices

# Create without MDE risk score check (if MDE not connected)
.\Deploy-macOSCompliancePolicy.ps1 -SkipMdeRiskScore -AssignToAllDevices
```

> [!TIP]
> Use `-SkipMdeRiskScore` if MDE is not yet integrated with Intune. Once onboarded, recreate the policy without that flag.

On first run you will be prompted for interactive Graph authentication in a browser window. Subsequent runs in the same PowerShell session reuse the existing connection.

## How It Works

1. Installs `Microsoft.Graph.Authentication` if not present.
2. Connects to Microsoft Graph with `DeviceManagementConfiguration.ReadWrite.All`.
3. Checks for an existing notification message template named `OnCloud - Device Noncompliance Notification`. Creates one with a default English message if not found. If the Windows compliance script has already been run, the existing template is reused.
4. Checks whether a policy named `OnCloud - macOS Compliance` already exists.
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

## API Property Reference

| Intune UI label | Graph API property | Value |
| :--- | :--- | :--- |
| FileVault encryption | `storageRequireEncryption` | `true` |
| System Integrity Protection | `systemIntegrityProtectionEnabled` | `true` |
| Gatekeeper | `gatekeeperAllowedAppSource` | `macAppStoreAndIdentifiedDevelopers` |
| Firewall | `firewallEnabled` | `true` |
| Stealth mode | `firewallEnableStealthMode` | `true` |
| Block all incoming | `firewallBlockAllIncoming` | `false` |
| Minimum OS version | `osMinimumVersion` | `"14.0"` |
| Password required | `passwordRequired` | `true` |
| Block simple passwords | `passwordBlockSimple` | `true` |
| Minimum password length | `passwordMinimumLength` | `12` |
| Password type | `passwordRequiredType` | `alphanumeric` |
| Inactivity before lock | `passwordMinutesOfInactivityBeforeLock` | `15` |
| Previous passwords blocked | `passwordPreviousPasswordBlockCount` | `5` |
| MDE risk score (generic) | `deviceThreatProtectionRequiredSecurityLevel` | `high` |
| MDE risk score (MDATP) | `advancedThreatProtectionRequiredSecurityLevel` | `high` |

### Gatekeeper Values

| API value | Meaning |
| :--- | :--- |
| `notConfigured` | Not configured |
| `macAppStore` | Mac App Store only |
| `macAppStoreAndIdentifiedDevelopers` | App Store + identified developers *(used by this policy)* |
| `anywhere` | Anywhere — no restriction (not recommended) |

## Troubleshooting

| Symptom | Resolution |
| :--- | :--- |
| Policy already exists warning | Run with `-Force` to delete and recreate it |
| Devices noncompliant due to MDE risk score | MDE is not integrated with Intune, or Mac devices don’t have a risk score yet. Use `-SkipMdeRiskScore` while onboarding MDE |
| FileVault shows as noncompliant when enabled | Ensure the device was enrolled in Intune before FileVault was turned on. Manually enabling FileVault outside Intune may not be detected until next device check-in |
| Email notifications not being sent | Ensure `OnCloud - Device Noncompliance Notification` exists in `Tenant admin > Notifications`. Users need an active Exchange Online licence |
| Graph authentication fails | Ensure your account has the Intune Administrator or Global Administrator role, or `DeviceManagementConfiguration.ReadWrite.All` consented |
