# MAM App Protection Policies

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Graph API](https://img.shields.io/badge/Microsoft%20Graph-beta-0078d4?logo=microsoft)
![Platform](https://img.shields.io/badge/Platform-iOS%20%C2%B7%20Android-lightgrey)

Deploys hardened Mobile Application Management (MAM) app protection policies for iOS and Android to Microsoft Intune via the Microsoft Graph API.

## Policy Settings

Both an iOS and Android policy are created targeting all core Microsoft apps.

| Setting | Value | Notes |
| :--- | :--- | :--- |
| **Targeting** | | |
| App group | All core Microsoft apps | |
| Target all device types | Yes | Covers corporate and personal (BYOD) devices |
| **Data Protection** | | |
| Inbound data transfer | From all apps | Data can be received from any app |
| Outbound data transfer | Managed apps only | Data cannot leave to unmanaged apps |
| Clipboard sharing | Managed apps with paste-in | |
| Save As | Blocked | |
| Allowed save locations | OneDrive for Business, SharePoint | |
| Allowed data ingestion | OneDrive for Business, SharePoint, Camera, Photo Library | |
| App data encryption | Enabled | |
| Contact sync | Blocked | |
| Print | Blocked | |
| Links open in | Microsoft Edge (managed browser) | |
| Data backup | Blocked | |
| Screen capture (Android only) | Blocked | |
| **Access Requirements** | | |
| PIN required | Yes | |
| Simple PIN blocked | Yes | |
| Minimum PIN length | **6** | |
| Biometric / fingerprint | Allowed | |
| Skip app PIN if device PIN set | Yes | |
| Device compliance required | Yes | |
| **Offline Behaviour** | | |
| Offline access check | **30 days** (720 hours) | Re-authentication required after 30 days offline |
| Offline wipe | **30 days** | Managed data wiped after 30 days without Intune check-in |

## Prerequisites

| Requirement | Detail |
| :--- | :--- |
| PowerShell | 5.1 or later |
| PowerShell module | `Microsoft.Graph.Authentication` — must be installed and connected |
| Graph permissions | `DeviceManagementApps.ReadWrite.All` |
| Intune licence | Active Intune licence on the tenant |

## Files

| File | Purpose |
| :--- | :--- |
| `New-MAMPolicies.ps1` | Deployment script — creates iOS and Android MAM policies |
| `MAM_Deployment_Log.txt` | Auto-generated run log (created in the same folder as the script) |

## Usage

```powershell
# Create both policies (skips if policies with the same name already exist)
.\New-MAMPolicies.ps1

# Delete existing policies and recreate them
.\New-MAMPolicies.ps1 -Force
```

> [!NOTE]
> The script prompts for interactive Graph authentication on first run. After policies are created, assign them to users or groups in the Intune portal:
> **Apps > App protection policies > select policy > Properties > Assignments**

## How It Works

1. Connects to Microsoft Graph with `DeviceManagementApps.ReadWrite.All`.
2. For each platform (iOS, Android):
   - Checks whether a policy named `MAM - {Platform} - Core Microsoft Apps` already exists.
   - If it exists and `-Force` is **not** specified: logs a warning and skips.
   - If it exists and `-Force` **is** specified: deletes the existing policy and recreates it.
   - POSTs the policy body to the appropriate endpoint.
3. Writes a timestamped log entry for every action to both the console and `MAM_Deployment_Log.txt`.

## API Endpoints

| Platform | Endpoint |
| :--- | :--- |
| iOS | `POST /beta/deviceAppManagement/iosManagedAppProtections` |
| Android | `POST /beta/deviceAppManagement/androidManagedAppProtections` |
| Check existing (iOS) | `GET /beta/deviceAppManagement/iosManagedAppProtections?$filter=displayName eq '...'` |
| Check existing (Android) | `GET /beta/deviceAppManagement/androidManagedAppProtections?$filter=displayName eq '...'` |
| Delete | `DELETE /beta/deviceAppManagement/{uri}/{id}` |

## Known Limitations

| Item | Detail |
| :--- | :--- |
| No automatic assignment | Policies must be assigned to user groups manually in the Intune portal after creation. There is no `-AssignToAllUsers` flag in this script. |
| `managedBrowser` deprecated | The `managedBrowser` property is deprecated but still accepted by the API. Future API versions may drop it. |
| `antispywareRequired` N/A | Not applicable to MAM — this is a device compliance concept. |
| `targetToAllDeviceTypes` | Applies to Android device type targeting (corporate vs personal). Sent on both payloads; iOS ignores it silently. |

## Troubleshooting

| Symptom | Resolution |
| :--- | :--- |
| Policy already exists — skipping | Run with `-Force` to delete and recreate both policies |
| Authentication fails | Ensure your account has the Intune Administrator role or `DeviceManagementApps.ReadWrite.All` consented in Entra ID |
| Policy created but not applying | The policy must be assigned to users or groups in the Intune portal. Creation via the API does not auto-assign |
| Android applies but iOS does not (or vice versa) | Each platform is a separate policy. Check `MAM_Deployment_Log.txt` for per-platform success/failure and verify assignments separately |
