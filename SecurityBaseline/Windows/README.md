# Windows MDM Security Baseline

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Graph API](https://img.shields.io/badge/Microsoft%20Graph-beta-0078d4?logo=microsoft)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078d4?logo=windows)
![Settings](https://img.shields.io/badge/~290%20settings-configured-green)

Deploys the customized **OnCloud - Windows Security Baseline** policy to Microsoft Intune under **Endpoint Security > Security baselines** using the modern `configurationPolicies` API. The latest available baseline template is selected dynamically. Organizational exclusions eliminate overlap with dedicated policies (BitLocker, Defender, Firewall, ASR).

## Organizational Customizations

### UAC Override

| Setting Name | Baseline Default | Customized Value | Rationale |
| :--- | :--- | :--- | :--- |
| **Behavior of the elevation prompt for standard users** | Automatically deny elevation requests | **Prompt for credentials on the secure desktop** | Standard users can elevate for authorized tasks by entering administrator credentials on a secure screen, preventing workflow blocks. |

### Excluded Categories

> [!NOTE]
> The following baseline categories are set to **Not Configured** because they are owned by dedicated Intune policies. This prevents conflicts and enrollment errors.

| Excluded Category | Managed By |
| :--- | :--- |
| BitLocker & Device Encryption | `BitLocker/Deploy-BitLockerPolicy.ps1` |
| Attack Surface Reduction (ASR) Rules | Dedicated ASR endpoint security policy |
| Network Protection | Deployed alongside the ASR policy |
| Windows Hello for Business | Tenant-wide identity / enrollment configurations |
| Microsoft Defender Antivirus | `SecurityBaseline/MDE/Deploy-MDESecurityBaseline.ps1` |
| Windows Firewall | `SecurityBaseline/MDE/Deploy-MDESecurityBaseline.ps1` |

## Prerequisites

| Requirement | Detail |
| :--- | :--- |
| PowerShell | 5.1 or later |
| Module | `Microsoft.Graph.Authentication` — auto-installed if missing |
| Graph permission | `DeviceManagementConfiguration.ReadWrite.All` |
| Role | Intune Administrator or Global Administrator |
| Execution Policy | `Set-ExecutionPolicy RemoteSigned -Scope Process` |

## Files

| File | Purpose |
| :--- | :--- |
| `Deploy-WindowsSecurityBaseline.ps1` | Deployment script |
| `baseline-settings.json` | Auto-generated audit file of all compiled settings (created on each run) |
| `SecurityBaseline_Deployment_Log.txt` | Auto-generated timestamped run log |

## Usage

To run the deployment, open PowerShell and execute the script:

```powershell
# Create the policy (skips if it already exists)
.\Deploy-WindowsSecurityBaseline.ps1

# Delete and recreate if a policy with the same name already exists
.\Deploy-WindowsSecurityBaseline.ps1 -Force
```

After creation, assign the profile in the Intune admin center:
**Endpoint Security > Security baselines > MDM Security Baseline > OnCloud - Windows Security Baseline > Properties > Assignments**

## How It Works

The script automates the baseline definition using a multi-step Graph API loop:

1. **Authentication**: Connects to MS Graph via `Connect-MgGraph`.
2. **Template Discovery**: Queries `/beta/deviceManagement/configurationPolicyTemplates` and selects the newest Windows MDM Baseline.
3. **Settings Parsing**: Reads template settings and parses the packed choice settings. Excludes all settings matching the customisation filters and applies UAC overrides.
4. **Dependency Resolution**: During policy creation, the Graph API might return a `BadRequest` if certain child settings are missing. The script reads the missing setting IDs from the API error message, queries their definitions dynamically, injects them into the configuration settings tree, and retries until completion.

## Settings Breakdown

> [!NOTE]
> Values are decoded from the Settings Catalog ID suffix: `_0`/`_1`/`_2` correspond to the enumeration order in Microsoft CSP documentation. For boolean-style settings, `_1` = Enabled/Yes and `_0` = Disabled/No unless otherwise noted.

<details>
<summary>Expand — all ~290 configured settings by category</summary>

### Lock Screen

| Setting | Value | Description |
| :--- | :--- | :--- |
| Prevent enabling lock screen camera | **Enabled** | Disables the camera shortcut on the Windows lock screen |
| Prevent lock screen slideshow | **Enabled** | Disables lock screen slideshow — no media exposure before authentication |

### MSS Security Guide

| Setting | Value | Description |
| :--- | :--- | :--- |
| Apply UAC restrictions to local accounts on network logon | **Enabled** | Strips elevated tokens from local accounts authenticating over the network (mitigates pass-the-hash) |
| Configure SMBv1 client driver | **Enabled (disable/block)** | SMBv1 client is disabled — prevents EternalBlue-class attacks |
| Configure SMBv1 server | **Disabled** | SMBv1 server component is turned off |
| Enable Structured Exception Handling Overwrite Protection (SEHOP) | **Enabled** | SEHOP active — mitigates SEH-based memory exploitation |

### MSS Legacy (TCP/IP Hardening)

| Setting | Value | Description |
| :--- | :--- | :--- |
| IPv6 source routing protection level | **Highest protection (1)** | Drop all IPv6 packets with source routing options |
| IP source routing protection level | **Highest protection (1)** | Drop all IPv4 packets with source routing options |
| Allow ICMP redirects to override OSPF-generated routes | **Disabled** | Prevents route poisoning via ICMP redirect messages |
| Allow computer to ignore NetBIOS name release requests except from WINS servers | **Enabled** | Protects against NetBIOS denial-of-service attacks |

### DNS Client

| Setting | Value | Description |
| :--- | :--- | :--- |
| Turn off multicast name resolution (LLMNR) | **Enabled** | LLMNR disabled — prevents LLMNR/NBT-NS poisoning attacks |

### Network Connections

| Setting | Value | Description |
| :--- | :--- | :--- |
| Prohibit use of Internet Connection Sharing | **Enabled** | Prevents users from sharing the device's internet connection |
| Prohibit connection to non-domain networks when connected to domain-authenticated network | **Enabled** | Prevents dual-home network connections that could bridge corporate and untrusted networks |
| Hardened UNC Paths | **Enabled** | `\\*\SYSVOL` and `\\*\NETLOGON` require mutual authentication and integrity (`RequireMutualAuthentication=1,RequireIntegrity=1`) |

### Printers

| Setting | Value | Description |
| :--- | :--- | :--- |
| Configure Redirection Guard policy | **Enabled** | Prevents printer driver redirection attacks |
| Configure RPC connection policy | **Enabled** | Enforces authenticated RPC for printer connections |
| Configure RPC listener policy | **Enabled** | Controls the RPC listener used by the print spooler |
| Configure RPC over TCP port | **Enabled** | RPC printer connections use a fixed TCP port |
| Restrict driver installation to administrators | **Enabled** | Only administrators can install printer drivers |
| Configure Copy Files policy | **Enabled** | Restricts files that can be copied during printer driver installation |

### Notifications

| Setting | Value | Description |
| :--- | :--- | :--- |
| No lock screen toast notification (User) | **Enabled** | Toast notifications are not shown on the lock screen |

### Audit Settings

| Setting | Value | Description |
| :--- | :--- | :--- |
| Include command line in process creation events | **Enabled** | Full command-line arguments captured in Event ID 4688 — critical for incident response |

### Credentials Delegation

| Setting | Value | Description |
| :--- | :--- | :--- |
| Remote host allows delegation of non-exportable credentials | **Enabled** | Enables Remote Credential Guard — credentials are never sent to remote hosts in exportable form |

### Device Installation

| Setting | Value | Description |
| :--- | :--- | :--- |
| Prevent installation of matching device setup classes | **Enabled** | Blocks device classes defined in the policy (e.g., specific hardware categories) |

### System

| Setting | Value | Description |
| :--- | :--- | :--- |
| Boot Start Driver Initialization | **Good, unknown, bad but critical (1)** | Only allows boot-start drivers classified as Good, Unknown, or Bad-but-Critical — blocks known-bad drivers |

### Group Policy

| Setting | Value | Description |
| :--- | :--- | :--- |
| Configure registry policy processing | **Enabled** | Enforces registry group policy re-processing even when settings have not changed |

### Connectivity

| Setting | Value | Description |
| :--- | :--- | :--- |
| Turn off downloading of print drivers over HTTP | **Enabled** | Blocks automatic download of printer drivers from the internet |
| Turn off Internet download for Web publishing and online ordering wizards | **Enabled** | Prevents web-based wizard connections that could leak information |

### Local Security Authority (LSA)

| Setting | Value | Description |
| :--- | :--- | :--- |
| Allow Custom SSPs and APs to be loaded into LSASS | **Disabled** | Prevents third-party Security Support Providers from injecting into LSASS |

### Power Management

| Setting | Value | Description |
| :--- | :--- | :--- |
| Allow standby states (S1–S3) when sleeping on battery | **Disabled** | Eliminates low-power states that do not fully protect memory (DMA attacks) |
| Allow standby states (S1–S3) when sleeping plugged in | **Disabled** | Same protection when plugged in |
| Require password when computer wakes on battery | **Enabled** | Password/PIN required after wake from sleep on battery |
| Require password when computer wakes plugged in | **Enabled** | Password/PIN required after wake from sleep when plugged in |

### Remote Assistance

| Setting | Value | Description |
| :--- | :--- | :--- |
| Solicited remote assistance | **Disabled** | Users cannot request remote assistance sessions — prevents social engineering attacks |

### Remote Procedure Call (RPC)

| Setting | Value | Description |
| :--- | :--- | :--- |
| Restrict unauthenticated RPC clients | **Authenticated (1)** | All RPC clients must authenticate before connecting |

### App Runtime

| Setting | Value | Description |
| :--- | :--- | :--- |
| Allow Microsoft accounts to be optional | **Enabled** | Microsoft accounts are optional for Windows Store apps — reduces data exposure |

### AutoPlay / AutoRun

| Setting | Value | Description |
| :--- | :--- | :--- |
| Disallow AutoPlay for non-volume devices | **Enabled** | AutoPlay disabled for cameras, phones, and other non-volume devices |
| Set default AutoRun behavior | **Do not execute any AutoRun commands (1)** | AutoRun.inf commands are ignored |
| Turn off AutoPlay | **Enabled (all drives)** | AutoPlay completely disabled for all drives |

### Credentials UI

| Setting | Value | Description |
| :--- | :--- | :--- |
| Enumerate administrator accounts on elevation | **Disabled** | Administrator account names are not listed on the UAC elevation prompt |

### Event Log Service

| Setting | Value | Description |
| :--- | :--- | :--- |
| Maximum Application log size | **Enabled** | Application event log maximum size enforced |
| Maximum Security log size | **Enabled** | Security event log maximum size enforced |
| Maximum System log size | **Enabled** | System event log maximum size enforced |

### Windows SmartScreen

| Setting | Value | Description |
| :--- | :--- | :--- |
| Enable SmartScreen (Windows Explorer / ADMX) | **Enabled** | SmartScreen reputation check active for downloaded files in Explorer |
| Turn off Data Execution Prevention for Explorer | **Disabled** | DEP remains active for Windows Explorer — prevents code execution from data pages |

### UAC (User Account Control)

> The full UAC settings set is deployed from the template. Only the one **customized** value is shown; all others are at Microsoft’s baseline default.

| Setting | Baseline Default | Customized Value | Reason |
| :--- | :--- | :--- | :--- |
| Behavior of the elevation prompt for standard users | Automatically deny elevation requests | **Prompt for credentials on secure desktop (3)** | Allows authorized standard users to elevate by entering admin credentials, preventing workflow blocks while maintaining security |

</details>
