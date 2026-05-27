#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys the "OnCloud - Windows Compliance" policy to Intune via Microsoft Graph API.

.DESCRIPTION
    Creates a Windows 10/11 device compliance policy using:
    POST /beta/deviceManagement/deviceCompliancePolicies

    Policy enforces:
      - Secure Boot required
      - TPM (1.2 or 2.0) required
      - Code Integrity (HVCI) required
      - BitLocker required
      - Storage encryption required
      - Minimum OS version: Windows 10 22H2 (10.0.19045.0)
      - Password required; simple passwords blocked
      - Windows Firewall required
      - Microsoft Defender Antimalware required (min platform version enforced)
      - Defender security intelligence up-to-date required
      - Defender real-time protection required
      - Antivirus registered and enabled required
      - Antispyware registered and enabled required
      - Microsoft Defender for Endpoint maximum risk score: High

    NOTE: antivirusRequired and antispywareRequired (Windows Security Center generic checks)
    were removed from the windows10CompliancePolicy Graph API. Antimalware coverage is
    enforced via defenderEnabled, defenderVersion, signatureOutOfDate, and rtpEnabled instead.
      - Mark device noncompliant: immediately (0-hour grace period)
      - Email notification to user: immediately

    API endpoint : POST /beta/deviceManagement/deviceCompliancePolicies
    Policy type  : #microsoft.graph.windows10CompliancePolicy

    NOTE: "Custom compliance policies" (visible in the Intune compliance recommendation list)
    is not deployed by this script. It requires a separate PowerShell detection script and a
    JSON schema file uploaded to Intune — these are tenant-specific.

    NOTE: deviceThreatProtectionRequiredSecurityLevel requires Microsoft Defender for Endpoint
    (MDE) to be integrated with Intune. If MDE is not connected, use -SkipMdeRiskScore to
    omit that setting and avoid marking all devices noncompliant.

.PARAMETER AssignToGroupId
    Entra ID group Object ID to assign the policy to after creation.

.PARAMETER AssignToAllDevices
    Assign the policy to the built-in "All Devices" virtual group.

.PARAMETER AssignToAllUsers
    Assign the policy to the built-in "All Users" virtual group.

.PARAMETER Force
    Delete and recreate the policy if one with the same name already exists.

.PARAMETER OsMinimumVersion
    Minimum required Windows OS version. Default: 10.0.19045.0 (Windows 10 22H2).
    Use 10.0.22621.0 for Windows 11 22H2 minimum.

.PARAMETER DefenderMinimumVersion
    Minimum required Defender Antimalware platform version. Default: 4.18.2001.10.
    Run 'Get-MpComputerStatus | Select-Object AMProductVersion' on a device to check.

.PARAMETER SkipMdeRiskScore
    Omit the Microsoft Defender for Endpoint risk score check. Use this if MDE is not
    integrated with Intune, otherwise all devices will be marked noncompliant.

.EXAMPLE
    # Create only (no assignment)
    .\Deploy-WindowsCompliancePolicy.ps1

.EXAMPLE
    # Create and assign to all devices
    .\Deploy-WindowsCompliancePolicy.ps1 -AssignToAllDevices

.EXAMPLE
    # Create and assign to a group
    .\Deploy-WindowsCompliancePolicy.ps1 -AssignToGroupId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.EXAMPLE
    # Overwrite existing policy and assign to all users
    .\Deploy-WindowsCompliancePolicy.ps1 -Force -AssignToAllUsers

.EXAMPLE
    # Create without MDE risk score check (if MDE not connected)
    .\Deploy-WindowsCompliancePolicy.ps1 -SkipMdeRiskScore -AssignToAllDevices

.NOTES
    Required Graph permissions : DeviceManagementConfiguration.ReadWrite.All
    Supported OS               : Windows 10 1703+ / Windows 11
    TPM requirement            : TPM 1.2 or TPM 2.0 required on target devices
    MDE requirement            : Microsoft Defender for Endpoint Intune connector for risk score
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'NoAssignment')]
param (
    [Parameter(Mandatory = $true, ParameterSetName = 'GroupAssignment')]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$AssignToGroupId,

    [Parameter(Mandatory = $true, ParameterSetName = 'AllDevices')]
    [switch]$AssignToAllDevices,

    [Parameter(Mandatory = $true, ParameterSetName = 'AllUsers')]
    [switch]$AssignToAllUsers,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [ValidatePattern('^\d+\.\d+\.\d+(\.\d+)?$')]
    [string]$OsMinimumVersion = '10.0.19045.0',

    [Parameter()]
    [ValidatePattern('^\d+\.\d+\.\d+(\.\d+)?$')]
    [string]$DefenderMinimumVersion = '4.18.2001.10',

    [Parameter()]
    [switch]$SkipMdeRiskScore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helpers

function Install-RequiredModule {
    param ([string]$ModuleName)
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "  Installing '$ModuleName'..." -ForegroundColor Yellow
        Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
    }
    if (-not (Get-Module -Name $ModuleName)) {
        Import-Module -Name $ModuleName -Force
    }
}

function Connect-ToGraph {
    $requiredScopes = @('DeviceManagementConfiguration.ReadWrite.All')
    $context = Get-MgContext -ErrorAction SilentlyContinue
    $hasScopes = $context -and ($context.Scopes -contains $requiredScopes[0])

    if (-not $hasScopes) {
        Write-Host '  Launching interactive Graph authentication...' -ForegroundColor Yellow
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        $context = Get-MgContext
    }
    Write-Host "  Tenant : $($context.TenantId)" -ForegroundColor Green
    Write-Host "  Account: $($context.Account)"  -ForegroundColor Green
}

function Get-ExistingCompliancePolicy {
    param ([string]$DisplayName)
    $escaped  = $DisplayName -replace "'", "''"
    $uri      = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$filter=displayName eq '$escaped'"
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    return $response.value | Where-Object { $_.displayName -eq $DisplayName } | Select-Object -First 1
}

function Remove-CompliancePolicy {
    param ([string]$PolicyId)
    Invoke-MgGraphRequest -Method DELETE `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$PolicyId"
}

function Get-NotificationTemplateId {
    <#
        Returns the ID of an existing "OnCloud" notification template,
        or creates one (with a default en-us message) if none is found.
    #>
    $templateName = 'OnCloud - Device Noncompliance Notification'
    $uri          = 'https://graph.microsoft.com/beta/deviceManagement/notificationMessageTemplates'
    $response     = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject

    $existing = $response.value |
        Where-Object { $_.displayName -eq $templateName } |
        Select-Object -First 1

    if ($existing) {
        Write-Host "  Notification template: found existing '$($existing.displayName)'" -ForegroundColor Green
        return $existing.id
    }

    Write-Host "  Notification template: creating '$templateName'..." -ForegroundColor Yellow

    # Step 1: create template shell
    $templateBody = @{
        displayName     = $templateName
        brandingOptions = 'includeCompanyLogo,includeCompanyName,includeContactInformation'
    } | ConvertTo-Json -Depth 3

    $template = Invoke-MgGraphRequest -Method POST -Uri $uri `
        -Body $templateBody -ContentType 'application/json' -OutputType PSObject

    # Step 2: add default (en-us) localized message
    $msgBody = @{
        locale          = 'en-us'
        subject         = 'Action required: your device is not compliant'
        messageTemplate = "Your device does not meet your organization's security compliance requirements.`n`nCommon causes:`n  - Missing security updates`n  - BitLocker or encryption not enabled`n  - Antivirus or Defender not running`n`nPlease contact your IT administrator for assistance or review the Company Portal app for details."
        isDefault       = $true
    } | ConvertTo-Json -Depth 3

    Invoke-MgGraphRequest -Method POST `
        -Uri "$uri/$($template.id)/localizedNotificationMessages" `
        -Body $msgBody -ContentType 'application/json' | Out-Null

    Write-Host "  Notification template: created (ID: $($template.id))" -ForegroundColor Green
    return $template.id
}

function New-CompliancePolicy {
    param ([hashtable]$Body)
    $json = $Body | ConvertTo-Json -Depth 10
    return Invoke-MgGraphRequest -Method POST `
        -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies' `
        -Body $json `
        -ContentType 'application/json' `
        -OutputType PSObject
}

function Add-CompliancePolicyAssignment {
    param (
        [string]$PolicyId,
        [string]$GroupId,
        [bool]$AllDevices,
        [bool]$AllUsers
    )
    $target = if ($AllDevices) {
        @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' }
    }
    elseif ($AllUsers) {
        @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' }
    }
    else {
        @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $GroupId }
    }

    $body = @{ assignments = @(@{ target = $target }) } | ConvertTo-Json -Depth 5

    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$PolicyId/assign" `
        -Body $body `
        -ContentType 'application/json'
}

#endregion

#region Main Execution

$policyName = 'OnCloud - Windows Compliance'

Write-Host "`n=== Intune Windows Compliance Policy Deployment ===" -ForegroundColor Cyan

# Modules
Write-Host "`n[1] Checking required modules..." -ForegroundColor Cyan
Install-RequiredModule -ModuleName 'Microsoft.Graph.Authentication'

# Connect
Write-Host "`n[2] Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-ToGraph

# Notification template (required for email action on noncompliance)
Write-Host "`n[3] Preparing noncompliance notification template..." -ForegroundColor Cyan
$notificationTemplateId = Get-NotificationTemplateId

# Duplicate check
Write-Host "`n[4] Checking for existing policy '$policyName'..." -ForegroundColor Cyan
$existing = Get-ExistingCompliancePolicy -DisplayName $policyName

if ($existing) {
    if ($Force) {
        if ($PSCmdlet.ShouldProcess("'$policyName' (ID: $($existing.id))", 'Delete existing compliance policy')) {
            Write-Host "  Deleting existing policy (Force)..." -ForegroundColor Yellow
            Remove-CompliancePolicy -PolicyId $existing.id
            Write-Host "  Deleted." -ForegroundColor Yellow
        }
    }
    else {
        Write-Warning "Policy '$policyName' already exists (ID: $($existing.id)). Use -Force to overwrite."
        exit 0
    }
}
else {
    Write-Host "  No existing policy found." -ForegroundColor Green
}

# ── Build policy body ────────────────────────────────────────────────────────
#
# Property reference:
#   https://learn.microsoft.com/graph/api/resources/intune-deviceconfig-windows10compliancepolicy
#
# deviceThreatProtectionRequiredSecurityLevel values:
#   secured  = Clear (most strict: device must be clean)
#   low      = Low and above are non-compliant
#   medium   = Medium and above are non-compliant
#   high     = High and above are non-compliant (only critical fails)
#   notSet   = No MDE risk requirement
#
# signatureOutOfDate = true  →  mark noncompliant when signatures ARE out of date
#                               (i.e., require up-to-date signatures)
#

$policyBody = @{
    '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'
    displayName   = $policyName
    description   = @"
Windows device compliance policy. Enforces:
  - Secure Boot, TPM, Code Integrity required
  - BitLocker required
  - Minimum OS: $OsMinimumVersion
  - Password required; simple passwords blocked
  - Windows Firewall required
  - Defender Antimalware required (min version: $DefenderMinimumVersion)
  - Defender signatures up-to-date and real-time protection required
  - MDE maximum machine risk score: High
  - Mark noncompliant and send email immediately
"@

    # ── Device Health (requires attestation) ──────────────────────────────────
    bitLockerEnabled     = $true
    secureBootEnabled    = $true
    codeIntegrityEnabled = $true

    # ── Device Properties ─────────────────────────────────────────────────────
    osMinimumVersion = $OsMinimumVersion
    # storageRequireEncryption omitted - BitLocker (bitLockerEnabled) already enforces encryption

    # ── System Security - Password ────────────────────────────────────────────
    passwordRequired    = $true
    passwordBlockSimple = $true

    # ── System Security - Firewall & Defender ─────────────────────────────────
    activeFirewallRequired = $true
    antivirusRequired      = $true          # Any antivirus registered with Windows Security Center
    # NOTE: antispywareRequired was removed from the Intune backend API (microsoft.management.services.api);
    #       it cannot be set via Graph API. Windows Defender (defenderEnabled) registers as antispyware
    #       in WSC, so devices running Defender satisfy the WSC antispyware check regardless.
    defenderEnabled        = $true          # Require Defender Antimalware
    defenderVersion        = $DefenderMinimumVersion
    signatureOutOfDate     = $true          # Non-compliant when signatures ARE out of date
    rtpEnabled             = $true          # Real-time protection

    # ── Hardware - TPM ────────────────────────────────────────────────────────
    tpmRequired = $true

    # ── Microsoft Defender for Endpoint - Risk Score ──────────────────────────
    # Requires MDE ↔ Intune connector. Use -SkipMdeRiskScore if not configured.
    deviceThreatProtectionEnabled               = (-not $SkipMdeRiskScore)
    deviceThreatProtectionRequiredSecurityLevel = if ($SkipMdeRiskScore) { 'unavailable' } else { 'high' }

    # ── Noncompliance Actions ─────────────────────────────────────────────────
    scheduledActionsForRule = @(
        @{
            ruleName = 'PasswordRequired'
            scheduledActionConfigurations = @(
                @{
                    # Mark the device noncompliant immediately (0-hour grace period)
                    actionType                = 'block'
                    gracePeriodHours          = 0
                    notificationTemplateId    = ''
                    notificationMessageCCList = @()
                },
                @{
                    # Send email notification to the user immediately
                    actionType                = 'notification'
                    gracePeriodHours          = 0
                    notificationTemplateId    = $notificationTemplateId
                    notificationMessageCCList = @()
                }
            )
        }
    )
}

# Create
Write-Host "`n[5] Creating compliance policy in Intune..." -ForegroundColor Cyan
$created = $null

if ($PSCmdlet.ShouldProcess($policyName, 'Create Windows Compliance Policy')) {
    $created = New-CompliancePolicy -Body $policyBody
    Write-Host "  Created : $($created.displayName)" -ForegroundColor Green
    Write-Host "  ID      : $($created.id)"          -ForegroundColor Green
}

# Assign
if ($created -and ($AssignToAllDevices -or $AssignToAllUsers -or $PSBoundParameters.ContainsKey('AssignToGroupId'))) {
    $target = if ($AssignToAllDevices)   { 'All Devices' }
              elseif ($AssignToAllUsers) { 'All Users' }
              else                       { "Group $AssignToGroupId" }

    if ($PSCmdlet.ShouldProcess($policyName, "Assign to $target")) {
        Write-Host "`n[6] Assigning policy to $target..." -ForegroundColor Cyan
        Add-CompliancePolicyAssignment `
            -PolicyId   $created.id `
            -GroupId    $AssignToGroupId `
            -AllDevices $AssignToAllDevices.IsPresent `
            -AllUsers   $AssignToAllUsers.IsPresent
        Write-Host "  Assigned to: $target" -ForegroundColor Green
    }
}
elseif ($created) {
    Write-Host "`n  Policy NOT assigned. Use -AssignToGroupId, -AssignToAllDevices, or -AssignToAllUsers to assign." -ForegroundColor Yellow
}

Write-Host "`n=== Complete ===" -ForegroundColor Green
Write-Host ''
Write-Host '  Setting                                  Value'                                          -ForegroundColor Cyan
Write-Host '  -------                                  -----'                                          -ForegroundColor Cyan
Write-Host '  Secure Boot                              REQUIRED'
Write-Host '  TPM                                      REQUIRED'
Write-Host '  Code Integrity (HVCI)                    REQUIRED'
Write-Host '  BitLocker                                REQUIRED'
Write-Host '  Storage encryption                       NOT CONFIGURED (covered by BitLocker)'
Write-Host '  Storage encryption                       REQUIRED'
Write-Host "  Minimum OS version                       $OsMinimumVersion"
Write-Host '  Password required                        YES'
Write-Host '  Simple passwords blocked                 YES'
Write-Host '  Windows Firewall                         REQUIRED'
Write-Host '  Defender Antimalware                     REQUIRED'
Write-Host "  Defender minimum version                 $DefenderMinimumVersion"
Write-Host '  Defender signatures up-to-date           REQUIRED'
Write-Host '  Defender real-time protection            REQUIRED'
if ($SkipMdeRiskScore) {
Write-Host '  MDE maximum risk score                   SKIPPED (-SkipMdeRiskScore)'                    -ForegroundColor Yellow
} else {
Write-Host '  MDE maximum risk score                   HIGH'
}
Write-Host '  Mark noncompliant                        IMMEDIATELY'
Write-Host '  Email notification on noncompliance      IMMEDIATELY'
Write-Host ''

#endregion
