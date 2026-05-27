#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys the "OnCloud - macOS Compliance" policy to Intune via Microsoft Graph API.

.DESCRIPTION
    Creates a macOS device compliance policy using:
    POST /beta/deviceManagement/deviceCompliancePolicies

    Policy enforces:
      - FileVault encryption required
      - System Integrity Protection (SIP) required
      - Firewall required + stealth mode enabled
      - Gatekeeper: App Store and identified developers
      - Password required; simple passwords blocked
      - Minimum password length: 12 characters (alphanumeric)
      - Screen lock after 15 minutes of inactivity
      - Previous 5 passwords blocked from reuse
      - Minimum OS version: macOS 14.0 Sonoma
      - Microsoft Defender for Endpoint maximum risk score: High
      - Mark device noncompliant: immediately (0-hour grace period)
      - Email notification to user: immediately

    API endpoint : POST /beta/deviceManagement/deviceCompliancePolicies
    Policy type  : #microsoft.graph.macOSCompliancePolicy

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
    Minimum required macOS version string. Default: 14.0 (macOS 14 Sonoma).
    Use 15.0 for macOS 15 Sequoia minimum.

.PARAMETER SkipMdeRiskScore
    Omit the Microsoft Defender for Endpoint risk score check. Use this if MDE is not
    integrated with Intune, otherwise all devices will be marked noncompliant.

.EXAMPLE
    # Create only (no assignment)
    .\Deploy-macOSCompliancePolicy.ps1

.EXAMPLE
    # Create and assign to all devices
    .\Deploy-macOSCompliancePolicy.ps1 -AssignToAllDevices

.EXAMPLE
    # Create and assign to a group
    .\Deploy-macOSCompliancePolicy.ps1 -AssignToGroupId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.EXAMPLE
    # Overwrite existing policy and assign to all users
    .\Deploy-macOSCompliancePolicy.ps1 -Force -AssignToAllUsers

.EXAMPLE
    # Create without MDE risk score check (if MDE not connected)
    .\Deploy-macOSCompliancePolicy.ps1 -SkipMdeRiskScore -AssignToAllDevices

.NOTES
    Required Graph permissions : DeviceManagementConfiguration.ReadWrite.All
    Supported OS               : macOS 12 Monterey and later (policy targets macOS 14+)
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
    [ValidatePattern('^\d+\.\d+(\.\d+)?$')]
    [string]$OsMinimumVersion = '14.0',

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

    $templateBody = @{
        displayName     = $templateName
        brandingOptions = 'includeCompanyLogo,includeCompanyName,includeContactInformation'
    } | ConvertTo-Json -Depth 3

    $template = Invoke-MgGraphRequest -Method POST -Uri $uri `
        -Body $templateBody -ContentType 'application/json' -OutputType PSObject

    $msgBody = @{
        locale          = 'en-us'
        subject         = 'Action required: your device is not compliant'
        messageTemplate = "Your device does not meet your organization's security compliance requirements.`n`nCommon causes:`n  - Missing security updates`n  - FileVault or encryption not enabled`n  - Antivirus or Defender not running`n`nPlease contact your IT administrator for assistance or review the Company Portal app for details."
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

$policyName = 'OnCloud - macOS Compliance'

Write-Host "`n=== Intune macOS Compliance Policy Deployment ===" -ForegroundColor Cyan

# Modules
Write-Host "`n[1] Checking required modules..." -ForegroundColor Cyan
Install-RequiredModule -ModuleName 'Microsoft.Graph.Authentication'

# Connect
Write-Host "`n[2] Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-ToGraph

# Notification template
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
#   https://learn.microsoft.com/graph/api/resources/intune-deviceconfig-macoscompliancepolicy
#
# gatekeeperAllowedAppSource values:
#   notConfigured                    = Not configured
#   macAppStore                      = Mac App Store only
#   macAppStoreAndIdentifiedDevelopers = App Store + identified developers (recommended)
#   anywhere                         = No restriction (not recommended)
#
# deviceThreatProtectionRequiredSecurityLevel values:
#   secured = Clear (most strict)  |  low / medium / high  |  notSet = no requirement
#
# advancedThreatProtectionRequiredSecurityLevel: MDATP-specific risk level for Mac
#

$policyBody = @{
    '@odata.type' = '#microsoft.graph.macOSCompliancePolicy'
    displayName   = $policyName
    description   = @"
macOS device compliance policy. Enforces:
  - FileVault encryption required
  - System Integrity Protection (SIP) required
  - Firewall + stealth mode required
  - Gatekeeper: App Store and identified developers
  - Password: min 12 chars, alphanumeric, no simple passwords
  - Screen lock after 15 min inactivity; last 5 passwords blocked
  - Minimum macOS $OsMinimumVersion
  - MDE maximum machine risk score: High
  - Mark noncompliant and send email immediately
"@

    # ── Encryption ────────────────────────────────────────────────────────────
    storageRequireEncryption = $true          # FileVault

    # ── System Integrity & Gatekeeper ─────────────────────────────────────────
    systemIntegrityProtectionEnabled = $true
    gatekeeperAllowedAppSource       = 'macAppStoreAndIdentifiedDevelopers'

    # ── Firewall ──────────────────────────────────────────────────────────────
    firewallEnabled         = $true
    firewallEnableStealthMode = $true         # No response to probing/port-scan requests
    firewallBlockAllIncoming = $false         # Blocking all incoming is too restrictive for most environments

    # ── Device Properties ─────────────────────────────────────────────────────
    osMinimumVersion = $OsMinimumVersion

    # ── Password ──────────────────────────────────────────────────────────────
    passwordRequired                     = $true
    passwordBlockSimple                  = $true
    passwordMinimumLength                = 12
    passwordRequiredType                 = 'alphanumeric'
    passwordMinutesOfInactivityBeforeLock = 15
    passwordPreviousPasswordBlockCount   = 5

    # ── Microsoft Defender for Endpoint - Risk Score ──────────────────────────
    # Requires MDE ↔ Intune connector. Use -SkipMdeRiskScore if not configured.
    deviceThreatProtectionEnabled                  = (-not $SkipMdeRiskScore)
    deviceThreatProtectionRequiredSecurityLevel    = if ($SkipMdeRiskScore) { 'unavailable' } else { 'high' }
    advancedThreatProtectionRequiredSecurityLevel  = if ($SkipMdeRiskScore) { 'unavailable' } else { 'high' }

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

if ($PSCmdlet.ShouldProcess($policyName, 'Create macOS Compliance Policy')) {
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
Write-Host '  FileVault encryption                     REQUIRED'
Write-Host '  System Integrity Protection (SIP)        REQUIRED'
Write-Host '  Gatekeeper                               APP STORE + IDENTIFIED DEVELOPERS'
Write-Host '  Firewall                                 REQUIRED'
Write-Host '  Firewall stealth mode                    ENABLED'
Write-Host '  Firewall block all incoming              NOT CONFIGURED'
Write-Host "  Minimum macOS version                    $OsMinimumVersion"
Write-Host '  Password required                        YES'
Write-Host '  Simple passwords blocked                 YES'
Write-Host '  Minimum password length                  12 CHARACTERS'
Write-Host '  Password type                            ALPHANUMERIC'
Write-Host '  Screen lock inactivity timeout           15 MINUTES'
Write-Host '  Previous passwords blocked               5'
if ($SkipMdeRiskScore) {
Write-Host '  MDE maximum risk score                   SKIPPED (-SkipMdeRiskScore)'                    -ForegroundColor Yellow
} else {
Write-Host '  MDE maximum risk score                   HIGH'
}
Write-Host '  Mark noncompliant                        IMMEDIATELY'
Write-Host '  Email notification on noncompliance      IMMEDIATELY'
Write-Host ''

#endregion
