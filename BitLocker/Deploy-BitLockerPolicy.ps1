#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys the "OnCloud - Bitlocker" policy to Intune as an Endpoint Security > Disk Encryption policy.

.DESCRIPTION
    Creates the policy using the modern Settings Catalog engine (POST /configurationPolicies).
    The Endpoint Security Disk Encryption template ID is discovered dynamically from your tenant
    so this script works regardless of tenant-specific template GUIDs.

    Policy enforces:
      - Silent encryption          : No user prompts (AllowWarningForOtherDiskEncryption = 0)
      - TPM-only startup           : Only TPM allowed at boot (no PIN, no USB key)
      - Non-TPM devices blocked    : BitLocker will NOT enable on devices without a TPM
      - XTS-AES 256-bit encryption : OS drive and fixed drives
      - Entra ID backup required   : Recovery key + password MUST be backed up before encryption starts
      - Recovery password rotation : Rotated after use on Entra ID / Hybrid Entra ID joined devices
      - Fixed drive encryption     : All fixed data drives encrypted

    API endpoint : POST /beta/deviceManagement/configurationPolicies
    Template node: Endpoint Security > Disk Encryption > BitLocker (Windows)

.PARAMETER AssignToGroupId
    Entra ID group Object ID to assign the policy to after creation.

.PARAMETER AssignToAllDevices
    Assign the policy to the built-in "All Devices" group after creation.

.PARAMETER Force
    Delete and recreate the policy if one with the same name already exists.

.PARAMETER ShowTemplateSettings
    Queries the tenant for all available settings in the BitLocker Endpoint Security template
    and writes them to the console. Useful for verifying settingDefinitionIds without creating
    a policy. No policy is created when this switch is used.

.EXAMPLE
    # Create only (no assignment)
    .\Deploy-BitLockerPolicy.ps1

.EXAMPLE
    # Create and assign to a group
    .\Deploy-BitLockerPolicy.ps1 -AssignToGroupId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.EXAMPLE
    # Create and assign to all devices
    .\Deploy-BitLockerPolicy.ps1 -AssignToAllDevices

.EXAMPLE
    # Inspect all available settings for the BitLocker template in this tenant
    .\Deploy-BitLockerPolicy.ps1 -ShowTemplateSettings

.NOTES
    Required Graph permissions : DeviceManagementConfiguration.ReadWrite.All
                                 DeviceManagementEndpointSecurity.ReadWrite.All
    Supported OS               : Windows 10 1703+ / Windows 11
    TPM requirement            : TPM 1.2 or TPM 2.0
    Device join types          : Entra ID joined, Hybrid Entra ID joined

    IMPORTANT: AllowWarningForOtherDiskEncryption = 0 (silent) requires the device to be
    Entra ID joined AND AllowStandardUserEncryption = 1 for standard user accounts.
    Devices not meeting these conditions will report an encryption error in Intune.

    IMPORTANT: The settingDefinitionIds for ADMX-backed settings (startup auth, recovery options,
    encryption method) follow the Settings Catalog naming convention derived from the ADMX data
    element names. Run -ShowTemplateSettings to validate them against your tenant's catalog.
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'NoAssignment')]
param (
    [Parameter(Mandatory = $true, ParameterSetName = 'GroupAssignment')]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$AssignToGroupId,

    [Parameter(Mandatory = $true, ParameterSetName = 'AllDevices')]
    [switch]$AssignToAllDevices,

    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$ShowTemplateSettings
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
    $requiredScopes = @(
        'DeviceManagementConfiguration.ReadWrite.All',
        'DeviceManagementEndpointSecurity.ReadWrite.All'
    )
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

function Get-BitLockerEndpointSecurityTemplate {
    <#
        Queries GET /beta/deviceManagement/configurationPolicyTemplates to find the
        Endpoint Security > Disk Encryption (BitLocker) template for Windows.
        Returns the template object with the highest displayVersion.
    #>
    $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicyTemplates" +
           "?`$filter=templateFamily eq 'endpointSecurityDiskEncryption'" +
           "&`$select=id,displayName,displayVersion,platforms,technologies,templateFamily"

    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject

    $template = $response.value |
        Where-Object { $_.platforms -eq 'windows10' -and $_.displayName -notlike '*FileVault*' } |
        Sort-Object -Property displayVersion -Descending |
        Select-Object -First 1

    if (-not $template) {
        throw "Could not find an Endpoint Security Disk Encryption (BitLocker) template for Windows 10 in this tenant. Verify that Intune is licensed and provisioned."
    }

    Write-Host "  Template : $($template.displayName) (v$($template.displayVersion))" -ForegroundColor Green
    Write-Host "  TemplateId: $($template.id)" -ForegroundColor DarkGray
    return $template
}

function Show-TemplateSettings {
    param ([string]$TemplateId)

    Write-Host "`nFetching all settings for template $TemplateId ..." -ForegroundColor Cyan
    $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicyTemplates/$TemplateId/settingTemplates?`$expand=settingDefinitions"
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject

    $response.value | ForEach-Object {
        $sd = $_.settingDefinitions | Select-Object -First 1
        [PSCustomObject]@{
            SettingDefinitionId = $sd.id
            DisplayName         = $sd.displayName
            ValueType           = $sd.settingValueType
        }
    } | Sort-Object SettingDefinitionId | Format-Table -AutoSize
}

function Get-ExistingPolicy {
    param ([string]$DisplayName)
    $filter   = "name eq '$($DisplayName -replace "'", "''")'"
    $uri      = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$filter=$filter"
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    return $response.value | Where-Object { $_.name -eq $DisplayName } | Select-Object -First 1
}

function Remove-EndpointSecurityPolicy {
    param ([string]$PolicyId)
    Invoke-MgGraphRequest -Method DELETE `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$PolicyId"
}

function New-EndpointSecurityPolicy {
    param ([hashtable]$Body)
    $json = $Body | ConvertTo-Json -Depth 20
    return Invoke-MgGraphRequest -Method POST `
        -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies' `
        -Body $json `
        -ContentType 'application/json' `
        -OutputType PSObject
}

function Add-PolicyAssignment {
    param (
        [string]$PolicyId,
        [string]$GroupId,
        [bool]$AllDevices
    )
    $target = if ($AllDevices) {
        @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' }
    }
    else {
        @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $GroupId }
    }

    $body = @{ assignments = @(@{ target = $target }) } | ConvertTo-Json -Depth 5

    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$PolicyId/assign" `
        -Body $body `
        -ContentType 'application/json'
}

#endregion

#region Settings Definition
#
# settingDefinitionId reference:
#   BitLocker CSP   : https://learn.microsoft.com/windows/client-management/mdm/bitlocker-csp
#   Policy CSP ADMX : https://learn.microsoft.com/windows/client-management/mdm/policy-csp-bitlocker
#
# ID convention for ADMX-backed settings in the Settings Catalog:
#   Parent : device_vendor_msft_bitlocker_{settingName}
#   Child  : {parentId}_{admxDataElementName}       (lowercase, underscores)
#   Value  : {childId}_{numericValue|true|false}
#
# Encryption method values  : 3=AES-CBC-128 | 4=AES-CBC-256 | 6=XTS-AES-128 | 7=XTS-AES-256
# Startup auth values       : 0=Do Not Allow | 1=Require | 2=Allow (optional)
# Recovery password values  : 0=Do Not Allow | 1=Require | 2=Allow
# AD Backup scope values    : 1=Password + Key Package | 2=Password Only
# Password rotation values  : 0=Disabled | 1=Entra ID joined | 2=Entra ID + Hybrid joined
#

$policySettings = @(

    # ── BitLocker CSP - simple integer choice settings ──────────────────────────────
    @{
        '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
        settingInstance = @{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = 'device_vendor_msft_bitlocker_requiredeviceencryption'
            choiceSettingValue  = @{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                value         = 'device_vendor_msft_bitlocker_requiredeviceencryption_1'
                children      = @()
            }
        }
    },
    @{
        '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
        settingInstance = @{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = 'device_vendor_msft_bitlocker_allowwarningforotherdiskencryption'
            choiceSettingValue  = @{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                value         = 'device_vendor_msft_bitlocker_allowwarningforotherdiskencryption_0'
                children      = @()
            }
        }
    },
    @{
        '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
        settingInstance = @{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = 'device_vendor_msft_bitlocker_allowstandarduserencryption'
            choiceSettingValue  = @{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                value         = 'device_vendor_msft_bitlocker_allowstandarduserencryption_1'
                children      = @()
            }
        }
    },
    @{
        '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
        settingInstance = @{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = 'device_vendor_msft_bitlocker_configurerecoverypasswordrotation'
            choiceSettingValue  = @{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                value         = 'device_vendor_msft_bitlocker_configurerecoverypasswordrotation_2'
                children      = @()
            }
        }
    },

    # ── Policy CSP - Encryption Method (XTS-AES 256 for OS + Fixed, AES-CBC 256 for Removable) ──
    @{
        '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
        settingInstance = @{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = 'device_vendor_msft_bitlocker_encryptionmethodbydrivetype'
            choiceSettingValue  = @{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                value         = 'device_vendor_msft_bitlocker_encryptionmethodbydrivetype_1'
                children      = @(
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsosdropdown_name'
                        choiceSettingValue  = @{
                            value    = 'device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsosdropdown_name_7'
                            children = @()
                        }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsfdvdropdown_name'
                        choiceSettingValue  = @{
                            value    = 'device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsfdvdropdown_name_7'
                            children = @()
                        }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsrdvdropdown_name'
                        choiceSettingValue  = @{
                            value    = 'device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsrdvdropdown_name_4'
                            children = @()
                        }
                    }
                )
            }
        }
    },

    # ── Policy CSP - OS Drive Startup Authentication ────────────────────────────────
    # TPM required (1). All other factors blocked (0). Non-TPM blocked (false).
    # This combination ensures no user interaction at boot = supports silent encryption.
    @{
        '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
        settingInstance = @{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication'
            choiceSettingValue  = @{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                value         = 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_1'
                children      = @(
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configurenontpmstartupkeyusage_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configurenontpmstartupkeyusage_name_0'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmusagedropdown_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmusagedropdown_name_1'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmstartupkeyusagedropdown_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmstartupkeyusagedropdown_name_0'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configurepinusagedropdown_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configurepinusagedropdown_name_0'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmpinkeyusagedropdown_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmpinkeyusagedropdown_name_0'; children = @() }
                    }
                )
            }
        }
    },

    # ── Policy CSP - OS Drive Recovery Options ──────────────────────────────────────
    # osrequireactivedirectorybackup_name = true is the safety net:
    # BitLocker will NOT enable until the backup to Entra ID succeeds.
    @{
        '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
        settingInstance = @{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions'
            choiceSettingValue  = @{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                value         = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_1'
                children      = @(
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osallowdra_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osallowdra_name_0'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrecoverypasswordusagedropdown_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrecoverypasswordusagedropdown_name_2'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrecoverykeyusagedropdown_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrecoverykeyusagedropdown_name_2'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_oshiderecoverypage_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_oshiderecoverypage_name_1'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osactivedirectorybackup_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osactivedirectorybackup_name_1'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osactivedirectorybackupdropdown_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osactivedirectorybackupdropdown_name_1'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrequireactivedirectorybackup_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrequireactivedirectorybackup_name_1'; children = @() }
                    }
                )
            }
        }
    },

    # ── Policy CSP - Fixed Drives ───────────────────────────────────────────────────
    @{
        '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
        settingInstance = @{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = 'device_vendor_msft_bitlocker_fixeddrivesrequireencryption'
            choiceSettingValue  = @{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                value         = 'device_vendor_msft_bitlocker_fixeddrivesrequireencryption_1'
                children      = @()
            }
        }
    },
    @{
        '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
        settingInstance = @{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions'
            choiceSettingValue  = @{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                value         = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions_1'
                children      = @(
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions_fdvallowdra_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions_fdvallowdra_name_0'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions_fdvrecoverypasswordusagedropdown_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions_fdvrecoverypasswordusagedropdown_name_2'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions_fdvrecoverykeyusagedropdown_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions_fdvrecoverykeyusagedropdown_name_2'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions_fdvhiderecoverypage_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions_fdvhiderecoverypage_name_1'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions_fdvactivedirectorybackup_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions_fdvactivedirectorybackup_name_1'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions_fdvactivedirectorybackupdropdown_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions_fdvactivedirectorybackupdropdown_name_1'; children = @() }
                    },
                    @{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions_fdvrequireactivedirectorybackup_name'
                        choiceSettingValue  = @{ value = 'device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions_fdvrequireactivedirectorybackup_name_1'; children = @() }
                    }
                )
            }
        }
    }
)

#endregion

#region Main Execution

Write-Host "`n=== Intune Endpoint Security - BitLocker Policy Deployment ===" -ForegroundColor Cyan

# Modules
Write-Host "`n[1] Checking required modules..." -ForegroundColor Cyan
Install-RequiredModule -ModuleName 'Microsoft.Graph.Authentication'

# Connect
Write-Host "`n[2] Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-ToGraph

# ShowTemplateSettings mode - discover template and list settings, then exit
if ($ShowTemplateSettings) {
    Write-Host "`n[3] Discovering BitLocker Endpoint Security template..." -ForegroundColor Cyan
    $template = Get-BitLockerEndpointSecurityTemplate
    Show-TemplateSettings -TemplateId $template.id
    exit 0
}

# Duplicate check
$policyName = 'OnCloud - Bitlocker'
Write-Host "`n[4] Checking for existing policy '$policyName'..." -ForegroundColor Cyan
$existing = Get-ExistingPolicy -DisplayName $policyName

if ($existing) {
    if ($Force) {
        if ($PSCmdlet.ShouldProcess("'$policyName' (ID: $($existing.id))", 'Delete existing policy')) {
            Write-Host "  Deleting existing policy (Force)..." -ForegroundColor Yellow
            Remove-EndpointSecurityPolicy -PolicyId $existing.id
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

# Build policy body
$policyBody = @{
    name              = $policyName
    description       = @'
Endpoint Security > Disk Encryption (BitLocker). Best practice settings:
  - Silent encryption (AllowWarningForOtherDiskEncryption=0, AllowStandardUserEncryption=1)
  - TPM-only startup; non-TPM devices blocked
  - XTS-AES 256-bit (OS + fixed drives), AES-CBC 256-bit (removable)
  - Recovery key + password backed up to Entra ID BEFORE encryption enables
  - Recovery password rotated after use (Entra ID + Hybrid joined)
  - Fixed drive encryption required
'@
    platforms    = 'windows10'
    technologies = 'mdm'
    settings     = $policySettings
}

# Create
Write-Host "`n[5] Creating policy in Intune..." -ForegroundColor Cyan
$created = $null

if ($PSCmdlet.ShouldProcess($policyName, 'Create Endpoint Security Disk Encryption policy')) {
    $created = New-EndpointSecurityPolicy -Body $policyBody
    Write-Host "  Created : $($created.name)" -ForegroundColor Green
    Write-Host "  ID      : $($created.id)"   -ForegroundColor Green
}

# Assign
if ($created -and ($AssignToAllDevices -or $PSBoundParameters.ContainsKey('AssignToGroupId'))) {
    $target = if ($AssignToAllDevices) { 'All Devices' } else { "Group $AssignToGroupId" }
    if ($PSCmdlet.ShouldProcess($policyName, "Assign to $target")) {
        Write-Host "`n[6] Assigning policy to $target..." -ForegroundColor Cyan
        Add-PolicyAssignment -PolicyId $created.id -GroupId $AssignToGroupId -AllDevices $AssignToAllDevices.IsPresent
        Write-Host "  Assigned to: $target" -ForegroundColor Green
    }
}
elseif ($created) {
    Write-Host "`n  Policy NOT assigned. Use -AssignToGroupId or -AssignToAllDevices to assign." -ForegroundColor Yellow
}

Write-Host "`n=== Complete ===" -ForegroundColor Green
Write-Host ''
Write-Host '  Setting                               Value'                                             -ForegroundColor Cyan
Write-Host '  -------                               -----'                                             -ForegroundColor Cyan
Write-Host '  Policy type                           Endpoint Security > Disk Encryption'
Write-Host '  Silent encryption                     ENABLED'
Write-Host '  Startup authentication                TPM ONLY'
Write-Host '  Non-TPM devices                       BLOCKED'
Write-Host '  Startup PIN / USB key                 NOT ALLOWED'
Write-Host '  Encryption algorithm (OS + Fixed)     XTS-AES 256-bit'
Write-Host '  Encryption algorithm (Removable)      AES-CBC 256-bit'
Write-Host '  Recovery password + key package       Backed up to Entra ID'
Write-Host '  Backup required before encryption     YES'
Write-Host '  Recovery password rotation            ENABLED (Entra ID + Hybrid joined)'
Write-Host '  Fixed drive encryption                REQUIRED'
Write-Host ''

#endregion

