#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys the "OnCloud - ASR Rules" policy to Intune as an Endpoint Security
    > Attack Surface Reduction policy.

.DESCRIPTION
    Creates the policy using the modern Settings Catalog engine
    (POST /beta/deviceManagement/configurationPolicies) with the
    endpointSecurityAttackSurfaceReduction template family.

    The script queries the tenant's own template catalog to build the settings,
    so it automatically adapts to new rule additions without code changes.

    All ASR rules and Network Protection are set to Block by default.
    Use -AuditMode to configure everything as Audit for initial assessment.

    Controlled Folder Access is intentionally left at Not Configured — it
    requires a separate allow-list and is best managed in a dedicated policy.

.PARAMETER AssignToGroupId
    Entra ID group Object ID to assign the policy to after creation.

.PARAMETER AssignToAllDevices
    Assign the policy to the built-in "All Devices" group after creation.

.PARAMETER Force
    Delete and recreate the policy if one with the same name already exists.

.PARAMETER AuditMode
    Configure all ASR rules and Network Protection in Audit mode instead of Block.
    Useful for assessing impact before enforcing Block across production devices.
    The policy will be named "OnCloud - ASR Rules (Audit)".

.EXAMPLE
    # Create in Block mode (no assignment)
    .\Deploy-ASRPolicy.ps1

    # Create in Block mode and assign to all devices
    .\Deploy-ASRPolicy.ps1 -AssignToAllDevices

    # Create in Audit mode for initial assessment
    .\Deploy-ASRPolicy.ps1 -AuditMode -AssignToAllDevices

    # Recreate in Block mode after audit assessment
    .\Deploy-ASRPolicy.ps1 -Force -AssignToAllDevices

    # Assign to a specific group
    .\Deploy-ASRPolicy.ps1 -AssignToGroupId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.NOTES
    Required Graph permission : DeviceManagementConfiguration.ReadWrite.All
    Intune location           : Endpoint Security > Attack Surface Reduction
    Supported OS              : Windows 10 1709+ / Windows 11

    Recommended rollout:
      1. Deploy in Audit mode first (-AuditMode -AssignToAllDevices)
      2. Monitor in MDE Advanced Hunting / Event Viewer (Event ID 1121/1122)
      3. After 2–4 weeks with no blocking issues, switch to Block mode:
         .\Deploy-ASRPolicy.ps1 -Force -AssignToAllDevices
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
    [switch]$AuditMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Policy naming ─────────────────────────────────────────────────────────────
$policyDisplayName = if ($AuditMode) { 'OnCloud - ASR Rules (Audit)' } else { 'OnCloud - ASR Rules' }
$modeLabel         = if ($AuditMode) { 'Audit' } else { 'Block' }
$targetSuffix      = if ($AuditMode) { '_audit' } else { '_block' }

# ── Logging ───────────────────────────────────────────────────────────────────
$LogFile = Join-Path $PSScriptRoot 'ASR_Deployment_Log.txt'

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')][string]$Level = 'INFO'
    )
    $ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$ts] [$Level] $Message"
    $entry | Out-File -FilePath $LogFile -Append -Encoding utf8
    $color = switch ($Level) {
        'SUCCESS' { 'Green'  }
        'ERROR'   { 'Red'    }
        'WARNING' { 'Yellow' }
        default   { 'Gray'   }
    }
    Write-Host $entry -ForegroundColor $color
}

Write-Log "=== ASR Policy Deployment ($modeLabel mode) ===" 'INFO'

# ── Module ────────────────────────────────────────────────────────────────────
Write-Log 'Checking for Microsoft.Graph.Authentication module...' 'INFO'
if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
    Write-Log 'Module not found. Installing Microsoft.Graph.Authentication...' 'INFO'
    try {
        Install-Module -Name 'Microsoft.Graph.Authentication' -Scope CurrentUser -Force -ErrorAction Stop
        Write-Log 'Module installed successfully.' 'SUCCESS'
    } catch {
        Write-Log "Failed to install module: $($_.Exception.Message)" 'ERROR'
        exit 1
    }
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# ── Authentication ────────────────────────────────────────────────────────────
Write-Log 'Connecting to Microsoft Graph...' 'INFO'
try {
    Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All' -NoWelcome -ErrorAction Stop
    $ctx = Get-MgContext
    Write-Log "Connected. Tenant: $($ctx.TenantId)  Account: $($ctx.Account)" 'SUCCESS'
} catch {
    Write-Log "Authentication failed: $($_.Exception.Message)" 'ERROR'
    exit 1
}

# ── Helpers ───────────────────────────────────────────────────────────────────
function Get-AllGraphPages {
    param([string]$Uri)
    $all  = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop
        if ($page.value) { $page.value | ForEach-Object { $all.Add($_) } }
        $next = $null
        if ($page.PSObject.Properties['@odata.nextLink']) {
            $next = $page.'@odata.nextLink'
        }
    }
    return $all
}

function Get-GraphErrorBody {
    param($ErrorRecord)
    if (-not $ErrorRecord) { return '' }
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $msg = $ErrorRecord.ErrorDetails.Message
        if ($msg -match '(?s)(\{"error":.*)') { return $Matches[1] }
    }
    if ($ErrorRecord.Exception -and $ErrorRecord.Exception.Message) {
        $msg = $ErrorRecord.Exception.Message
        if ($msg -match '(?s)(\{"error":.*)') { return $Matches[1] }
    }
    return ''
}

# ── Template Discovery ────────────────────────────────────────────────────────
Write-Log 'Searching for Attack Surface Reduction template...' 'INFO'
$template = $null
try {
    $allTemplates = Get-AllGraphPages '/beta/deviceManagement/configurationPolicyTemplates'

    $allTemplates |
        Where-Object {
            $_.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' -and
            $_.displayName -match 'Attack Surface Reduction Rules' -and
            $_.displayName -notmatch 'ConfigMgr'
        } |
        Sort-Object { [int]($_.version) } |
        ForEach-Object {
            Write-Log "  Found: '$($_.displayName)' v$($_.version) lifecycle=$($_.lifecycleState) (ID: $($_.id))" 'INFO'
        }

    $candidates = $allTemplates | Where-Object {
        $_.templateFamily -eq 'endpointSecurityAttackSurfaceReduction' -and
        $_.displayName -match 'Attack Surface Reduction Rules' -and
        $_.displayName -notmatch 'ConfigMgr' -and
        ($_.PSObject.Properties['isDeprecated'] -eq $null -or $_.isDeprecated -ne $true) -and
        ($_.PSObject.Properties['lifecycleState'] -eq $null -or $_.lifecycleState -ne 'deprecated')
    }

    # Prefer lifecycleState = active; fall back to highest version
    $template = $candidates |
        Where-Object { $_.lifecycleState -eq 'active' } |
        Sort-Object { [int]($_.version) } -Descending |
        Select-Object -First 1

    if (-not $template) {
        $template = $candidates |
            Sort-Object { [int]($_.version) } -Descending |
            Select-Object -First 1
    }
} catch {
    Write-Log "Template query failed: $($_.Exception.Message)" 'ERROR'
    exit 1
}

if (-not $template) {
    Write-Log 'No Attack Surface Reduction Rules template found on this tenant.' 'ERROR'
    Write-Log "Expected display name contains 'Attack Surface Reduction Rules' (excluding ConfigMgr)." 'ERROR'
    Write-Log 'Verify that Intune is licensed and the Endpoint Security workload is enabled.' 'ERROR'
    exit 1
}

Write-Log "Using template: '$($template.displayName)' v$($template.version) (ID: $($template.id))" 'INFO'

# ── Duplicate Check ───────────────────────────────────────────────────────────
Write-Log "Checking for an existing policy named '$policyDisplayName'..." 'INFO'
$escaped        = $policyDisplayName -replace "'", "''"
$existingPolicy = $null
try {
    $er = Invoke-MgGraphRequest -Method GET `
        -Uri "/beta/deviceManagement/configurationPolicies?`$filter=name eq '$escaped'" `
        -OutputType PSObject -ErrorAction Stop
    $existingPolicy = $er.value | Select-Object -First 1
} catch {
    Write-Log "Failed to check for existing policy: $($_.Exception.Message)" 'ERROR'
    exit 1
}

if ($existingPolicy) {
    if ($Force) {
        Write-Log "Policy '$policyDisplayName' exists (ID: $($existingPolicy.id)). Deleting (Force)..." 'WARNING'
        Invoke-MgGraphRequest -Method DELETE `
            -Uri "/beta/deviceManagement/configurationPolicies/$($existingPolicy.id)" -ErrorAction Stop
        Write-Log 'Deleted.' 'WARNING'
    } else {
        Write-Log "Policy '$policyDisplayName' already exists. Use -Force to overwrite." 'WARNING'
        exit 0
    }
}

# ── Settings: Block/Audit Override Logic ──────────────────────────────────────
#
# ASR rule and Network Protection choice settings follow the Settings Catalog
# word suffix pattern:
#   _off   = Not configured / Disabled
#   _block = Block
#   _audit = Audit mode
#   _warn  = Warn (where supported)
#
# Settings matching the keywords below are overridden to the target mode.
# All other settings (e.g., Controlled Folder Access) remain at template defaults.
#
$asrKeywords = @(
    'attacksurface',
    'asrblock',
    'asrrule',
    'enablenetworkprotect',
    'networkprotect',
    'guardrailsenabled_asr'
)

$auditOnlyKeywords = @(
    'enablecontrolledfolderaccess',
    'controlledfolder'
)

function Test-IsAsrOrNpSetting {
    param([string]$DefId)
    foreach ($kw in $asrKeywords) {
        if ($DefId -ilike "*$kw*") { return $true }
    }
    return $false
}

function Test-IsAuditOnlySetting {
    param([string]$DefId)
    foreach ($kw in $auditOnlyKeywords) {
        if ($DefId -ilike "*$kw*") { return $true }
    }
    return $false
}

# ── Fetch Setting Templates ───────────────────────────────────────────────────
Write-Log 'Fetching setting templates from ASR template...' 'INFO'
$stAll = @()
try {
    $stAll = @(Get-AllGraphPages "/beta/deviceManagement/configurationPolicyTemplates/$($template.id)/settingTemplates")
    Write-Log "$($stAll.Count) setting templates retrieved." 'INFO'
} catch {
    Write-Log "Failed to fetch setting templates: $($_.Exception.Message)" 'ERROR'
    exit 1
}

if ($stAll.Count -lt 1) {
    Write-Log 'No setting templates returned by the API. Cannot build policy.' 'ERROR'
    exit 1
}

$settings      = [System.Collections.Generic.List[object]]::new()
$totalIncluded = 0
$totalOverride = 0

# 1. Detect and process packed choice settings
#    (some template versions encode all rules as a single space-separated token list)
$packedSetting = $stAll | Where-Object {
    $tmpl = $_.settingInstanceTemplate
    if (-not $tmpl) { return $false }
    if (-not $tmpl.PSObject.Properties['choiceSettingValueTemplate']) { return $false }
    $cvt = $tmpl.choiceSettingValueTemplate
    if (-not $cvt) { return $false }
    if (-not $cvt.PSObject.Properties['defaultValue']) { return $false }
    $dv = $cvt.defaultValue
    if (-not $dv) { return $false }
    if (-not $dv.PSObject.Properties['settingDefinitionOptionId']) { return $false }
    $optionId = $dv.settingDefinitionOptionId
    if (-not $optionId) { return $false }
    return $optionId -match '\s+'
} | Select-Object -First 1

if ($packedSetting) {
    $packedValue = [string]$packedSetting.settingInstanceTemplate.choiceSettingValueTemplate.defaultValue.settingDefinitionOptionId
    $tokens      = ($packedValue -split '\s+') | Where-Object { $_ -ne '' }
    Write-Log "Packed choice settings: $($tokens.Count) tokens." 'INFO'

    foreach ($token in $tokens) {
        $defId      = $token -replace '_([0-9]+|true|false)$', ''
        $defaultVal = $token

        if (Test-IsAuditOnlySetting $defId) {
            $chosenVal = "${defId}_2"
            Write-Log "  [Audit always] $defId" 'INFO'
            $totalOverride++
        } elseif (Test-IsAsrOrNpSetting $defId) {
            $chosenVal = "${defId}${targetSuffix}"
            Write-Log "  [$modeLabel] $defId" 'INFO'
            $totalOverride++
        } else {
            $chosenVal = $defaultVal
        }

        $settings.Add([ordered]@{
            '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
            settingInstance = [ordered]@{
                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                settingDefinitionId = $defId
                choiceSettingValue  = [ordered]@{
                    '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                    value         = $chosenVal
                    children      = @()
                }
            }
        })
        $totalIncluded++
    }
}

# 2. Process non-packed individual setting templates
foreach ($st in $stAll) {
    if ($packedSetting -and $st.id -eq $packedSetting.id) { continue }

    $tmpl  = $st.settingInstanceTemplate
    if (-not $tmpl) { continue }
    $defId = [string]$tmpl.settingDefinitionId
    $tType = [string]$tmpl.'@odata.type'

    # Group setting collection (ASR rules arrive in this shape in many tenants)
    if ($tType -like '*GroupSettingCollectionInstanceTemplate*') {
        if (-not $tmpl.PSObject.Properties['groupSettingCollectionValueTemplate']) { continue }
        $groupTemplateArr = @($tmpl.groupSettingCollectionValueTemplate)
        if ($groupTemplateArr.Count -eq 0) { continue }
        $groupTemplate = $groupTemplateArr[0]
        if (-not $groupTemplate) { continue }
        if (-not $groupTemplate.PSObject.Properties['children']) { continue }
        $groupChildren = @($groupTemplate.children)
        if (-not $groupChildren -or $groupChildren.Count -eq 0) { continue }

        $groupValue = [ordered]@{ children = @() }
        if ($groupTemplate.PSObject.Properties['settingValueTemplateId'] -and $groupTemplate.settingValueTemplateId) {
            $groupValue.settingValueTemplateReference = [ordered]@{
                settingValueTemplateId = $groupTemplate.settingValueTemplateId
            }
        }

        foreach ($child in $groupChildren) {
            if (-not $child) { continue }
            $childDefId = [string]$child.settingDefinitionId
            if (-not $childDefId) { continue }

            # ASR group children are choice settings in this template.
            $childDefaultVal = ''
            if (
                $child.PSObject.Properties['choiceSettingValueTemplate'] -and
                $child.choiceSettingValueTemplate -and
                $child.choiceSettingValueTemplate.PSObject.Properties['defaultValue'] -and
                $child.choiceSettingValueTemplate.defaultValue -and
                $child.choiceSettingValueTemplate.defaultValue.PSObject.Properties['settingDefinitionOptionId'] -and
                $child.choiceSettingValueTemplate.defaultValue.settingDefinitionOptionId
            ) {
                $childDefaultVal = [string]$child.choiceSettingValueTemplate.defaultValue.settingDefinitionOptionId
            }

            if (Test-IsAuditOnlySetting $childDefId) {
                $childChosenVal = if ($childDefaultVal) { ($childDefaultVal -replace '_(off|block|audit|warn|\d+)$', '') + '_2' } else { "${childDefId}_2" }
                $totalOverride++
            } elseif (Test-IsAsrOrNpSetting $childDefId) {
                $childChosenVal = if ($childDefaultVal) { ($childDefaultVal -replace '_(off|block|audit|warn|\d+)$', '') + $targetSuffix } else { "${childDefId}${targetSuffix}" }
                $totalOverride++
            } else {
                if (-not $childDefaultVal) { continue }
                $childChosenVal = $childDefaultVal
            }

            $childInstance = [ordered]@{
                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                settingDefinitionId = $childDefId
                choiceSettingValue  = [ordered]@{
                    '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                    value         = $childChosenVal
                    children      = @()
                }
            }

            if ($child.PSObject.Properties['settingInstanceTemplateId'] -and $child.settingInstanceTemplateId) {
                $childInstance.settingInstanceTemplateReference = [ordered]@{
                    settingInstanceTemplateId = $child.settingInstanceTemplateId
                }
            }

            if (
                $child.PSObject.Properties['choiceSettingValueTemplate'] -and
                $child.choiceSettingValueTemplate -and
                $child.choiceSettingValueTemplate.PSObject.Properties['settingValueTemplateId'] -and
                $child.choiceSettingValueTemplate.settingValueTemplateId
            ) {
                $childInstance.choiceSettingValue.settingValueTemplateReference = [ordered]@{
                    settingValueTemplateId = $child.choiceSettingValueTemplate.settingValueTemplateId
                }
            }

            $groupValue.children += $childInstance
        }

        if (-not $groupValue.children -or $groupValue.children.Count -eq 0) { continue }

        $groupInstance = [ordered]@{
            '@odata.type'                = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
            settingDefinitionId          = $defId
            groupSettingCollectionValue  = @($groupValue)
        }

        if ($tmpl.PSObject.Properties['settingInstanceTemplateId'] -and $tmpl.settingInstanceTemplateId) {
            $groupInstance.settingInstanceTemplateReference = [ordered]@{
                settingInstanceTemplateId = $tmpl.settingInstanceTemplateId
            }
        }

        $settings.Add([ordered]@{
            '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
            settingInstance = $groupInstance
        })
        $totalIncluded++
    }
    # Choice setting
    elseif ($tType -like '*ChoiceSettingInstanceTemplate*') {
        if (-not $tmpl.PSObject.Properties['choiceSettingValueTemplate']) { continue }
        $choiceTemplate = $tmpl.choiceSettingValueTemplate
        if (-not $choiceTemplate) { continue }

        $defaultVal = ''
        if (
            $choiceTemplate.PSObject.Properties['defaultValue'] -and
            $choiceTemplate.defaultValue -and
            $choiceTemplate.defaultValue.PSObject.Properties['settingDefinitionOptionId'] -and
            $choiceTemplate.defaultValue.settingDefinitionOptionId
        ) {
            $defaultVal = [string]$choiceTemplate.defaultValue.settingDefinitionOptionId
        }

        if (Test-IsAuditOnlySetting $defId) {
            $chosenVal = if ($defaultVal) { ($defaultVal -replace '_(off|block|audit|warn|\d+)$', '') + '_2' } else { "${defId}_2" }
            Write-Log "  [Audit always] $defId" 'INFO'
            $totalOverride++
        } elseif (Test-IsAsrOrNpSetting $defId) {
            $chosenVal = if ($defaultVal) { ($defaultVal -replace '_(off|block|audit|warn|\d+)$', '') + $targetSuffix } else { "${defId}${targetSuffix}" }
            Write-Log "  [$modeLabel] $defId" 'INFO'
            $totalOverride++
        } else {
            if (-not $defaultVal) { continue }
            $chosenVal = $defaultVal
        }

        $choiceInstance = [ordered]@{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = $defId
            choiceSettingValue  = [ordered]@{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                value         = $chosenVal
                children      = @()
            }
        }

        if ($tmpl.PSObject.Properties['settingInstanceTemplateId'] -and $tmpl.settingInstanceTemplateId) {
            $choiceInstance.settingInstanceTemplateReference = [ordered]@{
                settingInstanceTemplateId = $tmpl.settingInstanceTemplateId
            }
        }

        if ($choiceTemplate.PSObject.Properties['settingValueTemplateId'] -and $choiceTemplate.settingValueTemplateId) {
            $choiceInstance.choiceSettingValue.settingValueTemplateReference = [ordered]@{
                settingValueTemplateId = $choiceTemplate.settingValueTemplateId
            }
        }

        $settings.Add([ordered]@{
            '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
            settingInstance = $choiceInstance
        })
        $totalIncluded++
    }
    # Scalar simple setting
    elseif ($tType -like '*SimpleSettingInstanceTemplate*') {
        if (-not $tmpl.PSObject.Properties['simpleSettingValueTemplate']) { continue }
        $svTemplate = $tmpl.simpleSettingValueTemplate
        if (-not $svTemplate) { continue }
        if (-not $svTemplate.PSObject.Properties['defaultValue']) { continue }
        $defaultSimple = $svTemplate.defaultValue
        if (-not $defaultSimple) { continue }
        if (-not $defaultSimple.PSObject.Properties['constantValue']) { continue }
        $constVal = $defaultSimple.constantValue
        if ($null -eq $constVal) { continue }

        $valType = ([string]$svTemplate.'@odata.type') -replace 'Template$', ''
        $settings.Add([ordered]@{
            '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
            settingInstance = [ordered]@{
                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                settingDefinitionId = $defId
                settingInstanceTemplateReference = [ordered]@{
                    settingInstanceTemplateId = $tmpl.settingInstanceTemplateId
                }
                simpleSettingValue  = [ordered]@{
                    '@odata.type' = $valType
                    value         = $constVal
                    settingValueTemplateReference = [ordered]@{
                        settingValueTemplateId = $svTemplate.settingValueTemplateId
                    }
                }
            }
        })
        $totalIncluded++
    }
    # Simple setting collection
    elseif ($tType -like '*SimpleSettingCollectionInstanceTemplate*') {
        if (-not $tmpl.PSObject.Properties['simpleSettingCollectionValueTemplate']) { continue }
        $collectionTemplate = $tmpl.simpleSettingCollectionValueTemplate
        if (-not $collectionTemplate) { continue }
        if (-not $collectionTemplate.PSObject.Properties['defaultValue']) { continue }
        $rawDefaults = @($collectionTemplate.defaultValue)
        if (-not $rawDefaults -or $rawDefaults.Count -eq 0) { continue }

        $collValues = @()
        foreach ($rd in $rawDefaults) {
            $rdType  = [string]$rd.'@odata.type'
            $apiType = $rdType -replace 'ConstantDefaultTemplate$', '' -replace 'ValueTemplate$', 'Value'
            if ($apiType -eq $rdType) { $apiType = $rdType -replace 'Template$', '' }
            $collValues += [ordered]@{
                '@odata.type' = $apiType
                value         = [string]$rd.constantValue
            }
        }

        $settings.Add([ordered]@{
            '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
            settingInstance = [ordered]@{
                '@odata.type'                = '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance'
                settingDefinitionId          = $defId
                settingInstanceTemplateReference = [ordered]@{
                    settingInstanceTemplateId = $tmpl.settingInstanceTemplateId
                }
                simpleSettingCollectionValue = $collValues
            }
        })
        $totalIncluded++
    }
}

Write-Log "Settings compiled: $totalIncluded total, $totalOverride ASR/NP rules set to $modeLabel mode." 'INFO'

if ($settings.Count -eq 0) {
    Write-Log 'No settings to deploy after processing. Exiting.' 'ERROR'
    exit 1
}

# ── Save Audit JSON ───────────────────────────────────────────────────────────
$settingsJsonFile = Join-Path $PSScriptRoot 'asr-settings.json'
try {
    $settings | ConvertTo-Json -Depth 25 | Out-File -FilePath $settingsJsonFile -Encoding utf8 -Force
    Write-Log "Saved settings audit file: $settingsJsonFile" 'INFO'
} catch {
    Write-Log "Failed to save settings audit file: $($_.Exception.Message)" 'WARNING'
}

# ── Policy Creation with Dependency Resolution Loop ───────────────────────────
$descText = "OnCloud ASR Rules policy — $modeLabel mode. All ASR rules and Network Protection configured. Controlled Folder Access: Audit (always). Managed by Deploy-ASRPolicy.ps1."

Write-Log "Creating policy '$policyDisplayName'..." 'INFO'
$maxAttempts   = 300
$attempt       = 0
$policyCreated = $false
$createdPolicy = $null

while (-not $policyCreated -and $attempt -lt $maxAttempts) {
    $attempt++

    $createBody = [ordered]@{
        name              = $policyDisplayName
        description       = $descText
        platforms         = if ($template.platforms)    { $template.platforms }    else { 'windows10' }
        technologies      = if ($template.technologies) { $template.technologies } else { 'mdm,microsoftSense' }
        templateReference = [ordered]@{
            templateId     = $template.id
            templateFamily = $template.templateFamily
        }
        settings = @($settings)
    } | ConvertTo-Json -Depth 25

    try {
        $createdPolicy = Invoke-MgGraphRequest -Method POST `
            -Uri '/beta/deviceManagement/configurationPolicies' `
            -Body $createBody -ContentType 'application/json' -ErrorAction Stop
        $policyCreated = $true
        Write-Log "Policy created successfully (ID: $($createdPolicy.id))." 'SUCCESS'
    } catch {
        $errBody  = Get-GraphErrorBody $_
        $innerMsg = $errBody
        try {
            $outer = $errBody | ConvertFrom-Json -ErrorAction Stop
            if ($outer.error -and $outer.error.message) {
                $innerMsg = $outer.error.message
                try {
                    $inner = $outer.error.message | ConvertFrom-Json -ErrorAction Stop
                    if ($inner.Message) { $innerMsg = $inner.Message }
                } catch {}
            }
        } catch {}

        # Dependency error: parent setting requires missing child settings
        if ($innerMsg -match '^([\w_]+):\s+Selected option.+?Required dependent settings are\s+(.+?)(?:\s+-\s+Operation|$)') {
            $parentId  = $Matches[1]
            $childList = $Matches[2] -split '[,\s]+' | Where-Object { $_ -ne '' }
            Write-Log "Attempt ${attempt}: '$parentId' requires child settings: $($childList -join ', '). Resolving..." 'WARNING'

            $parentIdx = -1
            for ($i = 0; $i -lt $settings.Count; $i++) {
                if ($settings[$i].settingInstance.settingDefinitionId -eq $parentId) {
                    $parentIdx = $i; break
                }
            }
            if ($parentIdx -lt 0) {
                Write-Log "Parent setting '$parentId' not found in settings array. Cannot resolve." 'ERROR'
                exit 1
            }

            foreach ($childId in $childList) {
                $alreadyAdded = @($settings[$parentIdx].settingInstance.choiceSettingValue.children) |
                    Where-Object { $_ -and $_.settingDefinitionId -eq $childId }
                if ($alreadyAdded) { continue }

                $cd = $null
                try {
                    $cd = Invoke-MgGraphRequest -Method GET `
                        -Uri "/beta/deviceManagement/configurationSettings/$childId" `
                        -OutputType PSObject -ErrorAction Stop
                } catch {
                    Write-Log "  Could not fetch child definition '$childId': $($_.Exception.Message)" 'WARNING'
                    continue
                }

                $childObj = $null
                $childValueType = ''
                if ($cd.PSObject.Properties['settingValueType'] -and $cd.settingValueType) {
                    $childValueType = [string]$cd.settingValueType
                } elseif (
                    ($cd.PSObject.Properties['defaultOptionId'] -and $cd.defaultOptionId) -or
                    ($cd.PSObject.Properties['options'] -and $cd.options)
                ) {
                    # Some tenants return choice-like child objects without settingValueType.
                    $childValueType = 'choice'
                } elseif ($cd.PSObject.Properties['@odata.type'] -and $cd.'@odata.type') {
                    $childValueType = [string]$cd.'@odata.type'
                }

                switch -Wildcard ($childValueType) {
                    '*choice*' {
                        $childDefVal = ''
                        if ($cd.PSObject.Properties['defaultOptionId'] -and $cd.defaultOptionId) {
                            $childDefVal = [string]$cd.defaultOptionId
                        }
                        if (-not $childDefVal -and $cd.PSObject.Properties['options'] -and $cd.options) {
                            if ($cd.options[0].PSObject.Properties['itemId'] -and $cd.options[0].itemId) {
                                $childDefVal = [string]$cd.options[0].itemId
                            }
                        }
                        if (-not $childDefVal) {
                            Write-Log "  Child '$childId' has no default option value; skipping child injection." 'WARNING'
                            continue
                        }

                        if (Test-IsAuditOnlySetting $childId) {
                            $childChosenVal = ($childDefVal -replace '_(off|block|audit|warn|\d+)$', '') + '_2'
                        } elseif (Test-IsAsrOrNpSetting $childId) {
                            $childChosenVal = ($childDefVal -replace '_(off|block|audit|warn|\d+)$', '') + $targetSuffix
                        } else {
                            $childChosenVal = $childDefVal
                        }
                        $childObj = [ordered]@{
                            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                            settingDefinitionId = $childId
                            choiceSettingValue  = [ordered]@{
                                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                                value         = $childChosenVal
                                children      = @()
                            }
                        }
                    }
                    '*integer*' {
                        $intDefault = 0
                        if (
                            $cd.PSObject.Properties['defaultValue'] -and $cd.defaultValue -and
                            $cd.defaultValue.PSObject.Properties['value'] -and
                            $null -ne $cd.defaultValue.value
                        ) {
                            $intDefault = [int]$cd.defaultValue.value
                        }

                        $childObj = [ordered]@{
                            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                            settingDefinitionId = $childId
                            simpleSettingValue  = [ordered]@{
                                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationIntegerSettingValue'
                                value         = $intDefault
                            }
                        }
                    }
                    default {
                        $childObj = [ordered]@{
                            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                            settingDefinitionId = $childId
                            simpleSettingValue  = [ordered]@{
                                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
                                value         = ''
                            }
                        }
                    }
                }

                if ($childObj) {
                    if (-not $settings[$parentIdx].settingInstance.choiceSettingValue.children) {
                        $settings[$parentIdx].settingInstance.choiceSettingValue['children'] = @()
                    }
                    $settings[$parentIdx].settingInstance.choiceSettingValue.children += $childObj
                    Write-Log "  Injected child: $childId" 'INFO'
                }
            }
        } else {
            Write-Log "Attempt ${attempt} failed: $innerMsg" 'ERROR'
            if ($attempt -ge $maxAttempts) {
                Write-Log 'Max retry attempts reached. Deployment failed.' 'ERROR'
                exit 1
            }
        }
    }
}

if (-not $policyCreated) {
    Write-Log 'Policy creation failed after all attempts.' 'ERROR'
    exit 1
}

# ── Assignment ────────────────────────────────────────────────────────────────
$assignTarget = $null
if ($PSCmdlet.ParameterSetName -eq 'GroupAssignment') {
    $assignTarget = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $AssignToGroupId }
    Write-Log "Assigning to group: $AssignToGroupId" 'INFO'
} elseif ($PSCmdlet.ParameterSetName -eq 'AllDevices') {
    $assignTarget = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' }
    Write-Log 'Assigning to All Devices...' 'INFO'
}

if ($assignTarget) {
    try {
        $assignBody = @{ assignments = @(@{ target = $assignTarget }) } | ConvertTo-Json -Depth 5
        Invoke-MgGraphRequest -Method POST `
            -Uri "/beta/deviceManagement/configurationPolicies/$($createdPolicy.id)/assign" `
            -Body $assignBody -ContentType 'application/json' -ErrorAction Stop
        Write-Log 'Assignment successful.' 'SUCCESS'
    } catch {
        Write-Log "Assignment failed: $($_.Exception.Message)" 'WARNING'
        Write-Log 'Policy was created but not assigned. Assign manually in the Intune admin center.' 'WARNING'
    }
} else {
    Write-Log 'No assignment specified. Assign the policy manually: Endpoint Security > Attack Surface Reduction.' 'INFO'
}

Write-Log "=== Deployment complete. Policy: '$policyDisplayName' ===" 'SUCCESS'
