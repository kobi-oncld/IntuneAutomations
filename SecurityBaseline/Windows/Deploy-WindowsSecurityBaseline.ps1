#Requires -Version 5.1

<#
.SYNOPSIS
    Deploys a customized Windows MDM Security Baseline profile to Microsoft Intune.

.DESCRIPTION
    Queries the tenant for the latest Windows Security Baseline template, creates an
    endpoint security configuration policy, then applies customizations by setting
    conflict-prone areas to 'Not Configured' and adjusting UAC prompts.

.PARAMETER Force
    Delete and recreate the policy if a policy with the same name already exists.

.EXAMPLE
    .\Deploy-WindowsSecurityBaseline.ps1
    .\Deploy-WindowsSecurityBaseline.ps1 -Force
#>

param(
    [switch]$Force
)

# ── Logging ───────────────────────────────────────────────────────────────────
$LogFile = Join-Path $PSScriptRoot "SecurityBaseline_Deployment_Log.txt"

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")][string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry  = "[$Timestamp] [$Level] $Message"
    $LogEntry | Out-File -FilePath $LogFile -Append -Encoding utf8
    $Color = switch ($Level) {
        "SUCCESS" { "Green"  }
        "ERROR"   { "Red"    }
        "WARNING" { "Yellow" }
        default   { "Gray"   }
    }
    Write-Host $LogEntry -ForegroundColor $Color
}

Write-Log "=== Windows Security Baseline Deployment ===" "INFO"

# ── Module ────────────────────────────────────────────────────────────────────
Write-Log "Checking for Microsoft.Graph.Authentication module..." "INFO"
if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
    Write-Log "Module not found. Installing Microsoft.Graph.Authentication..." "INFO"
    try {
        Install-Module -Name 'Microsoft.Graph.Authentication' -Scope CurrentUser -Force -ErrorAction Stop
        Write-Log "Module installed successfully." "SUCCESS"
    } catch {
        Write-Log "Failed to install module: $($_.Exception.Message)" "ERROR"
        exit 1
    }
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# ── Authentication ────────────────────────────────────────────────────────────
Write-Log "Connecting to Microsoft Graph..." "INFO"
try {
    Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All" -ErrorAction Stop
} catch {
    Write-Log "Authentication failed: $($_.Exception.Message)" "ERROR"
    exit 1
}

$policyDisplayName = "OnCloud - Windows Security Baseline"
$settingsJsonFile  = Join-Path $PSScriptRoot "baseline-settings.json"

# ── Helper: page through all Graph results ────────────────────────────────────
function Get-AllGraphPages {
    param([string]$Uri)
    $all  = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop
        if ($page.value) { $page.value | ForEach-Object { $all.Add($_) } }
        $next = $page.'@odata.nextLink'
    }
    return $all
}

# ── Helper: extract JSON response error body from Graph exceptions ────────────
function Get-GraphErrorBody {
    param($ErrorRecord)
    if (-not $ErrorRecord) { return "" }
    if ($ErrorRecord.Exception -and $ErrorRecord.Exception.Response -and $ErrorRecord.Exception.Response.Content) {
        try {
            $body = $ErrorRecord.Exception.Response.Content.ReadAsStringAsync().Result
            if ($body) { return $body }
        } catch {}
    }
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $msg = $ErrorRecord.ErrorDetails.Message
        if ($msg -match '(?s)(\{"error":.*)') { return $Matches[1] }
    }
    if ($ErrorRecord.Exception -and $ErrorRecord.Exception.Message) {
        $msg = $ErrorRecord.Exception.Message
        if ($msg -match '(?s)(\{"error":.*)') { return $Matches[1] }
    }
    return ""
}

# ── Template Discovery ────────────────────────────────────────────────────────
Write-Log "Searching configurationPolicyTemplates..." "INFO"
$template = $null
try {
    $newTemplates = Get-AllGraphPages "/beta/deviceManagement/configurationPolicyTemplates?`$filter=templateFamily eq 'baseline'"
    $template = $newTemplates |
        Where-Object {
            $_.displayName -imatch 'windows' -and
            $_.displayName -inotmatch 'Defender for Endpoint|MDE|Microsoft Edge|Windows Server|HoloLens'
        } |
        Sort-Object version -Descending |
        Select-Object -First 1
} catch {
    Write-Log "configurationPolicyTemplates query failed: $($_.Exception.Message)" "ERROR"
    exit 1
}

if (-not $template) {
    Write-Log "No Windows Security Baseline template found on this tenant." "ERROR"
    exit 1
}

Write-Log "Using template: '$($template.displayName)' v$($template.version) (ID: $($template.id))" "INFO"

# ── Duplicate check ───────────────────────────────────────────────────────────
Write-Log "Checking for an existing policy named '$policyDisplayName'..." "INFO"
$escaped        = $policyDisplayName -replace "'", "''"
$existingPolicy = $null
try {
    $er = Invoke-MgGraphRequest -Method GET `
        -Uri "/beta/deviceManagement/configurationPolicies?`$filter=name eq '$escaped'" `
        -OutputType PSObject -ErrorAction Stop
    $existingPolicy = if ($er) { $er.value | Select-Object -First 1 } else { $null }
} catch {
    Write-Log "Failed to check for existing policies: $($_.Exception.Message)" "ERROR"
    exit 1
}

if ($existingPolicy) {
    if ($Force) {
        Write-Log "Policy '$policyDisplayName' already exists (ID: $($existingPolicy.id)). Deleting (Force)..." "WARNING"
        Invoke-MgGraphRequest -Method DELETE -Uri "/beta/deviceManagement/configurationPolicies/$($existingPolicy.id)" -ErrorAction Stop
        Write-Log "Deleted." "WARNING"
    } else {
        Write-Log "Policy '$policyDisplayName' already exists (ID: $($existingPolicy.id)). Use -Force to overwrite." "WARNING"
        exit 0
    }
}

# ── Customisation exclusions and overrides ─────────────────────────────────────
# Exclude settings by omitting them (sets them to Not Configured)
$excludeKeywords = @(
    'bitlocker',                     # BitLocker
    'encryption',                    # Device Encryption
    'attacksurface',                 # ASR rules
    'asr',                           # ASR rules abbreviation
    'networkprotection',             # Network Protection
    'enablenetworkprotection',       # Network Protection (alternative ID)
    'passportforwork',               # Windows Hello for Business
    'windowshello',                  # Windows Hello for Business (alternative ID)
    'helloforbusiness',              # Windows Hello for Business (alternative ID)
    'defender',                      # Microsoft Defender Antivirus
    'antivirus',                     # Defender Antivirus (alternative ID)
    'firewall'                       # Firewall
)

$uacKeyword = 'standarduser'

# Description for the policy
$descText = "Customised Windows Security Baseline. UAC standard user prompt: Prompt for credentials on secure desktop. BitLocker, ASR, Windows Hello for Business, Defender Antivirus, and Firewall settings are Not Configured (managed by dedicated policies)."

# ── Build settings array from templates ───────────────────────────────────────
Write-Log "Fetching setting templates from baseline template..." "INFO"
$stAll = @()
try {
    $stAll = @(Get-AllGraphPages "/beta/deviceManagement/configurationPolicyTemplates/$($template.id)/settingTemplates")
    Write-Log "$($stAll.Count) setting templates retrieved." "INFO"
} catch {
    Write-Log "Failed to fetch setting templates: $($_.Exception.Message)" "ERROR"
    exit 1
}

if ($stAll.Count -lt 1) {
    Write-Log "No setting templates returned by the API. Cannot build policy." "ERROR"
    exit 1
}

$settings = [System.Collections.Generic.List[object]]::new()
$totalRemoved = 0
$totalOverridden = 0

# 1. Process choice setting instances (packed tokens)
# Modern security baselines pack choice settings inside the first setting template's default option ID
$packedSetting = $stAll | Where-Object {
    $_.settingInstanceTemplate -and 
    $_.settingInstanceTemplate.choiceSettingValueTemplate -and
    $_.settingInstanceTemplate.choiceSettingValueTemplate.defaultValue.settingDefinitionOptionId -match '\s+'
} | Select-Object -First 1

if ($packedSetting) {
    $packedValue = [string]$packedSetting.settingInstanceTemplate.choiceSettingValueTemplate.defaultValue.settingDefinitionOptionId
    $tokens      = ($packedValue -split '\s+') | Where-Object { $_ -ne '' }
    Write-Log "Packed choice settings found: $($tokens.Count) tokens extracted." "INFO"

    foreach ($token in $tokens) {
        # Extract base definition ID (remove trailing _[integer] or _true or _false)
        $defId       = $token -replace '_([0-9]+|true|false)$', ''
        $optionValue = $token

        # Check if setting should be excluded
        $isExcluded = $false
        foreach ($kw in $excludeKeywords) {
            if ($defId -like "*$kw*") {
                $isExcluded = $true
                break
            }
        }

        if ($isExcluded) {
            $totalRemoved++
            continue
        }

        # Override UAC standard user elevation prompt behavior
        # Default: _0 (Automatically deny elevation requests) -> Change to: _3 (Prompt for credentials on secure desktop)
        if ($defId -like "*$uacKeyword*") {
            $optionValue = $token -replace '_\d+$', '_3'
            Write-Log "UAC standard-user prompt override applied: $defId -> $optionValue" "INFO"
            $totalOverridden++
        }

        $settings.Add([ordered]@{
            '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
            settingInstance = [ordered]@{
                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                settingDefinitionId = $defId
                choiceSettingValue  = [ordered]@{
                    '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                    value         = $optionValue
                    children      = @()
                }
            }
        })
    }
} else {
    Write-Log "No packed choice settings found in template settingTemplates. Building from individual templates." "WARNING"
}

# 2. Process non-packed setting templates (scalars, collections, etc.)
foreach ($st in $stAll) {
    # Skip the packed setting itself
    if ($packedSetting -and $st.id -eq $packedSetting.id) { continue }

    $tmpl  = $st.settingInstanceTemplate
    if (-not $tmpl) { continue }
    $defId = [string]$tmpl.settingDefinitionId
    $tType = [string]$tmpl.'@odata.type'

    # Check if setting should be excluded
    $isExcluded = $false
    foreach ($kw in $excludeKeywords) {
        if ($defId -like "*$kw*") {
            $isExcluded = $true
            break
        }
    }
    if ($isExcluded) {
        $totalRemoved++
        continue
    }

    # Choice setting template (unpacked)
    if ($tType -like '*ChoiceSettingInstanceTemplate*') {
        $defVal = [string]$tmpl.choiceSettingValueTemplate.defaultValue.settingDefinitionOptionId
        if (-not $defVal) { continue }

        if ($defId -like "*$uacKeyword*") {
            $defVal = $defVal -replace '_\d+$', '_3'
            Write-Log "UAC standard-user prompt override applied (unpacked): $defId -> $defVal" "INFO"
            $totalOverridden++
        }

        $settings.Add([ordered]@{
            '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
            settingInstance = [ordered]@{
                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                settingDefinitionId = $defId
                settingInstanceTemplateReference = [ordered]@{
                    settingInstanceTemplateId = $tmpl.settingInstanceTemplateId
                }
                choiceSettingValue  = [ordered]@{
                    '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                    value         = $defVal
                    children      = @()
                    settingValueTemplateReference = [ordered]@{
                        settingValueTemplateId = $tmpl.choiceSettingValueTemplate.settingValueTemplateId
                    }
                }
            }
        })
    }
    # Simple setting template (scalars like integers and strings)
    elseif ($tType -like '*SimpleSettingInstanceTemplate*') {
        $svTemplate = $tmpl.simpleSettingValueTemplate
        if (-not $svTemplate) { continue }
        $constVal = $svTemplate.defaultValue.constantValue
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
    }
    # Simple setting collection template (arrays of SIDs or strings)
    elseif ($tType -like '*SimpleSettingCollectionInstanceTemplate*') {
        $rawDefaults = @($tmpl.simpleSettingCollectionValueTemplate.defaultValue)
        if (-not $rawDefaults -or $rawDefaults.Count -eq 0) { continue }

        # Transform template default-value objects into proper API value objects
        $collValues = @()
        foreach ($rd in $rawDefaults) {
            # Template type e.g. ...StringSettingValueConstantDefaultTemplate -> ...StringSettingValue
            $rdType = [string]$rd.'@odata.type'
            $apiType = $rdType -replace 'ConstantDefaultTemplate$', '' -replace 'ValueTemplate$', 'Value'
            if ($apiType -eq $rdType) {
                # Fallback: strip any trailing Template
                $apiType = $rdType -replace 'Template$', ''
            }
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
    }
}

Write-Log "Settings compiled: $($settings.Count) included, $totalRemoved excluded, $totalOverridden UAC overrides." "INFO"

# Save compiled settings to JSON for audit trail
try {
    $settings | ConvertTo-Json -Depth 25 | Out-File -FilePath $settingsJsonFile -Encoding utf8 -Force
    Write-Log "Saved compiled settings JSON to: $settingsJsonFile" "INFO"
} catch {
    Write-Log "Failed to save settings JSON: $($_.Exception.Message)" "WARNING"
}

# ── Policy Creation and Dependency Resolution Loop ─────────────────────────────
Write-Log "Creating baseline policy '$policyDisplayName'..." "INFO"
$maxAttempts   = 300
$attempt       = 0
$policyCreated = $false

while (-not $policyCreated -and $attempt -lt $maxAttempts) {
    $attempt++

    $createBody = [ordered]@{
        name              = $policyDisplayName
        description       = $descText
        platforms         = if ($template.platforms)    { $template.platforms }    else { 'windows10' }
        technologies      = if ($template.technologies) { $template.technologies } else { 'mdm' }
        templateReference = [ordered]@{
            templateId     = $template.id
            templateFamily = 'baseline'
        }
        settings = @($settings)
    } | ConvertTo-Json -Depth 25

    try {
        $createdPolicy = Invoke-MgGraphRequest -Method POST `
            -Uri '/beta/deviceManagement/configurationPolicies' `
            -Body $createBody -ContentType 'application/json' -ErrorAction Stop
        $policyCreated = $true
        Write-Log "Policy created successfully (ID: $($createdPolicy.id))." "SUCCESS"
    } catch {
        $errBody = Get-GraphErrorBody $_
        
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

        # 1. Dependency error resolution:
        # "{parentId}: Selected option ... doesnt contain required dependent settings. Required dependent settings are {childId} ..."
        if ($innerMsg -match '^([\w_]+):\s+Selected option.+?Required dependent settings are\s+(.+?)(?:\s+-\s+Operation|$)') {
            $parentId  = $Matches[1]
            $childList = $Matches[2] -split '[,\s]+' | Where-Object { $_ -ne '' }
            Write-Log "Dependency match: '$parentId' requires child settings: $($childList -join ', '). Resolving..." "WARNING"

            # Locate parent setting
            $parentIdx = -1
            for ($i = 0; $i -lt $settings.Count; $i++) {
                if ($settings[$i].settingInstance.settingDefinitionId -eq $parentId) {
                    $parentIdx = $i; break
                }
            }
            if ($parentIdx -lt 0) {
                Write-Log "Parent setting '$parentId' not found in settings array. Cannot resolve." "ERROR"
                exit 1
            }

            foreach ($childId in $childList) {
                # Skip if already added
                $alreadyAdded = @($settings[$parentIdx].settingInstance.choiceSettingValue.children) |
                    Where-Object { $_ -and $_.settingDefinitionId -eq $childId }
                if ($alreadyAdded) { continue }

                # Fetch definition of the child setting to build a proper child instance
                $cd = $null
                try {
                    $cd = Invoke-MgGraphRequest -Method GET `
                        -Uri "/beta/deviceManagement/configurationSettings/$([Uri]::EscapeDataString($childId))" `
                        -OutputType PSObject -ErrorAction Stop
                } catch {
                    Write-Log "Could not retrieve child definition for '$childId'. Using fallback." "WARNING"
                }

                $newChild = $null
                # Group Setting Collection (e.g. Hardened UNC Paths)
                if ($cd -and ($cd.'@odata.type' -eq '#microsoft.graph.deviceManagementConfigurationSettingGroupCollectionDefinition' -or $cd.childIds)) {
                    $collectionValues = @()
                    if ($childId -like '*hardeneduncpaths*') {
                        $paths = @(
                            @{ Key = '\\*\SYSVOL'; Value = 'RequireMutualAuthentication=1,RequireIntegrity=1' },
                            @{ Key = '\\*\NETLOGON'; Value = 'RequireMutualAuthentication=1,RequireIntegrity=1' }
                        )
                        foreach ($p in $paths) {
                            $collectionValues += [ordered]@{
                                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationGroupSettingValue'
                                children = @(
                                    [ordered]@{
                                        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                                        settingDefinitionId = "${childId}_key"
                                        simpleSettingValue = [ordered]@{
                                            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
                                            value = $p.Key
                                        }
                                    },
                                    [ordered]@{
                                        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                                        settingDefinitionId = "${childId}_value"
                                        simpleSettingValue = [ordered]@{
                                            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
                                            value = $p.Value
                                        }
                                    }
                                )
                            }
                        }
                    } else {
                        $groupChildren = @()
                        foreach ($cId in $cd.childIds) {
                            $groupChildren += [ordered]@{
                                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                                settingDefinitionId = $cId
                                simpleSettingValue = [ordered]@{
                                    '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
                                    value = ""
                                }
                            }
                        }
                        $collectionValues += [ordered]@{
                            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationGroupSettingValue'
                            children = $groupChildren
                        }
                    }

                    $newChild = [ordered]@{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
                        settingDefinitionId = $childId
                        groupSettingCollectionValue = $collectionValues
                    }
                    Write-Log "Added GroupCollection child '$childId' to parent '$parentId'." "INFO"
                }
                # Simple Setting (scalar)
                elseif ($cd -and $cd.'@odata.type' -like '*SimpleSettingDefinition*') {
                    $valDef  = $cd.defaultValue
                    $valType = '#microsoft.graph.deviceManagementConfigurationIntegerSettingValue'
                    $rawVal  = 0
                    if ($valDef) {
                        if ($valDef.'@odata.type') { $valType = [string]$valDef.'@odata.type' }
                        if ($null -ne $valDef.value) { $rawVal = $valDef.value }
                    }
                    $newChild = [ordered]@{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                        settingDefinitionId = $childId
                        simpleSettingValue  = [ordered]@{
                            '@odata.type' = $valType
                            value         = $rawVal
                        }
                    }
                    Write-Log "Added SimpleSetting child '$childId' = $rawVal to parent '$parentId'." "INFO"
                }
                # Simple Setting Collection (array)
                elseif ($cd -and $cd.'@odata.type' -like '*SimpleSettingCollectionDefinition*') {
                    $collVals = @()
                    if ($childId -like '*deny_list*') {
                        # Default block FireWire device GUID
                        $collVals = @(
                            [ordered]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = '{d48179be-ec20-11d1-b6b8-00c04fa372a7}' }
                        )
                    } elseif ($cd.defaultValue) {
                        $collVals = @($cd.defaultValue | ForEach-Object {
                            [ordered]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = [string]$_ }
                        })
                    }
                    if ($collVals.Count -gt 0) {
                        $newChild = [ordered]@{
                            '@odata.type'                = '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance'
                            settingDefinitionId          = $childId
                            simpleSettingCollectionValue = $collVals
                        }
                        Write-Log "Added SimpleCollection child '$childId' ($($collVals.Count) value(s)) to parent '$parentId'." "INFO"
                    }
                }
                # Choice Setting
                else {
                    $childOptId = ''
                    if ($cd -and $cd.options) {
                        # Try to find a disabling option first (security best practice), then default to last/highest-indexed option
                        $best = $cd.options | Where-Object { $_.name -imatch 'disabl' } | Select-Object -First 1
                        if (-not $best) {
                            $best = $cd.options |
                                Sort-Object { [int]([regex]::Match($_.itemId, '_(\d+)$').Groups[1].Value) } |
                                Select-Object -Last 1
                        }
                        if ($best) { $childOptId = $best.itemId }
                    }
                    if (-not $childOptId) { $childOptId = "${childId}_4" }

                    $newChild = [ordered]@{
                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                        settingDefinitionId = $childId
                        choiceSettingValue  = [ordered]@{
                            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                            value         = $childOptId
                            children      = @()
                        }
                    }
                    Write-Log "Added ChoiceSetting child '$childId' = '$childOptId' to parent '$parentId'." "INFO"
                }

                if ($newChild) {
                    $existing = @($settings[$parentIdx].settingInstance.choiceSettingValue.children)
                    $settings[$parentIdx].settingInstance.choiceSettingValue.children = $existing + @($newChild)
                }
            }
        }
        # 2. Template Reference missing setting error resolution:
        # "TemplateReference not found ... setting definition id {badDefId}"
        elseif ($innerMsg -match 'TemplateReference not found.+?setting definition id\s+([\w_]+)') {
            $badDefId = $Matches[1]
            $before   = $settings.Count
            $settings = [System.Collections.Generic.List[object]]($settings | Where-Object { $_.settingInstance.settingDefinitionId -ne $badDefId })
            Write-Log "Setting '$badDefId' not supported in this template version. Removed ($($before - $settings.Count) setting(s) removed). Retrying..." "WARNING"
        }
        # 3. Unhandled error - terminate
        else {
            $e = $_.Exception.Message
            if ($errBody) { $e += " | API Error: $errBody" }
            Write-Log "Unhandled error during baseline creation: $e" "ERROR"
            exit 1
        }
    }
}

if (-not $policyCreated) {
    Write-Log "Failed to create policy after $maxAttempts dependency-resolution attempts." "ERROR"
    exit 1
}

Write-Log "Deployment script completed successfully." "SUCCESS"
