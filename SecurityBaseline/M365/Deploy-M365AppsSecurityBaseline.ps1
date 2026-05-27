#Requires -Version 5.1

<#
.SYNOPSIS
    Deploys the Microsoft 365 Apps for Enterprise Security Baseline to Intune.

.DESCRIPTION
    Queries the tenant for the latest active M365 Apps Security Baseline template
    and creates an endpoint security configuration policy covering Office application
    hardening: macro settings, ActiveX controls, add-in trust, telemetry, and more.

    All settings from the M365 Apps baseline template are included by default.
    To exclude specific settings, add keywords to $excludeKeywords below.

.PARAMETER Force
    Delete and recreate the policy if a policy with the same name already exists.

.EXAMPLE
    .\Deploy-M365AppsSecurityBaseline.ps1
    .\Deploy-M365AppsSecurityBaseline.ps1 -Force
#>

param(
    [switch]$Force
)

# ── Logging ───────────────────────────────────────────────────────────────────
$LogFile = Join-Path $PSScriptRoot "M365_Baseline_Deployment_Log.txt"

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

Write-Log "=== M365 Apps Security Baseline Deployment ===" "INFO"

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

$policyDisplayName = "OnCloud - M365 Apps Security Baseline"
$settingsJsonFile  = Join-Path $PSScriptRoot "m365-baseline-settings.json"

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

# ── Helper: extract JSON error body from Graph exceptions ─────────────────────
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
Write-Log "Searching for M365 Apps Security Baseline template..." "INFO"
$template = $null
try {
    # Query ALL templates — no OData family filter so newer versions are never missed
    $allTemplates = Get-AllGraphPages "/beta/deviceManagement/configurationPolicyTemplates"

    # Log every matching template for visibility
    $allTemplates |
        Where-Object { $_.displayName -imatch '365 Apps for Enterprise|Microsoft 365 Apps' } |
        Sort-Object { [int]($_.version) } |
        ForEach-Object {
            Write-Log "  Found template: '$($_.displayName)' v$($_.version) family=$($_.templateFamily) (ID: $($_.id)) deprecated=$($_.isDeprecated) lifecycle=$($_.lifecycleState)" "INFO"
        }

    # Prefer lifecycleState=active; within active pick highest version.
    # NOTE: version numbers are NOT monotonically increasing across lifecycle
    # transitions (same pattern seen in MDE baseline), so active-first is essential.
    $candidates = $allTemplates |
        Where-Object {
            $_.displayName -imatch '365 Apps for Enterprise|Microsoft 365 Apps' -and
            $_.isDeprecated -ne $true -and
            $_.lifecycleState -ne 'deprecated'
        }
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
    Write-Log "configurationPolicyTemplates query failed: $($_.Exception.Message)" "ERROR"
    exit 1
}

if (-not $template) {
    Write-Log "No M365 Apps Security Baseline template found on this tenant." "ERROR"
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
        Invoke-MgGraphRequest -Method DELETE `
            -Uri "/beta/deviceManagement/configurationPolicies/$($existingPolicy.id)" -ErrorAction Stop
        Write-Log "Deleted." "WARNING"
    } else {
        Write-Log "Policy '$policyDisplayName' already exists (ID: $($existingPolicy.id)). Use -Force to overwrite." "WARNING"
        exit 0
    }
}

# ── Customisation exclusions ──────────────────────────────────────────────────
# All M365 Apps baseline settings are included by default.
# Add lowercase keyword fragments here to exclude specific setting IDs if needed.
$excludeKeywords = @(
    # Example: 'telemetry'  — uncomment to exclude telemetry-related settings
)

$descText = "Customised M365 Apps Security Baseline. All settings from the Microsoft 365 Apps for Enterprise Security Baseline template are included (macros, ActiveX, add-ins, connected experiences hardening)."

# ── Build settings array from templates ───────────────────────────────────────
Write-Log "Fetching setting templates from M365 Apps baseline template..." "INFO"
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

$settings       = [System.Collections.Generic.List[object]]::new()
$totalRemoved   = 0
$totalIncluded  = 0

function Test-Excluded {
    param([string]$DefId)
    foreach ($kw in $excludeKeywords) {
        if ($DefId -like "*$kw*") { return $true }
    }
    return $false
}

# 1. Process packed choice settings
$packedSetting = $stAll | Where-Object {
    $_.settingInstanceTemplate -and
    $_.settingInstanceTemplate.choiceSettingValueTemplate -and
    $_.settingInstanceTemplate.choiceSettingValueTemplate.defaultValue.settingDefinitionOptionId -match '\s+'
} | Select-Object -First 1

if ($packedSetting) {
    $packedValue = [string]$packedSetting.settingInstanceTemplate.choiceSettingValueTemplate.defaultValue.settingDefinitionOptionId
    $tokens      = ($packedValue -split '\s+') | Where-Object { $_ -ne '' }
    Write-Log "Packed choice settings: $($tokens.Count) tokens extracted." "INFO"

    foreach ($token in $tokens) {
        $defId = $token -replace '_([0-9]+|true|false)$', ''

        if (Test-Excluded $defId) {
            $totalRemoved++
            continue
        }

        $settings.Add([ordered]@{
            '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
            settingInstance = [ordered]@{
                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                settingDefinitionId = $defId
                choiceSettingValue  = [ordered]@{
                    '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                    value         = $token
                    children      = @()
                }
            }
        })
        $totalIncluded++
    }
} else {
    Write-Log "No packed choice settings found. Will use individual setting templates only." "WARNING"
}

# 2. Process non-packed setting templates
foreach ($st in $stAll) {
    if ($packedSetting -and $st.id -eq $packedSetting.id) { continue }

    $tmpl  = $st.settingInstanceTemplate
    if (-not $tmpl) { continue }
    $defId = [string]$tmpl.settingDefinitionId
    $tType = [string]$tmpl.'@odata.type'

    if (Test-Excluded $defId) {
        $totalRemoved++
        continue
    }

    # Unpacked choice setting
    if ($tType -like '*ChoiceSettingInstanceTemplate*') {
        $defVal = [string]$tmpl.choiceSettingValueTemplate.defaultValue.settingDefinitionOptionId
        if (-not $defVal) { continue }

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
        $totalIncluded++
    }
    # Scalar simple setting
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
        $totalIncluded++
    }
    # SimpleSettingCollection
    elseif ($tType -like '*SimpleSettingCollectionInstanceTemplate*') {
        $rawDefaults = @($tmpl.simpleSettingCollectionValueTemplate.defaultValue)
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

Write-Log "Settings compiled: $($settings.Count) included, $totalRemoved excluded." "INFO"

if ($settings.Count -eq 0) {
    Write-Log "No settings to deploy after filtering. Exiting." "ERROR"
    exit 1
}

try {
    $settings | ConvertTo-Json -Depth 25 | Out-File -FilePath $settingsJsonFile -Encoding utf8 -Force
    Write-Log "Saved settings JSON to: $settingsJsonFile" "INFO"
} catch {
    Write-Log "Failed to save settings JSON: $($_.Exception.Message)" "WARNING"
}

# ── Policy Creation with Dependency Resolution Loop ───────────────────────────
Write-Log "Creating M365 Apps baseline policy '$policyDisplayName'..." "INFO"
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
            templateFamily = if ($template.templateFamily) { $template.templateFamily } else { 'baseline' }
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

        # 1. Dependency error
        if ($innerMsg -match '^([\w_]+):\s+Selected option.+?Required dependent settings are\s+(.+?)(?:\s+-\s+Operation|$)') {
            $parentId  = $Matches[1]
            $childList = $Matches[2] -split '[,\s]+' | Where-Object { $_ -ne '' }
            Write-Log "Attempt ${attempt}: '$parentId' requires child settings: $($childList -join ', '). Resolving..." "WARNING"

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
                $alreadyAdded = @($settings[$parentIdx].settingInstance.choiceSettingValue.children) |
                    Where-Object { $_ -and $_.settingDefinitionId -eq $childId }
                if ($alreadyAdded) { continue }

                $cd = $null
                try {
                    $cd = Invoke-MgGraphRequest -Method GET `
                        -Uri "/beta/deviceManagement/configurationSettings/$([Uri]::EscapeDataString($childId))" `
                        -OutputType PSObject -ErrorAction Stop
                } catch {
                    Write-Log "Could not retrieve child definition for '$childId'. Using fallback." "WARNING"
                }

                $newChild = $null

                if ($cd -and ($cd.'@odata.type' -eq '#microsoft.graph.deviceManagementConfigurationSettingGroupCollectionDefinition' -or $cd.childIds)) {
                    $collectionValues = @()
                    $groupChildren = @()
                    foreach ($cId in $cd.childIds) {
                        $groupChildren += [ordered]@{
                            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                            settingDefinitionId = $cId
                            simpleSettingValue  = [ordered]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = "" }
                        }
                    }
                    $collectionValues += [ordered]@{
                        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationGroupSettingValue'
                        children      = $groupChildren
                    }
                    $newChild = [ordered]@{
                        '@odata.type'               = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
                        settingDefinitionId         = $childId
                        groupSettingCollectionValue = $collectionValues
                    }
                    Write-Log "Added GroupCollection child '$childId' to '$parentId'." "INFO"
                }
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
                        simpleSettingValue  = [ordered]@{ '@odata.type' = $valType; value = $rawVal }
                    }
                    Write-Log "Added SimpleSetting child '$childId' = $rawVal to '$parentId'." "INFO"
                }
                elseif ($cd -and $cd.'@odata.type' -like '*SimpleSettingCollectionDefinition*') {
                    $collVals = @()
                    if ($cd.defaultValue) {
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
                        Write-Log "Added SimpleCollection child '$childId' ($($collVals.Count) value(s)) to '$parentId'." "INFO"
                    }
                }
                else {
                    $childOptId = ''
                    if ($cd -and $cd.options) {
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
                    Write-Log "Added ChoiceSetting child '$childId' = '$childOptId' to '$parentId'." "INFO"
                }

                if ($newChild) {
                    $existing = @($settings[$parentIdx].settingInstance.choiceSettingValue.children)
                    $settings[$parentIdx].settingInstance.choiceSettingValue.children = $existing + @($newChild)
                }
            }
        }
        # 2. Setting not in this template version
        elseif ($innerMsg -match 'TemplateReference not found.+?setting definition id\s+([\w_]+)') {
            $badDefId = $Matches[1]
            $before   = $settings.Count
            $settings = [System.Collections.Generic.List[object]]($settings |
                Where-Object { $_.settingInstance.settingDefinitionId -ne $badDefId })
            Write-Log "Attempt ${attempt}: Removed '$badDefId' (not in template, $($before - $settings.Count) removed). Retrying..." "WARNING"
        }
        # 3. Unhandled error
        else {
            $e = $_.Exception.Message
            if ($errBody) { $e += " | API Error: $errBody" }
            Write-Log "Unhandled error during policy creation: $e" "ERROR"
            exit 1
        }
    }
}

if (-not $policyCreated) {
    Write-Log "Failed to create policy after $maxAttempts attempts." "ERROR"
    exit 1
}

Write-Log "Deployment completed successfully." "SUCCESS"
