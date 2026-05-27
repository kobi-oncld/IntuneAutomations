#Requires -Version 5.1

param(
    [switch]$Force   # Delete and recreate the policy if one with the same name already exists
)

# 0. Logging Configuration
$LogFile = Join-Path $PSScriptRoot "MAM_Deployment_Log.txt"

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    $LogEntry | Out-File -FilePath $LogFile -Append
    
    $Color = switch ($Level) {
        "SUCCESS" { "Green" }
        "ERROR"   { "Red" }
        "WARNING" { "Yellow" }
        default   { "Gray" }
    }
    Write-Host $LogEntry -ForegroundColor $Color
}

# 1. Authentication
Write-Log "Initializing MAM Policy Deployment..." "INFO"
try {
    Write-Log "Connecting to Microsoft Graph..." "INFO"
    Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All" -ErrorAction Stop
} catch {
    Write-Log "Authentication failed: $($_.Exception.Message)" "ERROR"
    exit
}

# 2. Hardened Security Configuration
$mamConfig = @{
    # --- Targeting Logic ---
    "appGroupType"                        = "allCoreMicrosoftApps"
    "targetToAllDeviceTypes"              = $true
    
    # --- Data Protection (Hardened) ---
    "allowedInboundDataTransferSources"   = "allApps" 
    "allowedOutboundDataTransferDestinations" = "managedApps"
    "allowedOutboundClipboardSharingLevel" = "managedAppsWithPasteIn"
    "saveAsBlocked"                       = $true
    "allowedDataStorageLocations"         = @("oneDriveForBusiness", "sharePoint")
    "allowedDataIngestionLocations"       = @("oneDriveForBusiness", "sharePoint", "camera", "photoLibrary")
    "encryptAppData"                      = $true
    "contactSyncBlocked"                  = $true
    "printBlocked"                        = $true
    "managedBrowser"                      = "microsoftEdge"
    "managedBrowserToOpenLinksRequired"   = $true
    "dataBackupBlocked"                   = $true
    
    # --- Access Requirements ---
    "pinRequired"                         = $true
    "simplePinBlocked"                    = $true
    "minimumPinLength"                    = 6
    "fingerprintAndBiometricEnabled"      = $true
    "disableAppPinIfDevicePinIsSet"       = $true
    "deviceComplianceRequired"            = $true

    # --- Offline Behaviour ---
    # Wipe managed data after 30 days offline (no connection to Intune service)
    "periodOfflineBeforeWipeIsEnforced"   = "P30D"
    # Require re-authentication after 30 days offline
    "periodOfflineBeforeAccessCheck"      = "PT720H"
}

# 3. Platform Definitions
$platforms = @(
    @{ Name="iOS"; Type="#microsoft.graph.iosManagedAppProtection"; Uri="iosManagedAppProtections"; ScreenBlock=$false },
    @{ Name="Android"; Type="#microsoft.graph.androidManagedAppProtection"; Uri="androidManagedAppProtections"; ScreenBlock=$true }
)

$betaBase = "https://graph.microsoft.com/beta/deviceAppManagement"

foreach ($p in $platforms) {
    $policyName = "MAM - $($p.Name) - Core Microsoft Apps"
    Write-Log "Processing $($p.Name) MAM Policy..." "INFO"

    # Duplicate check
    $escaped      = $policyName -replace "'", "''"
    $existingResp = Invoke-MgGraphRequest -Method GET `
        -Uri "$betaBase/$($p.Uri)?`$filter=displayName eq '$escaped'" `
        -OutputType PSObject -ErrorAction SilentlyContinue
    $existing = $existingResp.value | Where-Object { $_.displayName -eq $policyName } | Select-Object -First 1

    if ($existing) {
        if ($Force) {
            Write-Log "Policy '$policyName' already exists (ID: $($existing.id)). Deleting (Force)..." "WARNING"
            Invoke-MgGraphRequest -Method DELETE `
                -Uri "$betaBase/$($p.Uri)/$($existing.id)" -ErrorAction Stop
            Write-Log "Deleted." "WARNING"
        } else {
            Write-Log "Policy '$policyName' already exists (ID: $($existing.id)). Skipping. Use -Force to overwrite." "WARNING"
            continue
        }
    }

    $payload = [ordered]@{ "@odata.type" = $p.Type }
    $payload["displayName"] = $policyName
    $payload["description"] = "Hardened security based on organization requirements."

    foreach ($key in $mamConfig.Keys) { $payload[$key] = $mamConfig[$key] }
    if ($p.ScreenBlock) { $payload["screenCaptureBlocked"] = $true }

    try {
        $jsonPayload = $payload | ConvertTo-Json -Depth 10
        Write-Log "Sending POST request to Graph for $($p.Name)..." "INFO"
        
        $response = Invoke-MgGraphRequest -Method POST -Uri "$betaBase/$($p.Uri)" -Body $jsonPayload -ContentType "application/json" -ErrorAction Stop
        
        if ($response.id) {
            Write-Log "Successfully Created $($p.Name) Policy (ID: $($response.id))" "SUCCESS"
        } else {
            Write-Log "Policy created for $($p.Name) but no ID was returned in the response." "WARNING"
        }
    } catch {
        $errorDetail = $_.Exception.Message
        if ($_.Exception.InnerException) {
            $errorDetail += " | $($_.Exception.InnerException.Message)"
        }
        
        # Check for specific Graph error details if available
        if ($null -ne $_.ErrorRecord -and $null -ne $_.ErrorRecord.ScriptStackTrace) {
             # Optionally log stack trace to file only
             $_.ErrorRecord.ScriptStackTrace | Out-File -FilePath $LogFile -Append
        }

        Write-Log "Failed to deploy $($p.Name). Error: $errorDetail" "ERROR"
    }
}

Write-Log "Automation Complete. Log saved to: $LogFile" "SUCCESS"
Write-Log "Verify policies in Intune: Apps > App protection policies." "INFO"