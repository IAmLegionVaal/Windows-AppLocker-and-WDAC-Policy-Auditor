[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1,720)]
    [int]$Hours = 168,

    [Parameter()]
    [string]$OutputPath = (Join-Path $PWD ("AppLocker-WDAC-Audit-{0:yyyyMMdd_HHmmss}" -f (Get-Date)))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$ErrorLog = Join-Path $OutputPath 'command-errors.log'

function Invoke-Safe {
    param([scriptblock]$ScriptBlock,[string]$Label)
    try { & $ScriptBlock }
    catch { "[$(Get-Date -Format o)] $Label :: $($_.Exception.Message)" | Add-Content $ErrorLog; $null }
}

$appIdService = Invoke-Safe -Label 'Application Identity service' -ScriptBlock {
    Get-Service AppIDSvc -ErrorAction Stop | Select-Object Name,Status,StartType
}

$effectivePolicy = Invoke-Safe -Label 'Effective AppLocker policy' -ScriptBlock { Get-AppLockerPolicy -Effective -Xml }
if ($effectivePolicy) { $effectivePolicy | Set-Content (Join-Path $OutputPath 'effective-applocker-policy.xml') -Encoding UTF8 }
$localPolicy = Invoke-Safe -Label 'Local AppLocker policy' -ScriptBlock { Get-AppLockerPolicy -Local -Xml }
if ($localPolicy) { $localPolicy | Set-Content (Join-Path $OutputPath 'local-applocker-policy.xml') -Encoding UTF8 }

$ruleRows = New-Object System.Collections.Generic.List[object]
if ($effectivePolicy) {
    [xml]$xml = $effectivePolicy
    foreach ($collection in @($xml.AppLockerPolicy.RuleCollection)) {
        foreach ($rule in @($collection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })) {
            $ruleRows.Add([pscustomobject]@{
                CollectionType = $collection.Type
                EnforcementMode = $collection.EnforcementMode
                RuleType = $rule.LocalName
                Id = $rule.Id
                Name = $rule.Name
                Description = $rule.Description
                UserOrGroupSid = $rule.UserOrGroupSid
                Action = $rule.Action
                Conditions = ($rule.Conditions.InnerXml -replace '\s+',' ').Trim()
                Exceptions = ($rule.Exceptions.InnerXml -replace '\s+',' ').Trim()
            })
        }
    }
}
$ruleRows | Export-Csv (Join-Path $OutputPath 'effective-applocker-rules.csv') -NoTypeInformation -Encoding UTF8

$policyFiles = New-Object System.Collections.Generic.List[object]
$wdacLocations = @(
    "$env:windir\System32\CodeIntegrity\CiPolicies\Active",
    "$env:windir\System32\CodeIntegrity",
    "$env:windir\System32\CodeIntegrity\CIPolicies"
)
foreach ($location in $wdacLocations) {
    if (-not (Test-Path $location)) { continue }
    foreach ($file in Get-ChildItem -Path $location -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.cip','.p7b','.xml') }) {
        $signature = Invoke-Safe -Label "Signature $($file.FullName)" -ScriptBlock { Get-AuthenticodeSignature -FilePath $file.FullName }
        $policyFiles.Add([pscustomobject]@{
            Path = $file.FullName
            Length = $file.Length
            LastWriteTime = $file.LastWriteTime
            Sha256 = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
            SignatureStatus = if ($signature) { $signature.Status } else { 'Unknown' }
            Signer = if ($signature -and $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
        })
    }
}
$policyFiles | Sort-Object Path -Unique | Export-Csv (Join-Path $OutputPath 'wdac-policy-files.csv') -NoTypeInformation -Encoding UTF8

$deviceGuard = Invoke-Safe -Label 'Device Guard status' -ScriptBlock {
    Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop |
        Select-Object AvailableSecurityProperties,RequiredSecurityProperties,SecurityServicesConfigured,SecurityServicesRunning,VirtualizationBasedSecurityStatus,CodeIntegrityPolicyEnforcementStatus,UsermodeCodeIntegrityPolicyEnforcementStatus
}
$deviceGuard | Export-Csv (Join-Path $OutputPath 'device-guard.csv') -NoTypeInformation -Encoding UTF8

$start = (Get-Date).AddHours(-$Hours)
$logs = @(
    'Microsoft-Windows-AppLocker/EXE and DLL',
    'Microsoft-Windows-AppLocker/MSI and Script',
    'Microsoft-Windows-AppLocker/Packaged app-Deployment',
    'Microsoft-Windows-AppLocker/Packaged app-Execution',
    'Microsoft-Windows-CodeIntegrity/Operational'
)
$events = New-Object System.Collections.Generic.List[object]
foreach ($log in $logs) {
    $items = Invoke-Safe -Label "Events $log" -ScriptBlock {
        Get-WinEvent -FilterHashtable @{ LogName=$log; StartTime=$start } -ErrorAction Stop |
            Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message
    }
    foreach ($item in @($items)) {
        if ($item) {
            $events.Add([pscustomobject]@{
                LogName=$log
                TimeCreated=$item.TimeCreated
                Id=$item.Id
                Level=$item.LevelDisplayName
                Provider=$item.ProviderName
                Message=$item.Message
            })
        }
    }
}
$events | Export-Csv (Join-Path $OutputPath 'application-control-events.csv') -NoTypeInformation -Encoding UTF8

$summary = [pscustomobject]@{
    CollectedAt = (Get-Date).ToString('o')
    ComputerName = $env:COMPUTERNAME
    ApplicationIdentityServiceStatus = if ($appIdService) { $appIdService.Status } else { 'Not detected' }
    EffectiveAppLockerPolicyDetected = [bool]$effectivePolicy
    EffectiveAppLockerRuleCount = $ruleRows.Count
    AuditOnlyCollections = @($ruleRows | Where-Object EnforcementMode -eq 'AuditOnly' | Select-Object -ExpandProperty CollectionType -Unique).Count
    EnforcedCollections = @($ruleRows | Where-Object EnforcementMode -eq 'Enabled' | Select-Object -ExpandProperty CollectionType -Unique).Count
    WdacPolicyFilesDetected = @($policyFiles | Sort-Object Path -Unique).Count
    RecentApplicationControlEvents = $events.Count
    RecentErrorOrWarningEvents = @($events | Where-Object { $_.Level -in @('Error','Warning','Critical') }).Count
    VbsStatus = if ($deviceGuard) { $deviceGuard.VirtualizationBasedSecurityStatus } else { $null }
    KernelCodeIntegrityStatus = if ($deviceGuard) { $deviceGuard.CodeIntegrityPolicyEnforcementStatus } else { $null }
    UserModeCodeIntegrityStatus = if ($deviceGuard) { $deviceGuard.UsermodeCodeIntegrityPolicyEnforcementStatus } else { $null }
}
$summary | Export-Csv (Join-Path $OutputPath 'summary.csv') -NoTypeInformation -Encoding UTF8
$summary | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $OutputPath 'summary.json') -Encoding UTF8

$style = '<style>body{font-family:Segoe UI,Arial;margin:28px;color:#172033}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d5dde7;padding:7px;text-align:left}th{background:#eaf2f8}h1,h2{color:#0b3558}</style>'
$body = @()
$body += $summary | ConvertTo-Html -Fragment -PreContent '<h2>Summary</h2>'
$body += $ruleRows | Select-Object -First 250 | ConvertTo-Html -Fragment -PreContent '<h2>Effective AppLocker Rules</h2>'
$body += $policyFiles | ConvertTo-Html -Fragment -PreContent '<h2>WDAC Policy Files</h2>'
$body += $events | Select-Object -First 250 | ConvertTo-Html -Fragment -PreContent '<h2>Recent Events</h2>'
$body += '<p>Diagnostic-only. No application-control policy or service configuration is changed.</p>'
ConvertTo-Html -Title 'AppLocker and WDAC Audit' -Head $style -Body $body | Set-Content (Join-Path $OutputPath 'AppLocker-WDAC-Audit.html') -Encoding UTF8

Write-Host "AppLocker and WDAC audit completed: $OutputPath"
