[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [switch]$RestartApplicationIdentity,
    [switch]$RefreshGroupPolicy,
    [switch]$SetAppLockerEnforcement,
    [ValidateSet('AuditOnly','Enabled')][string]$Mode='AuditOnly',
    [string]$OutputPath="$env:USERPROFILE\Desktop\AppControlRepair"
)
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Path $OutputPath -Force|Out-Null
$Log=Join-Path $OutputPath ("repair-{0:yyyyMMdd-HHmmss}.log"-f(Get-Date))
function L($m){"$(Get-Date -Format s) $m"|Tee-Object -FilePath $Log -Append}
if(-not($RestartApplicationIdentity-or$RefreshGroupPolicy-or$SetAppLockerEnforcement)){throw'Choose at least one repair action.'}
Get-AppLockerPolicy -Effective -Xml|Set-Content (Join-Path $OutputPath 'effective-policy-before.xml')
if($RestartApplicationIdentity-and$PSCmdlet.ShouldProcess('AppIDSvc','Set automatic and restart')){Set-Service AppIDSvc -StartupType Automatic;Start-Service AppIDSvc -ErrorAction SilentlyContinue;Restart-Service AppIDSvc -Force;L'Application Identity service repaired.'}
if($RefreshGroupPolicy-and$PSCmdlet.ShouldProcess('Group Policy','Refresh computer policy')){gpupdate /target:computer /force|Tee-Object -FilePath $Log -Append;L'Group Policy refreshed.'}
if($SetAppLockerEnforcement){
    $policy=Get-AppLockerPolicy -Local
    if(-not$policy){throw'No local AppLocker policy found.'}
    foreach($collection in $policy.RuleCollections){$collection.EnforcementMode=$Mode}
    if($PSCmdlet.ShouldProcess('Local AppLocker policy',"Set enforcement mode $Mode")){
        Set-AppLockerPolicy -PolicyObject $policy
        L "AppLocker mode set to $Mode"
    }
}
Get-AppLockerPolicy -Effective -Xml|Set-Content (Join-Path $OutputPath 'effective-policy-after.xml')
L'Repair workflow finished.'
