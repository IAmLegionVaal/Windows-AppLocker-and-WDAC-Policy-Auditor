# Windows AppLocker and WDAC Policy Auditor

A read-only PowerShell toolkit for collecting AppLocker and Windows Defender Application Control policy, enforcement, event, and service evidence.

## Features

- Effective AppLocker policy export by rule collection
- Local AppLocker policy inventory
- Rule counts, enforcement modes, publishers, paths, and hashes
- Application Identity service state
- AppLocker EXE/DLL, MSI/Script, and Packaged App events
- Code Integrity operational events
- WDAC policy-file inventory and signing metadata
- Device Guard and virtualization-based security context
- CSV, XML, JSON, HTML, and text outputs

## Usage

Run from an elevated PowerShell console:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\src\Get-AppLockerWdacAudit.ps1
```

```powershell
.\src\Get-AppLockerWdacAudit.ps1 -Hours 168 -OutputPath C:\Temp\ApplicationControlAudit
```

## Safety

The toolkit does not create, deploy, merge, convert, enable, disable, or enforce AppLocker or WDAC policies. It does not start services or alter application-control configuration.

## Interpretation

Event evidence should be correlated with policy source, deployment scope, business requirements, and the affected file's publisher or hash before remediation.

## Validation

Test on a device without application-control policies, a lab AppLocker audit-only device, and a WDAC-enabled lab device.

## Author

Dewald Pretorius — L2 IT Support Engineer
