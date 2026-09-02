param (
    [string[]]$Directory = @("C:\Windows"),
    [ValidateRange(1, 20)]
    [int]$Depth = 5,

    [string]$ProbeExecutable = "$env:WINDIR\System32\cmd.exe",
    [string]$ProbeArguments = "/d /c exit 0",

    [ValidateRange(250, 30000)]
    [int]$ExecTimeoutMs = 3000,

    [string]$CsvPath = ".\fkpathprobe.csv",

    [switch]$NoExec,
    [switch]$NoAclEscalation
)

$ErrorActionPreference = "SilentlyContinue"

if (-not $NoExec -and -not (Test-Path -LiteralPath $ProbeExecutable -PathType Leaf)) {
    throw "Probe executable not found: $ProbeExecutable"
}

$currentIdentity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity)
$currentAccount   = $currentIdentity.Name
$currentSid       = $currentIdentity.User

# Access-check approximation:
# - allowSids contains only groups which are actually enabled for role membership.
#   WindowsPrincipal.IsInRole() uses token membership semantics and therefore does
#   not treat DENY_ONLY groups as usable for ALLOW ACEs.
# - denySids contains all token groups, because DENY_ONLY groups still participate
#   in DENY ACE evaluation.
$allowSids = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$denySids  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

[void]$allowSids.Add($currentSid.Value)
[void]$denySids.Add($currentSid.Value)

foreach ($sid in $currentIdentity.Groups) {
    if ($null -eq $sid) { continue }

    [void]$denySids.Add($sid.Value)

    try {
        if ($currentPrincipal.IsInRole($sid)) {
            [void]$allowSids.Add($sid.Value)
        }
    }
    catch {}
}

$probeHash = $null
if (-not $NoExec) {
    try {
        $probeHash = (Get-FileHash -LiteralPath $ProbeExecutable -Algorithm SHA256).Hash
    }
    catch {}
}

function Invoke-DirectoryProbe {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $id = [guid]::NewGuid().ToString('N')
    $writeProbe = Join-Path $Path ".fkpathprobe_$id.tmp"
    $exeProbe   = Join-Path $Path ".fkpathprobe_$id.exe"

    $write      = $false
    $read       = $false
    $delete     = $false
    $copyExe    = $false
    $execute    = $false
    $cleanupExe = $false
    $writeError = $null
    $execError  = $null

    try {
        [System.IO.File]::WriteAllText($writeProbe, "FKPATHPROBE_$id")
        $write = $true
    }
    catch {
        $writeError = $_.Exception.Message
    }

    if ($write) {
        try {
            if ([System.IO.File]::ReadAllText($writeProbe) -eq "FKPATHPROBE_$id") {
                $read = $true
            }
        }
        catch {}

        try {
            Remove-Item -LiteralPath $writeProbe -Force -ErrorAction Stop
            $delete = $true
        }
        catch {}

        if (-not $NoExec) {
            try {
                Copy-Item -LiteralPath $ProbeExecutable -Destination $exeProbe -Force -ErrorAction Stop
                $copyExe = $true
            }
            catch {
                $execError = $_.Exception.Message
            }

            if ($copyExe) {
                $process = $null
                try {
                    $psi = New-Object System.Diagnostics.ProcessStartInfo
                    $psi.FileName = $exeProbe
                    $psi.Arguments = $ProbeArguments
                    $psi.WorkingDirectory = $Path
                    $psi.UseShellExecute = $false
                    $psi.CreateNoWindow = $true

                    $process = [System.Diagnostics.Process]::Start($psi)
                    if ($null -ne $process) {
                        $execute = $true

                        if (-not $process.WaitForExit($ExecTimeoutMs)) {
                            try { $process.Kill() } catch {}
                        }
                    }
                }
                catch {
                    $execError = $_.Exception.Message
                }
                finally {
                    if ($null -ne $process) {
                        try { $process.Dispose() } catch {}
                    }
                }

                try {
                    Remove-Item -LiteralPath $exeProbe -Force -ErrorAction Stop
                    $cleanupExe = $true
                }
                catch {}
            }
        }
    }

    return [PSCustomObject]@{
        Writable       = $write
        Readable       = $read
        Deletable      = $delete
        ProbeCopied    = $copyExe
        Executable     = $execute
        ProbeCleanup   = $cleanupExe
        WriteError     = $writeError
        ExecutionError = $execError
    }
}

function Get-EffectiveControlRights {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.DirectorySecurity]$Acl
    )

    $canWriteDac   = $false
    $canWriteOwner = $false
    $writeDacSource   = $null
    $writeOwnerSource = $null

    # The object owner has the implicit ability to alter the DACL.
    try {
        $ownerSid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier])
        if ($null -ne $ownerSid -and $ownerSid.Value -eq $currentSid.Value) {
            $canWriteDac = $true
            $writeDacSource = "OBJECT_OWNER:$($ownerSid.Value)"
        }
    }
    catch {}

    try {
        $rules = $Acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        )

        $writeDacResolved   = $canWriteDac
        $writeOwnerResolved = $false

        foreach ($rule in $rules) {
            if ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) {
                continue
            }

            $sid = $rule.IdentityReference.Value
            $rights = [System.Security.AccessControl.FileSystemRights]$rule.FileSystemRights
            $isAllow = ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow)
            $isDeny  = ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny)

            # DENY_ONLY groups are intentionally eligible only here, not for ALLOW.
            $sidApplies = if ($isAllow) { $allowSids.Contains($sid) } else { $denySids.Contains($sid) }
            if (-not $sidApplies) { continue }

            if (-not $writeDacResolved -and ($rights -band [System.Security.AccessControl.FileSystemRights]::ChangePermissions)) {
                $writeDacResolved = $true
                $canWriteDac = $isAllow
                $writeDacSource = "$(if ($isAllow) {'ALLOW'} else {'DENY'}):$sid"
            }

            if (-not $writeOwnerResolved -and ($rights -band [System.Security.AccessControl.FileSystemRights]::TakeOwnership)) {
                $writeOwnerResolved = $true
                $canWriteOwner = $isAllow
                $writeOwnerSource = "$(if ($isAllow) {'ALLOW'} else {'DENY'}):$sid"
            }

            if ($writeDacResolved -and $writeOwnerResolved) {
                break
            }
        }
    }
    catch {}

    return [PSCustomObject]@{
        WriteDac        = $canWriteDac
        WriteOwner      = $canWriteOwner
        WriteDacSource  = $writeDacSource
        WriteOwnerSource = $writeOwnerSource
    }
}

function Grant-CurrentUserModify {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    # Only called for pre-filtered WRITE_DAC candidates, so spawning icacls here
    # is cheap. Unlike Set-Acl, icacls /grant changes the DACL specifically and
    # gives us a useful native error if Windows rejects the mutation.
    $grant = "${currentAccount}:(M)"
    $output = & icacls.exe $Path /grant $grant /Q 2>&1
    $exitCode = $LASTEXITCODE

    return [PSCustomObject]@{
        Success = ($exitCode -eq 0)
        Detail  = (($output | Out-String).Trim())
    }
}

function Set-CurrentUserOwner {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $output = & icacls.exe $Path /setowner $currentAccount /Q 2>&1
    $exitCode = $LASTEXITCODE

    return [PSCustomObject]@{
        Success = ($exitCode -eq 0)
        Detail  = (($output | Out-String).Trim())
    }
}

Write-Host ""
Write-Host "fkpathprobe" -ForegroundColor Cyan
Write-Host "-----------" -ForegroundColor DarkGray
Write-Host "Roots       : $($Directory -join ', ')"
Write-Host "Depth       : $Depth"
Write-Host "User        : $currentAccount"

if (-not $NoExec) {
    Write-Host "Probe       : $ProbeExecutable"
    Write-Host "Probe SHA256: $probeHash"
}

if ($NoAclEscalation) {
    Write-Host "ACL probing : disabled"
}
else {
    Write-Host "ACL probing : token-filtered + practical mutation; successful changes are PERSISTENT" -ForegroundColor Yellow
}

Write-Host ""

$folders = foreach ($root in $Directory) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        Write-Host "[NOT FOUND] $root" -ForegroundColor DarkYellow
        continue
    }

    Get-Item -LiteralPath $root -ErrorAction SilentlyContinue

    Get-ChildItem `
        -LiteralPath $root `
        -Directory `
        -Recurse `
        -Depth ($Depth - 1) `
        -Force `
        -ErrorAction SilentlyContinue
}

$folders = $folders |
    Where-Object { $_ } |
    Sort-Object FullName -Unique

Write-Host "Found $($folders.Count) directories."
Write-Host ""

$results = New-Object 'System.Collections.Generic.List[object]'
$processed = 0
$aclCandidates = 0
$aclRejected = 0

foreach ($folder in $folders) {
    $processed++
    $path = $folder.FullName

    # Fast path first. Already-writable directories do not need ACL parsing.
    $initialProbe = Invoke-DirectoryProbe -Path $path

    $candidateWriteDac   = $false
    $candidateWriteOwner = $false
    $writeDacSource      = $null
    $writeOwnerSource    = $null

    $aclGrantAttempted    = $false
    $aclGrantSucceeded    = $false
    $aclGrantError        = $null
    $ownerChangeAttempted = $false
    $ownerChangeSucceeded = $false
    $ownerChangeError     = $null
    $escalationMethod     = $null
    $aclOutcome           = $null
    $finalProbe           = $initialProbe

    $originalOwner = $null
    $originalSddl  = $null
    $finalOwner    = $null
    $finalSddl     = $null

    if (-not $initialProbe.Writable -and -not $NoAclEscalation) {
        $acl = $null

        try {
            $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
            $originalOwner = $acl.Owner
            $originalSddl  = $acl.Sddl
        }
        catch {}

        if ($null -ne $acl) {
            $control = Get-EffectiveControlRights -Acl $acl
            $candidateWriteDac   = $control.WriteDac
            $candidateWriteOwner = $control.WriteOwner
            $writeDacSource      = $control.WriteDacSource
            $writeOwnerSource    = $control.WriteOwnerSource

            if ($candidateWriteDac -or $candidateWriteOwner) {
                $aclCandidates++
                Write-Host "[ACL CANDIDATE] $path  WDAC=$candidateWriteDac WO=$candidateWriteOwner" -ForegroundColor DarkMagenta

                if ($candidateWriteDac) {
                    Write-Host "                WRITE_DAC source: $writeDacSource" -ForegroundColor DarkGray
                }
                if ($candidateWriteOwner) {
                    Write-Host "                WRITE_OWNER source: $writeOwnerSource" -ForegroundColor DarkGray
                }
            }

            if ($candidateWriteDac) {
                $aclGrantAttempted = $true
                $grantResult = Grant-CurrentUserModify -Path $path

                if ($grantResult.Success) {
                    $aclGrantSucceeded = $true
                    $escalationMethod = 'DACL'
                    $aclOutcome = 'DACL mutation succeeded'
                    Write-Host "[ACL APPLIED]   $path  granted Modify to $currentAccount" -ForegroundColor Magenta
                }
                else {
                    $aclGrantError = $grantResult.Detail
                    $aclOutcome = 'DACL candidate rejected by practical mutation'
                    $aclRejected++
                    Write-Host "[ACL REJECTED]  $path  DACL change failed: $aclGrantError" -ForegroundColor DarkYellow
                }
            }

            if (-not $aclGrantSucceeded -and $candidateWriteOwner) {
                $ownerChangeAttempted = $true
                $ownerResult = Set-CurrentUserOwner -Path $path

                if ($ownerResult.Success) {
                    $ownerChangeSucceeded = $true
                    $escalationMethod = 'OWNER'
                    Write-Host "[OWNER APPLIED] $path  owner changed to $currentAccount" -ForegroundColor Magenta

                    $aclGrantAttempted = $true
                    $grantAfterOwner = Grant-CurrentUserModify -Path $path

                    if ($grantAfterOwner.Success) {
                        $aclGrantSucceeded = $true
                        $escalationMethod = 'OWNER+DACL'
                        $aclOutcome = 'Owner mutation succeeded; DACL mutation succeeded'
                        Write-Host "[ACL APPLIED]   $path  granted Modify after owner change" -ForegroundColor Magenta
                    }
                    else {
                        $aclGrantError = $grantAfterOwner.Detail
                        $aclOutcome = 'Owner mutation succeeded; DACL mutation failed'
                        Write-Host "[ACL REJECTED]  $path  owner changed, but Modify grant failed: $aclGrantError" -ForegroundColor DarkYellow
                    }
                }
                else {
                    $ownerChangeError = $ownerResult.Detail
                    if (-not $aclOutcome) {
                        $aclOutcome = 'WRITE_OWNER candidate rejected by practical mutation'
                        $aclRejected++
                    }
                    Write-Host "[OWNER REJECTED] $path  owner change failed: $ownerChangeError" -ForegroundColor DarkYellow
                }
            }

            if ($aclGrantSucceeded -or $ownerChangeSucceeded) {
                $finalProbe = Invoke-DirectoryProbe -Path $path

                try {
                    $finalAcl = Get-Acl -LiteralPath $path -ErrorAction Stop
                    $finalOwner = $finalAcl.Owner
                    $finalSddl  = $finalAcl.Sddl
                }
                catch {}

                if ($finalProbe.Writable) {
                    Write-Host "[ACL VERIFIED]  $path  write succeeded after ACL/owner mutation" -ForegroundColor Green
                }
                else {
                    Write-Host "[ACL UNVERIFIED] $path  mutation succeeded but write still failed: $($finalProbe.WriteError)" -ForegroundColor DarkYellow
                }
            }
        }
    }

    $interesting = (
        $initialProbe.Writable -or
        $candidateWriteDac -or
        $candidateWriteOwner -or
        $aclGrantSucceeded -or
        $ownerChangeSucceeded -or
        $finalProbe.Writable
    )

    if (-not $interesting) {
        if (($processed % 500) -eq 0) {
            Write-Host "Processed $processed/$($folders.Count)..." -ForegroundColor DarkGray
        }
        continue
    }

    $result = [PSCustomObject]@{
        Path                    = $path
        InitiallyWritable       = $initialProbe.Writable
        InitiallyExecutable     = $initialProbe.Executable

        CandidateWriteDac       = $candidateWriteDac
        WriteDacSource          = $writeDacSource
        CandidateWriteOwner     = $candidateWriteOwner
        WriteOwnerSource        = $writeOwnerSource

        AclGrantAttempted       = $aclGrantAttempted
        AclGrantSucceeded       = $aclGrantSucceeded
        OwnerChangeAttempted    = $ownerChangeAttempted
        OwnerChangeSucceeded    = $ownerChangeSucceeded
        EscalationMethod        = $escalationMethod
        AclOutcome              = $aclOutcome

        Writable                = $finalProbe.Writable
        Readable                = $finalProbe.Readable
        Deletable               = $finalProbe.Deletable
        ProbeCopied             = $finalProbe.ProbeCopied
        Executable              = $finalProbe.Executable

        OriginalOwner           = $originalOwner
        OriginalSDDL            = $originalSddl
        FinalOwner              = $finalOwner
        FinalSDDL               = $finalSddl

        ProbeSHA256             = $probeHash
        ProbeCleanup            = $finalProbe.ProbeCleanup
        WriteError              = $finalProbe.WriteError
        ExecutionError          = $finalProbe.ExecutionError
        AclGrantError           = $aclGrantError
        OwnerChangeError        = $ownerChangeError
    }

    $results.Add($result)

    if (-not $initialProbe.Writable -and $aclGrantSucceeded -and $finalProbe.Executable) {
        Write-Host "[$escalationMethod -> WRITE + EXEC] $path" -ForegroundColor Magenta
    }
    elseif (-not $initialProbe.Writable -and $aclGrantSucceeded -and $finalProbe.Writable) {
        Write-Host "[$escalationMethod -> WRITE ONLY]   $path" -ForegroundColor Magenta
    }
    elseif ($initialProbe.Executable) {
        Write-Host "[WRITE + EXEC] $path" -ForegroundColor Red
    }
    elseif ($initialProbe.ProbeCopied) {
        Write-Host "[WRITE ONLY]   $path" -ForegroundColor Yellow
    }
    elseif ($initialProbe.Writable) {
        Write-Host "[WRITABLE]     $path" -ForegroundColor DarkYellow
    }
}

$results |
    Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Finished." -ForegroundColor Cyan
Write-Host "Scanned                    : $($folders.Count)"
Write-Host "ACL-control candidates     : $aclCandidates"
Write-Host "ACL candidates rejected    : $aclRejected"
Write-Host "Initially writable         : $(($results | Where-Object InitiallyWritable).Count)"
Write-Host "DACL grant succeeded       : $(($results | Where-Object AclGrantSucceeded).Count)"
Write-Host "Owner change succeeded     : $(($results | Where-Object OwnerChangeSucceeded).Count)"
Write-Host "Final writable             : $(($results | Where-Object Writable).Count)"
Write-Host "Final writable+executable  : $(($results | Where-Object Executable).Count)"
Write-Host "Results                     : $CsvPath"

if (-not $NoAclEscalation) {
    Write-Host ""
    Write-Host "Legend:" -ForegroundColor Cyan
    Write-Host "  ACL CANDIDATE = ACL/token analysis suggests WRITE_DAC/WRITE_OWNER; NOT proof." -ForegroundColor DarkGray
    Write-Host "  ACL APPLIED   = Windows accepted the persistent permission/owner change." -ForegroundColor DarkGray
    Write-Host "  ACL VERIFIED  = write probe succeeded after that change; practical proof." -ForegroundColor DarkGray
    Write-Host "  ACL REJECTED  = pre-filter looked interesting, but Windows rejected mutation." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Successful ACL/owner changes were NOT reverted." -ForegroundColor Yellow
    Write-Host "Original Owner and SDDL are stored in the CSV for evidence/manual rollback." -ForegroundColor Yellow
}
