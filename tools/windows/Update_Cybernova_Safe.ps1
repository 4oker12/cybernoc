#Requires -Version 5.1
<#
Local Windows updater for Cybernova.
- Executes from a CMD wrapper.
- Checks the target repo, branch, remote, listeners, worktree and fast-forward.
- Never stops processes, overwrites local changes, installs packages or starts services.
- Does not depend on Vast or any remote machine.
#>
$ErrorActionPreference = 'Stop'
$exitCode = 1
$transcriptStarted = $false
$originalLocation = Get-Location

function Step([int]$Number, [string]$Title) {
    Write-Host ("[{0}/5] {1}" -f $Number, $Title) -ForegroundColor Cyan
}
function GitValue([string[]]$Arguments) {
    $output = @(& git @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw ("GIT_FAILED: git {0} (exit={1})" -f ($Arguments -join ' '), $LASTEXITCODE)
    }
    return ($output -join "`n").Trim()
}
function PortOwners {
    $watched = @(9588, 18732, 18792, 18794, 18795, 18796, 18883, 18884)
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Where-Object { $watched -contains [int]$_.LocalPort })
    $owners = foreach ($listener in $listeners) {
        $pidValue = [int]$listener.OwningProcess
        $owner = Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId={0}" -f $pidValue) -ErrorAction SilentlyContinue
        $moduleName = ''
        if ($owner -and $owner.CommandLine) {
            $match = [regex]::Match([string]$owner.CommandLine, '(?i)\s-m\s+([A-Za-z0-9_.-]+)')
            if ($match.Success) { $moduleName = $match.Groups[1].Value }
        }
        [pscustomobject]@{
            LocalAddress = [string]$listener.LocalAddress
            Port         = [int]$listener.LocalPort
            PID          = $pidValue
            Process      = [string]$owner.Name
            PythonModule = $moduleName
        }
    }
    return $owners
}

try {
    if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA_NOT_SET' }
    $logDir = Join-Path $env:LOCALAPPDATA 'CyberNova\logs'
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $logPath = Join-Path $logDir ("safe-update-{0}-{1}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $PID)
    Start-Transcript -LiteralPath $logPath -ErrorAction Stop | Out-Null
    $transcriptStarted = $true
    Write-Host ("LOG: {0}" -f $logPath)

    Step 1 'REPOSITORY / BRANCH / REMOTE'
    $repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..') -ErrorAction Stop).Path
    Set-Location -LiteralPath $repo
    if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) { throw 'GIT_EXE_NOT_FOUND' }

    $top = GitValue @('rev-parse', '--show-toplevel')
    $expected = [System.IO.Path]::GetFullPath($repo).TrimEnd([char[]]@('\','/'))
    $actual = [System.IO.Path]::GetFullPath($top).TrimEnd([char[]]@('\','/'))
    if ($expected -ine $actual) { throw ("WRONG_REPOSITORY: {0}" -f $actual) }

    $branch = GitValue @('branch', '--show-current')
    if ([string]::IsNullOrWhiteSpace($branch)) { throw 'DETACHED_HEAD: stop, do not update' }
    if ($branch -notmatch '^[A-Za-z0-9._/-]+$') { throw 'UNEXPECTED_BRANCH_NAME' }

    $remote = GitValue @('remote', 'get-url', 'origin')
    if ($remote -notmatch '^(?:https://github\.com/|git@github\.com:)4oker12/cybernoc(?:\.git)?$') {
        throw 'UNEXPECTED_ORIGIN: verify your Git remote manually'
    }
    Write-Host ("REPO: {0}" -f $actual)
    Write-Host ("BRANCH: {0}" -f $branch)
    Write-Host 'REMOTE: verified 4oker12/cybernoc (URL not printed)'

    Step 2 'LISTENING PORTS / OWNER PID'
    $occupied = @(PortOwners)
    if ($occupied.Count -gt 0) {
        $occupied | Sort-Object Port, LocalAddress | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
        throw 'PORT_CONFLICT: stop the identified runtime gracefully (Ctrl+C in its own CMD), then retry. No processes were killed.'
    }
    Write-Host 'PORTS_CLEAR: no watched listeners'

    Step 3 'CLEAN WORKTREE'
    $dirty = @(& git status --porcelain=v1 --untracked-files=normal)
    if ($LASTEXITCODE -ne 0) { throw 'GIT_STATUS_FAILED' }
    if ($dirty.Count -gt 0) {
        $dirty | ForEach-Object { Write-Host $_ }
        throw 'DIRTY_WORKTREE: preserve/stash your edits manually before updating'
    }
    Write-Host 'WORKTREE_CLEAN'

    Step 4 'FETCH / FAST-FORWARD ONLY'
    $fetchSpec = "refs/heads/{0}:refs/remotes/origin/{0}" -f $branch
    & git fetch --no-tags origin $fetchSpec
    if ($LASTEXITCODE -ne 0) { throw ("GIT_FETCH_FAILED: exit {0}" -f $LASTEXITCODE) }

    $remoteRef = "refs/remotes/origin/{0}" -f $branch
    & git merge --ff-only $remoteRef
    if ($LASTEXITCODE -ne 0) { throw ("GIT_FAST_FORWARD_FAILED: exit {0}" -f $LASTEXITCODE) }

    Step 5 'REVISION / FINAL STATUS'
    $head = GitValue @('rev-parse', 'HEAD')
    $upstream = GitValue @('rev-parse', $remoteRef)
    if ($head -ne $upstream) { throw 'REVISION_MISMATCH_AFTER_UPDATE' }
    & git status --short --branch
    if ($LASTEXITCODE -ne 0) { throw 'GIT_FINAL_STATUS_FAILED' }
    & git log -1 --oneline
    if ($LASTEXITCODE -ne 0) { throw 'GIT_FINAL_LOG_FAILED' }

    Write-Host ("SUCCESS: branch {0} at {1}" -f $branch, $head.Substring(0, 12)) -ForegroundColor Green
    Write-Host 'NO SERVICES STOPPED OR STARTED. Recheck ports before starting the updated runtime.'
    $exitCode = 0
}
catch {
    Write-Host ("SAFE_UPDATE_FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host 'No PID was stopped by this script. Read the stage and the log above.'
}
finally {
    Set-Location $originalLocation
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
}
exit $exitCode
