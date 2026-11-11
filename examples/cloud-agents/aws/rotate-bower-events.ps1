# Rotate C:\ProgramData\BowerEvents\events.jsonl on Windows, which has no logrotate.
# test_windows_event_folder.ps1 runs it on a Windows Server CI runner, from the guide's
# scheduled task as SYSTEM.
#
# Run it as SYSTEM from a scheduled task (see docs/getting-started/aws-cloudwatch-agent.md).
# Keep this script where only administrators can write (for example
# C:\Program Files\BowerEvents\), because SYSTEM runs it.
#
# It renames events.jsonl to events.jsonl.1 (shifting older copies up to $Keep) and creates
# an empty events.jsonl, which inherits the folder's permissions. A writer must open the file
# for each event (as emit_event.py does) or reopen it after rotation.
#
# The live file is renamed first. While another process holds it open without delete
# sharing, that rename fails and the script stops before touching the older copies, so the
# next run tries again and nothing is lost. A run cut short later leaves events.jsonl.rotating,
# which the next run finishes.
param(
    [string] $Directory = 'C:\ProgramData\BowerEvents',
    [ValidateRange(1, 100)] [int] $Keep = 7
)
$ErrorActionPreference = 'Stop'

$file = Join-Path $Directory 'events.jsonl'
$rotating = "$file.rotating"
if (-not (Test-Path -LiteralPath $rotating)) {
    if (-not (Test-Path -LiteralPath $file) -or (Get-Item -LiteralPath $file).Length -eq 0) {
        return
    }

    Rename-Item -LiteralPath $file -NewName 'events.jsonl.rotating'
}

# Recreate the live file straight away, so writers that open it for each event carry on.
if (-not (Test-Path -LiteralPath $file)) {
    New-Item -ItemType File -Path $file | Out-Null
}

Remove-Item -LiteralPath "$file.$Keep" -ErrorAction SilentlyContinue
for ($index = $Keep - 1; $index -ge 1; $index--) {
    if (Test-Path -LiteralPath "$file.$index") {
        Rename-Item -LiteralPath "$file.$index" -NewName "events.jsonl.$($index + 1)"
    }
}

Rename-Item -LiteralPath $rotating -NewName 'events.jsonl.1'
