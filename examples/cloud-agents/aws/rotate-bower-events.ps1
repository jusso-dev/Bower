# Rotate C:\ProgramData\BowerEvents\events.jsonl on Windows, which has no logrotate.
# NOT TESTED ON WINDOWS: it was written from the PowerShell documentation and only
# syntax-checked with the PowerShell parser. Try it on a test server first.
#
# Run it as SYSTEM from a scheduled task (see docs/getting-started/aws-cloudwatch-agent.md).
# Keep this script where only administrators can write (for example
# C:\Program Files\BowerEvents\), because SYSTEM runs it.
#
# It renames events.jsonl to events.jsonl.1 (shifting older copies up to $Keep) and creates
# an empty events.jsonl, which inherits the folder's permissions. A writer must open the file
# for each event (as emit_event.py does) or reopen it after rotation. While another process
# holds the file open without delete sharing the rename fails; the script stops and the next
# run tries again, so nothing is lost.
param(
    [string] $Directory = 'C:\ProgramData\BowerEvents',
    [ValidateRange(1, 100)] [int] $Keep = 7
)
$ErrorActionPreference = 'Stop'

$file = Join-Path $Directory 'events.jsonl'
if (-not (Test-Path -LiteralPath $file) -or (Get-Item -LiteralPath $file).Length -eq 0) {
    return
}

Remove-Item -LiteralPath "$file.$Keep" -ErrorAction SilentlyContinue
for ($index = $Keep - 1; $index -ge 1; $index--) {
    if (Test-Path -LiteralPath "$file.$index") {
        Rename-Item -LiteralPath "$file.$index" -NewName "events.jsonl.$($index + 1)"
    }
}

Rename-Item -LiteralPath $file -NewName 'events.jsonl.1'
New-Item -ItemType File -Path $file | Out-Null
