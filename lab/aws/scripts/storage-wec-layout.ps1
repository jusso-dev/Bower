# Storage-pressure lab: move the WEC collector's queue to the recommended Windows layout.
# The dedicated volume is mounted at %ProgramData%\Bower\state, so the MSI's default
# BOWER_QUEUE_PATH (rewritten on every upgrade) stays on the dedicated volume.
$ErrorActionPreference = 'Stop'
if ($env:BOWER_LAB_RUN -notmatch '^bower-ws3-\d{8}-\d{6}$') { throw 'Unexpected run id' }
$state = 'C:\ProgramData\Bower\state'
$partition = Get-Partition -DriveLetter Q
if ($partition.AccessPaths -notcontains "$state\") {
    Stop-Service Bower
    foreach ($item in Get-ChildItem $state -Force) { Move-Item $item.FullName 'Q:\' -Force }
    foreach ($item in Get-ChildItem 'Q:\bower' -Force -ErrorAction SilentlyContinue) { Move-Item $item.FullName 'Q:\' -Force }
    Remove-Item 'Q:\bower' -Force -ErrorAction SilentlyContinue
    Add-PartitionAccessPath -InputObject $partition -AccessPath "$state\"
}
# The mount point's own ACL is not the volume's: set the state-folder rights on the
# volume root (and everything already on it), or the service cannot write the WAL.
# Never combine /inheritance:r with /T: it strips the inherited entries from existing
# files and leaves them with an empty ACL (seen in this lab; repaired with takeown and
# icacls /reset).
icacls 'Q:\' /grant 'NT SERVICE\Bower:(OI)(CI)M' /Q | Out-Null
icacls 'Q:\' /remove:g 'BUILTIN\Users' 'Everyone' 'CREATOR OWNER' /Q | Out-Null
$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bower'
$environment = @((Get-ItemProperty $key).Environment | Where-Object { $_ -notmatch '^BOWER_QUEUE_PATH=' }) + "BOWER_QUEUE_PATH=$state\queue.db"
Set-ItemProperty $key -Name Environment -Type MultiString -Value $environment
Start-Service Bower
$token = (Get-Content 'C:\ProgramData\Bower\secrets\ingest-token' -Raw).Trim()
Start-Sleep 5
$status = Invoke-RestMethod 'http://127.0.0.1:4319/v1/status' -Headers @{ Authorization = "Bearer $token" }
[ordered]@{ phase = 'wec-layout'; accessPaths = @((Get-Partition -DriveLetter Q).AccessPaths)
    queueFiles = @(Get-ChildItem $state -Filter 'queue.db*' | Select-Object Name, Length)
    systemDriveFreeBytes = (Get-Volume -DriveLetter C).SizeRemaining
    storage = $status.storage | Select-Object state, freeBytes, totalBytes, queueFileBytes
    queue = $status.queue } | ConvertTo-Json -Depth 4 -Compress
