# Requires an elevated Windows host with the Storage module and diskpart.
# Each case owns one temporary VHD and mounts it into a directory, never a drive letter.
BeforeDiscovery {
    $script:WindowsVolumeHost = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    $script:VolumeShells = @(@{ Shell = 'pwsh' }, @{ Shell = 'powershell.exe' })
}

Describe 'Queue disk space on an NTFS directory mount under <Shell>' -ForEach $script:VolumeShells -Skip:(-not $script:WindowsVolumeHost) {
    BeforeAll {
        $script:VolumeCheck = Join-Path $PSScriptRoot 'Test-BowerCollectorHealth.ps1'
    }

    It 'measures the mounted volume for directories and database files and fails closed for a missing parent' {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            $principal = [Security.Principal.WindowsPrincipal]::new($identity)
            $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) | Should -BeTrue
        } finally {
            $identity.Dispose()
        }
        foreach ($command in @('diskpart.exe', 'Get-DiskImage', 'Mount-DiskImage', 'Dismount-DiskImage', 'Get-Disk',
                'Initialize-Disk', 'New-Partition', 'Format-Volume', 'Add-PartitionAccessPath', 'Remove-PartitionAccessPath', 'Get-Volume', $Shell)) {
            Get-Command $command -ErrorAction Stop | Should -Not -BeNullOrEmpty
        }

        $ownedRoot = Join-Path $TestDrive ('bower-volume-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $ownedRoot
        $imagePath = Join-Path $ownedRoot 'queue-volume.vhdx'
        $mountPath = (Join-Path $ownedRoot 'mounted') + [IO.Path]::DirectorySeparatorChar
        $diskpartPath = Join-Path $ownedRoot 'create-vhd.txt'
        $probePath = Join-Path $ownedRoot 'probe.ps1'
        $partition = $null
        $mountAdded = $false
        try {
            # diskpart creates only this named image. All partition operations below receive
            # the disk returned for this exact image, never a broad disk selection.
            if ($imagePath -match '["\r\n]' -or $imagePath -match '[^\x00-\x7F]') {
                throw 'The isolated diskpart fixture requires an ASCII path without quotes or newlines.'
            }
            Set-Content -LiteralPath $diskpartPath -Encoding Ascii -Value @(
                "create vdisk file=`"$imagePath`" maximum=256 type=expandable"
                'exit'
            )
            $null = & diskpart.exe /s $diskpartPath
            $LASTEXITCODE | Should -Be 0
            Test-Path -LiteralPath $imagePath -PathType Leaf | Should -BeTrue

            $image = Mount-DiskImage -ImagePath $imagePath -NoDriveLetter -Access ReadWrite -PassThru -ErrorAction Stop
            $image.ImagePath | Should -Be $imagePath
            $disks = @($image | Get-Disk -ErrorAction Stop)
            $disks.Count | Should -Be 1
            $disk = $disks[0]
            $disk.IsBoot | Should -BeFalse
            $disk.IsSystem | Should -BeFalse
            $disk.PartitionStyle | Should -Be 'RAW'
            $disk.Size | Should -Be (256MB)
            $disk = Initialize-Disk -InputObject $disk -PartitionStyle GPT -PassThru -ErrorAction Stop
            $partition = New-Partition -InputObject $disk -UseMaximumSize -ErrorAction Stop
            $volume = Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel 'BowerCiQueue' -Confirm:$false -ErrorAction Stop
            $null = New-Item -ItemType Directory -Path $mountPath
            Add-PartitionAccessPath -InputObject $partition -AccessPath $mountPath -ErrorAction Stop
            $mountAdded = $true
            @($partition.AccessPaths | Where-Object { $_ -match '^[A-Za-z]:\\$' }).Count | Should -Be 0

            $volume.Size | Should -BeGreaterThan (128MB)
            $volume.Size | Should -BeLessOrEqual (256MB)
            $backingSize = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($imagePath)).TotalSize
            $backingSize | Should -BeGreaterThan (2 * $volume.Size)

            # Extract the production function instead of maintaining a second disk probe.
            $tokens = $null; $parseErrors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($script:VolumeCheck, [ref] $tokens, [ref] $parseErrors)
            $parseErrors.Count | Should -Be 0
            $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-QueueDiskSpace' }, $true)
            $function | Should -Not -BeNullOrEmpty
            $probe = 'param([string] $QueuePath)' + "`n" + $function.Extent.Text + @'

try {
    $space = Get-QueueDiskSpace $QueuePath
    [pscustomobject]@{ total = $space.TotalSize; available = $space.AvailableFreeSpace } | ConvertTo-Json -Compress
} catch {
    [pscustomobject]@{ errorType = $_.Exception.GetType().FullName; hresult = $_.Exception.HResult } | ConvertTo-Json -Compress
    exit 1
}
'@
            Set-Content -LiteralPath $probePath -Encoding Ascii -Value $probe
            $queueDirectory = Join-Path $mountPath 'queue'
            $null = New-Item -ItemType Directory -Path $queueDirectory
            $databasePath = Join-Path $queueDirectory 'queue.db'
            $null = New-Item -ItemType File -Path $databasePath
            foreach ($queuePath in @($mountPath, $queueDirectory, $databasePath)) {
                $raw = & $Shell -NoProfile -ExecutionPolicy Bypass -File $probePath -QueuePath $queuePath
                $LASTEXITCODE | Should -Be 0 -Because 'the real probe must resolve the mounted NTFS volume'
                $space = ($raw -join "`n") | ConvertFrom-Json
                # Storage and Win32 report usable NTFS capacity; allow at most 1 MiB of
                # accounting difference, far below the difference from the backing drive.
                [math]::Abs([double] $space.total - [double] $volume.Size) | Should -BeLessOrEqual (1MB)
                $space.total | Should -BeLessThan $backingSize
                $space.available | Should -BeGreaterThan 0
                $space.available | Should -BeLessOrEqual $space.total
            }

            $missingPath = Join-Path (Join-Path $mountPath 'missing-parent') 'queue.db'
            $raw = & $Shell -NoProfile -ExecutionPolicy Bypass -File $probePath -QueuePath $missingPath
            $LASTEXITCODE | Should -Be 1 -Because 'a missing queue parent must fail rather than fall back to the backing drive'
            $failure = ($raw -join "`n") | ConvertFrom-Json
            $failure.errorType | Should -Not -BeNullOrEmpty
            $failure.PSObject.Properties.Name | Should -Not -Contain 'total'
        } finally {
            # Even assertion/setup failures must release this case's mount and image.
            # Never recurse through a mount point or target an unrelated disk.
            try {
                if ($mountAdded) {
                    Remove-PartitionAccessPath -InputObject $partition -AccessPath $mountPath -ErrorAction Stop
                }
            } finally {
                if (Test-Path -LiteralPath $imagePath) {
                    $image = Get-DiskImage -ImagePath $imagePath -ErrorAction Stop
                    if ($image.Attached) {
                        Dismount-DiskImage -ImagePath $imagePath -ErrorAction Stop
                    }
                    (Get-DiskImage -ImagePath $imagePath -ErrorAction Stop).Attached | Should -BeFalse
                    Remove-Item -LiteralPath $imagePath -Force -ErrorAction Stop
                }
                if (Test-Path -LiteralPath $mountPath) { Remove-Item -LiteralPath $mountPath -Force -ErrorAction Stop }
                foreach ($file in @($diskpartPath, $probePath)) {
                    if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force -ErrorAction Stop }
                }
                Remove-Item -LiteralPath $ownedRoot -Force -ErrorAction Stop
            }
        }
    }
}
