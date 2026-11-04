$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$testDir = Join-Path ([System.IO.Path]::GetTempPath()) ('bower-position-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDir | Out-Null
$fakeProbe = Join-Path $testDir 'fake-probe.ps1'
function Set-FakeProbe([string]$Payload, [int]$ExitCode = 0) {
    $quoted = $Payload.Replace("'", "''")
    Set-Content -LiteralPath $fakeProbe -Encoding UTF8 -Value ("`$global:LASTEXITCODE = $ExitCode`nWrite-Output '$quoted'")
}
try {
    foreach ($relative in @('wecfix/wec-agent.ps1', 'soak/wec-agent.ps1')) {
        $path = Join-Path $root $relative
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        if ($errors.Count) { throw "Parser failed for $relative" }
        foreach ($name in @('Get-ReceivingBookmarkRecordId', 'Get-ReceivingPositionState')) {
            $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $name }, $true)
            if ($null -eq $definition) { throw "Position helper missing from $relative" }
            . ([scriptblock]::Create($definition.Extent.Text))
        }

        # No BookmarkXml property is exposed here, matching Windows PowerShell 5.1;
        # only the probe's receiving position is trusted, even when origin IDs differ.
        foreach ($case in @(@{ Origin = 7; Computer = 'source-a'; Receiving = 900 },
                            @{ Origin = 7; Computer = 'source-b'; Receiving = 901 },
                            @{ Origin = 12500; Computer = 'source-c'; Receiving = 902 })) {
            # The fixed probe protocol carries only the receiving position, never origin data.
            $payload = '{"kind":"receiving-position","channel":"ForwardedEvents","newestRecordId":' + $case.Receiving + '}'
            Set-FakeProbe $payload
            $actual = Get-ReceivingBookmarkRecordId $fakeProbe 'ForwardedEvents'
            if ($actual -ne $case.Receiving) { throw "Wrong receiving record ID from $relative" }
        }
        foreach ($payload in @('', '{bad', '{"kind":"other","channel":"ForwardedEvents","newestRecordId":5}',
            '{"kind":"receiving-position","channel":"Security","newestRecordId":5}',
            '{"kind":"receiving-position","channel":"ForwardedEvents","newestRecordId":"5"}',
            '{"kind":"receiving-position","channel":"ForwardedEvents","newestRecordId":0}',
            '{"kind":"wrong","kind":"receiving-position","channel":"ForwardedEvents","newestRecordId":5}',
            '{"kind":"receiving-position","channel":"wrong","channel":"ForwardedEvents","newestRecordId":5}',
            '{"kind":"receiving-position","channel":"ForwardedEvents","newestRecordId":4,"newestRecordId":5}',
            '{"kind":"receiving-position","channel":"ForwardedEvents","newestRecordId":5,"extra":true}',
            '{"ki\u006ed":"receiving-position","channel":"ForwardedEvents","newestRecordId":5}',
            '{"kind":"receiving-position","channel":"ForwardedEvents","newestRecordId":9223372036854775808}',
            '{"kind":"receiving-position","channel":"ForwardedEvents","newestRecordId":05}',
            '{"kind":"receiving-position","channel":"ForwardedEvents","newestRecordId":5.0}',
            (' ' * 513))) {
            Set-FakeProbe $payload
            if ($null -ne (Get-ReceivingBookmarkRecordId $fakeProbe 'ForwardedEvents')) {
                throw "Invalid probe result accepted by $relative"
            }
        }
        Set-FakeProbe '{"kind":"receiving-position","channel":"ForwardedEvents","newestRecordId":5}' 1
        $failedPosition = Get-ReceivingBookmarkRecordId $fakeProbe 'ForwardedEvents'
        if ($null -ne $failedPosition) { throw "Failed probe accepted by $relative" }
        if ((Get-ReceivingPositionState 7 $failedPosition) -cne 'missing-bookmark-with-records') { throw "Missing bookmark not reported by $relative" }
        if ((Get-ReceivingPositionState 0 $null) -cne 'unknown') { throw "Empty log misreported by $relative" }
        if ((Get-ReceivingPositionState 7 900) -cne 'observed') { throw "Valid bookmark misreported by $relative" }
        if ((Get-ReceivingPositionState 7 'not-an-id') -cne 'missing-bookmark-with-records') { throw "Invalid bookmark misreported by $relative" }

        # On Windows CI, compare the probe against a real local (not forwarded) event.
        # This verifies the PowerShell 5.1 invocation, not live WEF/WEC forwarding.
        if ($env:OS -eq 'Windows_NT' -and $env:BOWER_LAB_PROBE_PATH) {
            $channel = $null; $info = $null
            foreach ($candidate in @('Application', 'System')) {
                try {
                    $candidateInfo = Get-WinEvent -ListLog $candidate -ErrorAction Stop
                    if ($candidateInfo.RecordCount -gt 0) { $channel = $candidate; $info = $candidateInfo; break }
                } catch { continue }
            }
            if ($null -eq $channel) { throw 'No nonempty local event log available for native probe test' }
            $event = Get-WinEvent -LogName $channel -MaxEvents 1 -ErrorAction Stop
            try {
                $native = Get-ReceivingBookmarkRecordId $env:BOWER_LAB_PROBE_PATH $channel
                if ($null -eq $event.RecordId -or $null -eq $native -or $native -lt $event.RecordId) {
                    throw "Native receiving position unavailable for $channel"
                }
                $missing = Get-ReceivingBookmarkRecordId (Join-Path $testDir 'missing-probe.exe') $channel
                if ((Get-ReceivingPositionState $info.RecordCount $missing) -cne 'missing-bookmark-with-records') {
                    throw 'Nonempty native log did not report a missing bookmark'
                }
            } finally { $event.Dispose() }
        }
        Write-Output "$relative receiving-position tests passed"
    }
} finally { Remove-Item -LiteralPath $testDir -Recurse -Force -ErrorAction SilentlyContinue }
