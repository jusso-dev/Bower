# Pester 5 tests for Test-BowerCollectorHealth.ps1. Every end-to-end case runs the script under
# each available host: PowerShell 7 (pwsh) everywhere, and Windows PowerShell 5.1 on Windows.
#   pwsh -NoProfile -Command "Invoke-Pester -Path deploy/sentinel/monitoring/host -Output Detailed"
BeforeDiscovery {
    $script:Hosts = @(@{ Shell = 'pwsh' })
    if (($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) -and (Get-Command powershell.exe -ErrorAction SilentlyContinue)) {
        $script:Hosts += @{ Shell = 'powershell.exe' }
    }
}

BeforeAll {
    $script:Check = Join-Path $PSScriptRoot 'Test-BowerCollectorHealth.ps1'
    $script:Token = 'test-token-never-printed'

    # A loopback collector whose /v1/status body and status code can change between runs.
    function Initialize-FakeCollector {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = $listener.LocalEndpoint.Port
        $listener.Stop()
        $http = [System.Net.HttpListener]::new()
        $http.Prefixes.Add("http://127.0.0.1:$port/")
        $http.Start()
        $shared = [hashtable]::Synchronized(@{ Body = '{}'; Code = 200; Health = 'healthy'; Redirect = $null; StatusRequests = 0 })
        $runspace = [powershell]::Create()
        $null = $runspace.AddScript({
                param($Http, $Shared, $Token)
                while ($Http.IsListening) {
                    try { $context = $Http.GetContext() } catch { break }
                    $path = $context.Request.Url.AbsolutePath
                    if ($path -eq '/health') { $text = '{"status":"' + $Shared.Health + '"}'; $code = 200 }
                    elseif ($path -eq '/v1/status' -and $context.Request.Headers['Authorization'] -eq "Bearer $Token") {
                        $Shared.StatusRequests++
                        if ($Shared.Redirect) { $context.Response.RedirectLocation = $Shared.Redirect; $text = '{}'; $code = 302 }
                        else { $text = $Shared.Body; $code = $Shared.Code }
                    }
                    else { $text = '{}'; $code = 401 }
                    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
                    $context.Response.StatusCode = $code
                    $context.Response.ContentType = 'application/json'
                    $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                    $context.Response.Close()
                }
            }).AddArgument($http).AddArgument($shared).AddArgument($script:Token)
        $null = $runspace.BeginInvoke()
        return [pscustomobject]@{ Url = "http://127.0.0.1:$port"; Http = $http; Runspace = $runspace; Shared = $shared }
    }

    function Stop-FakeCollector($Collector) {
        $Collector.Http.Stop()
        $Collector.Runspace.Dispose()
    }

    function New-Status([hashtable] $Overrides = @{}) {
        $status = [ordered]@{
            status = 'healthy'
            queue = @{ queued = 0; retrying = 0; uploading = 0; deadLettered = 0; undeliveredBytes = 0; oldestUndelivered = $null }
            # Seven fractional digits and an offset, as the collector writes them.
            intake = @{ observedSince = '2026-10-31T08:00:00.1234567+00:00'; capacityRefusals = 0; privacyAlertRefusals = 0; lastRefusalAt = $null }
            syslog = @(@{ id = 'firewall-tls'; tlsHandshakeFailures = 1; connectionsAccepted = 1 })
            windowsEventLog = @(@{ id = 'forwarded-security'; state = 'running'; readErrors = 0; malformed = 0; oversized = 0 })
        }
        foreach ($key in $Overrides.Keys) { $status[$key] = $Overrides[$key] }
        return ($status | ConvertTo-Json -Depth 6)
    }

    function Invoke-Check([string] $Shell, [string] $Url, [string[]] $Extra = @()) {
        $tokenFile = Join-Path $TestDrive 'token'
        Set-Content -LiteralPath $tokenFile -Value $script:Token
        $output = & $Shell -NoProfile -ExecutionPolicy Bypass -File $script:Check -Url $Url -TokenFile $tokenFile `
            -QueuePath (Join-Path $TestDrive 'queue.db') -DiskWarningPercent 0 -DiskCriticalPercent 0 -Format Json @Extra
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = ($output -join "`n") }
    }

    function Get-FindingCodes($Result) {
        try { return @((($Result.Output | ConvertFrom-Json).findings).code) -join ',' }
        catch { return 'non-json-output' }
    }
}

Describe 'Test-BowerCollectorHealth on <Shell>' -ForEach $script:Hosts {
    It 'reads the queue volume in a fresh process' {
        $tokens = $null; $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Check, [ref] $tokens, [ref] $parseErrors)
        $function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-QueueDiskSpace' }, $true)
        $function | Should -Not -BeNullOrEmpty
        $probe = Join-Path $TestDrive 'disk-probe.ps1'
        $probeSource = $function.Extent.Text + @'

try {
    $disk = Get-QueueDiskSpace $args[0]
    if ($disk.TotalSize -le 0) { throw 'Invalid volume size' }
    'ok'
} catch {
    $exception = $_.Exception
    while ($null -ne $exception) {
        '{0} HRESULT={1}' -f $exception.GetType().FullName, $exception.HResult
        $exception = $exception.InnerException
    }
    'Win32Error={0}' -f [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    exit 1
}
'@
        Set-Content -LiteralPath $probe -Value $probeSource
        $diagnostic = & $Shell -NoProfile -ExecutionPolicy Bypass -File $probe (Join-Path $TestDrive 'queue.db')
        $LASTEXITCODE | Should -Be 0 -Because ("disk probe: " + ($diagnostic -join ', '))
    }

    It 'rejects unsafe initial URLs before requests' {
        foreach ($url in @('http://example.com', 'http://localhost', 'http://127.1', 'http://127.0.0.1.evil',
                           'http://127.0.0.1@evil', 'https://user@example.com', 'https://example.com?x=y')) {
            $result = Invoke-Check $Shell $url
            $result.Code | Should -Be 3
            $result.Output | Should -Match '^UNKNOWN: monitoring URL'
        }
    }

    It 'warns about existing source errors when there is no baseline' {
        $collector = Initialize-FakeCollector
        $collector.Shared.Body = New-Status @{ windowsEventLog = @(@{ id = 'wec'; state = 'running'; readErrors = 1 }) }
        try { $result = Invoke-Check $Shell $collector.Url }
        finally { Stop-FakeCollector $collector }
        $report = $result.Output | ConvertFrom-Json
        $result.Code | Should -Be 1 -Because ("finding codes: " + (Get-FindingCodes $result))
        @($report.findings.code) | Should -Contain 'syslog-errors'
        @($report.findings.code) | Should -Contain 'windows-event-log'
        @($report.findings | Where-Object { $_.detail -match 'baseline unavailable' }).Count | Should -Be 2
    }

    It 'does not forward the bearer token across redirects' {
        $collector = Initialize-FakeCollector
        $target = Initialize-FakeCollector
        try {
            $collector.Shared.Redirect = "$($target.Url)/v1/status"
            $result = Invoke-Check $Shell $collector.Url
            $result.Code | Should -Be 3
            ($result.Output | ConvertFrom-Json).findings.code | Should -Contain 'status-unavailable'
            $target.Shared.StatusRequests | Should -Be 0
            $result.Output | Should -Not -Match ([regex]::Escape($script:Token))
        }
        finally { Stop-FakeCollector $collector; Stop-FakeCollector $target }
    }

    It 'rejects oversized status responses without exposing their body' {
        $collector = Initialize-FakeCollector
        $collector.Shared.Body = '{"padding":"' + ('x' * 4194304) + '"}'
        try { $result = Invoke-Check $Shell $collector.Url }
        finally { Stop-FakeCollector $collector }
        $result.Code | Should -Be 3
        ($result.Output | ConvertFrom-Json).findings.code | Should -Contain 'status-unavailable'
        $result.Output.Length | Should -BeLessThan 10000
    }

    It 'reports malformed status as UNKNOWN without echoing it or replacing the baseline' {
        $collector = Initialize-FakeCollector
        $state = Join-Path $TestDrive 'safe-state.json'
        try {
            $collector.Shared.Body = New-Status
            $null = Invoke-Check $Shell $collector.Url @('-StateFile', $state)
            $saved = Get-Content -LiteralPath $state -Raw
            $collector.Shared.Body = New-Status @{ queue = @{ queued = 'synthetic-secret-marker' } }
            $result = Invoke-Check $Shell $collector.Url @('-StateFile', $state)
            $result.Code | Should -Be 3
            ($result.Output | ConvertFrom-Json).findings.code | Should -Contain 'invalid-response'
            $result.Output | Should -Not -Match 'synthetic-secret-marker'
            (Get-Content -LiteralPath $state -Raw) | Should -Be $saved
        }
        finally { Stop-FakeCollector $collector }
    }

    It 'does not hide a known critical finding when a later status field is malformed' {
        $collector = Initialize-FakeCollector
        try {
            $collector.Shared.Body = New-Status @{
                queue = @{ queued = 1; retrying = 0; uploading = 0; deadLettered = 0; undeliveredBytes = 0; oldestUndelivered = [datetime]::UtcNow.AddHours(-2).ToString('o') }
                intake = @{ capacityRefusals = 'synthetic-secret-marker' }
            }
            $result = Invoke-Check $Shell $collector.Url
            $result.Code | Should -Be 2
            $codes = @((($result.Output | ConvertFrom-Json).findings).code)
            $codes | Should -Contain 'backlog'
            $codes | Should -Contain 'invalid-response'
            $result.Output | Should -Not -Match 'synthetic-secret-marker'
        }
        finally { Stop-FakeCollector $collector }
    }

    It 'does not echo an untrusted delivery failure code' {
        $collector = Initialize-FakeCollector
        try {
            $collector.Shared.Body = New-Status @{
                deliveryActivity = @{ lastFailureCode = 'destination-azure-http-401-synthetic-secret-marker'; lastFailureAt = [datetime]::UtcNow.ToString('o') }
            }
            $result = Invoke-Check $Shell $collector.Url
            $result.Code | Should -Be 1 -Because ("finding codes: " + (Get-FindingCodes $result))
            ($result.Output | ConvertFrom-Json).findings.code | Should -Contain 'destination-failing'
            $result.Output | Should -Not -Match 'synthetic-secret-marker'
        }
        finally { Stop-FakeCollector $collector }
    }
    It 'reports UNKNOWN when status is unavailable even with another warning' {
        $collector = Initialize-FakeCollector
        try {
            $collector.Shared.Health = 'degraded'
            $collector.Shared.Code = 503
            $result = Invoke-Check $Shell $collector.Url
        }
        finally { Stop-FakeCollector $collector }
        $result.Code | Should -Be 3
        $report = $result.Output | ConvertFrom-Json
        @($report.findings.code) | Should -Contain 'health-degraded'
        @($report.findings.code) | Should -Contain 'status-unavailable'
    }
    It 'reports CRITICAL when the collector is unreachable' {
        $result = Invoke-Check $Shell 'http://127.0.0.1:9'
        $result.Code | Should -Be 2
        ($result.Output | ConvertFrom-Json).findings[0].code | Should -Be 'collector-unreachable'
    }

    It 'reads status with the token, reports problems and never prints the token' {
        $collector = Initialize-FakeCollector
        try {
            $collector.Shared.Body = New-Status @{
                status = 'degraded'
                queue = @{ queued = 5; retrying = 0; uploading = 0; deadLettered = 2; undeliveredBytes = 100; oldestUndelivered = [datetime]::UtcNow.AddMinutes(-20).ToString('o') }
                sources = @(@{ application = 'windows-security'; environment = 'production'; state = 'silent' })
                queuePages = @{ pageSize = 4096; pageLimitBytes = 8388608; usedBytes = 7549747; freeListBytes = 0; usedPercent = 90.0 }
            }
            $result = Invoke-Check $Shell $collector.Url
        }
        finally { Stop-FakeCollector $collector }
        $result.Output | Should -Not -Match ([regex]::Escape($script:Token))
        $report = $result.Output | ConvertFrom-Json
        $result.Code | Should -Be 2
        @($report.findings.code) | Should -Contain 'dead-letters'
        @($report.findings.code) | Should -Contain 'backlog'
        @($report.findings.code) | Should -Contain 'source-overdue'
        @($report.findings.code) | Should -Contain 'queue-pages'
        $report.metrics.bower_queue_undelivered_events | Should -Be 5
    }

    It 'reports new syslog and Windows errors across runs of the same process (dates stay comparable)' {
        $state = Join-Path $TestDrive "state-$($Shell -replace '\W', '').json"
        $collector = Initialize-FakeCollector
        try {
            $collector.Shared.Body = New-Status
            $initial = Invoke-Check $Shell $collector.Url @('-StateFile', $state)
            $initial.Code | Should -Be 1 -Because ("finding codes: " + (Get-FindingCodes $initial))
            $collector.Shared.Body = New-Status @{
                syslog = @(@{ id = 'firewall-tls'; tlsHandshakeFailures = 3; connectionsAccepted = 1 })
                windowsEventLog = @(@{ id = 'forwarded-security'; state = 'running'; readErrors = 0; malformed = 1; oversized = 1 })
            }
            $result = Invoke-Check $Shell $collector.Url @('-StateFile', $state)
        }
        finally { Stop-FakeCollector $collector }
        $report = $result.Output | ConvertFrom-Json
        $result.Code | Should -Be 1
        @($report.findings.code) | Should -Contain 'syslog-errors'
        @($report.findings.code) | Should -Contain 'windows-event-log'
        ($report.findings | Where-Object code -eq 'windows-event-log').detail | Should -Match '2 new'
    }

    It 'keeps the previous baselines when /v1/status cannot be read' {
        $state = Join-Path $TestDrive "kept-$($Shell -replace '\W', '').json"
        $collector = Initialize-FakeCollector
        try {
            $collector.Shared.Body = New-Status
            $null = Invoke-Check $Shell $collector.Url @('-StateFile', $state)
            $saved = Get-Content -LiteralPath $state -Raw
            $saved | Should -Match 'firewall-tls'
            $collector.Shared.Code = 500
            $result = Invoke-Check $Shell $collector.Url @('-StateFile', $state)
        }
        finally { Stop-FakeCollector $collector }
        $result.Code | Should -Be 3
        Get-Content -LiteralPath $state -Raw | Should -Be $saved
    }

    It 'separates a credential failure from an unreachable destination' {
        $collector = Initialize-FakeCollector
        try {
            $failedAt = [datetime]::UtcNow.AddSeconds(-30).ToString('o')
            $collector.Shared.Body = New-Status @{
                deliveryActivity = @{ lastSuccessfulDeliveryAt = [datetime]::UtcNow.AddMinutes(-10).ToString('o'); lastFailureCode = 'destination-azure-credential-failed'; lastFailureAt = $failedAt }
            }
            $credential = Invoke-Check $Shell $collector.Url
            $collector.Shared.Body = New-Status @{
                deliveryActivity = @{ lastSuccessfulDeliveryAt = $failedAt; lastFailureCode = 'destination-azure-credential-failed'; lastFailureAt = $failedAt }
            }
            $tied = Invoke-Check $Shell $collector.Url
            $collector.Shared.Body = New-Status @{
                deliveryActivity = @{ lastSuccessfulDeliveryAt = $null; lastFailureCode = 'destination-azure-unavailable'; lastFailureAt = $failedAt }
            }
            $unavailable = Invoke-Check $Shell $collector.Url
        }
        finally { Stop-FakeCollector $collector }
        $credential.Code | Should -Be 2
        ($credential.Output | ConvertFrom-Json).findings[0].code | Should -Be 'destination-credential'
        $tied.Code | Should -Be 2
        ($tied.Output | ConvertFrom-Json).findings[0].code | Should -Be 'destination-credential'
        $unavailable.Code | Should -Be 1 -Because ("finding codes: " + (Get-FindingCodes $unavailable))
        ($unavailable.Output | ConvertFrom-Json).findings[0].code | Should -Be 'destination-failing'
    }
}

Describe 'Verdict ranking' {
    BeforeAll {
        # The ranking function and table, taken from the script itself.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Check, [ref]$null, [ref]$null)
        $function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-WorstLevel' }, $true)
        $table = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$rank' }, $true)
        . ([scriptblock]::Create($table.Extent.Text + "`n" + $function.Extent.Text))
    }

    It 'lets CRITICAL win over UNKNOWN, and UNKNOWN over WARNING' {
        Get-WorstLevel @(3, 2) | Should -Be 2
        Get-WorstLevel @(2, 3, 1) | Should -Be 2
        Get-WorstLevel @(1, 3) | Should -Be 3
        Get-WorstLevel @() | Should -Be 0
    }

    It 'reports CRITICAL for an unreachable collector even when WEC state is unknown' -Skip:($IsWindows -or $PSVersionTable.PSEdition -eq 'Desktop') {
        # wecutil.exe does not exist off Windows: an UNKNOWN finding next to a CRITICAL one.
        $result = Invoke-Check 'pwsh' 'http://127.0.0.1:9' @('-WecSubscription', 'bower-forwarded')
        $report = $result.Output | ConvertFrom-Json
        @($report.findings.code) | Should -Contain 'wec-unknown'
        $result.Code | Should -Be 2
        $report.status | Should -Be 'CRITICAL'
    }
}
