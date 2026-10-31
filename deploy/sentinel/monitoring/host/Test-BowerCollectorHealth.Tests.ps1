# Pester 5 tests for Test-BowerCollectorHealth.ps1:
#   pwsh -NoProfile -Command "Invoke-Pester -Path deploy/sentinel/monitoring/host -Output Detailed"
BeforeAll {
    $script:Check = Join-Path $PSScriptRoot 'Test-BowerCollectorHealth.ps1'
    $script:Token = 'test-token-never-printed'

    function Initialize-FakeCollector([string] $StatusJson) {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = $listener.LocalEndpoint.Port
        $listener.Stop()
        $http = [System.Net.HttpListener]::new()
        $http.Prefixes.Add("http://127.0.0.1:$port/")
        $http.Start()
        $runspace = [powershell]::Create()
        $null = $runspace.AddScript({
                param($Http, $Body, $Token)
                while ($Http.IsListening) {
                    try { $context = $Http.GetContext() } catch { break }
                    $path = $context.Request.Url.AbsolutePath
                    if ($path -eq '/health') { $text = '{"status":"healthy"}'; $code = 200 }
                    elseif ($path -eq '/v1/status' -and $context.Request.Headers['Authorization'] -eq "Bearer $Token") { $text = $Body; $code = 200 }
                    else { $text = '{}'; $code = 401 }
                    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
                    $context.Response.StatusCode = $code
                    $context.Response.ContentType = 'application/json'
                    $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                    $context.Response.Close()
                }
            }).AddArgument($http).AddArgument($StatusJson).AddArgument($script:Token)
        $null = $runspace.BeginInvoke()
        return [pscustomobject]@{ Url = "http://127.0.0.1:$port"; Http = $http; Runspace = $runspace }
    }

    function Invoke-Check([string] $Url, [string[]] $Extra = @()) {
        $tokenFile = Join-Path $TestDrive 'token'
        Set-Content -LiteralPath $tokenFile -Value $script:Token
        $output = & pwsh -NoProfile -File $script:Check -Url $Url -TokenFile $tokenFile -QueuePath $TestDrive `
            -DiskWarningPercent 0 -DiskCriticalPercent 0 -Format Json @Extra
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = ($output -join "`n") }
    }
}

Describe 'Test-BowerCollectorHealth' {
    It 'reports CRITICAL when the collector is unreachable' {
        $result = Invoke-Check 'http://127.0.0.1:9'
        $result.Code | Should -Be 2
        ($result.Output | ConvertFrom-Json).findings[0].code | Should -Be 'collector-unreachable'
    }

    It 'reads status with the token, reports problems and never prints the token' {
        $old = [datetime]::UtcNow.AddMinutes(-20).ToString('o')
        $status = @{
            status = 'degraded'
            queue = @{ queued = 5; retrying = 0; uploading = 0; deadLettered = 2; undeliveredBytes = 100; oldestUndelivered = $old }
            intake = @{ observedSince = '2026-10-31T08:00:00+00:00'; capacityRefusals = 0; privacyAlertRefusals = 0; lastRefusalAt = $null }
            sources = @(@{ application = 'windows-security'; environment = 'production'; state = 'silent' })
            windowsEventLog = @(@{ id = 'forwarded-security'; state = 'running'; readErrors = 0 })
        } | ConvertTo-Json -Depth 5
        $collector = Initialize-FakeCollector $status
        try {
            $result = Invoke-Check $collector.Url
        }
        finally {
            $collector.Http.Stop()
            $collector.Runspace.Dispose()
        }
        $result.Output | Should -Not -Match ([regex]::Escape($script:Token))
        $report = $result.Output | ConvertFrom-Json
        $result.Code | Should -Be 1
        $report.status | Should -Be 'WARNING'
        @($report.findings.code) | Should -Contain 'dead-letters'
        @($report.findings.code) | Should -Contain 'backlog'
        @($report.findings.code) | Should -Contain 'source-overdue'
        $report.metrics.bower_queue_undelivered_events | Should -Be 5
    }
}
