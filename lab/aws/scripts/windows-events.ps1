$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
try {
    Import-Module AWSPowerShell -ErrorAction Stop
    $root=Join-Path $env:ProgramData 'BowerLab'
    $corpus=(Get-SECSecretValue -SecretId ('bower-lab/'+$env:BOWER_LAB_RUN+'/corpus') -Region $env:AWS_DEFAULT_REGION).SecretString | ConvertFrom-Json
    $correlations=@()
    for ($i=1;$i -le 100;$i++) {
        $correlation=$env:BOWER_LAB_RUN+'-'+$env:BOWER_LAB_HOST.ToLowerInvariant()+'-native-'+$i
        $reason='SyntheticFailure negative-control-order-ABC123'
        if ($i % 5 -eq 0) {
            $parts=@($corpus.values.PSObject.Properties | ForEach-Object { $_.Name+'='+$_.Value })
            $reason='SyntheticFailure '+($parts -join ' ')
        }
        $event=New-Object Diagnostics.EventInstance(9010,0,[Diagnostics.EventLogEntryType]::Warning)
        [Diagnostics.EventLog]::WriteEvent('BowerLab',$event,[object[]]@('synthetic-lab-operator',$correlation,$reason))
        $correlations+=$correlation
    }
    $result=[pscustomobject]@{phase='native';host=$env:BOWER_LAB_HOST;written=100;correlations=$correlations;sentinel='deferred'}
    $path=Join-Path $root 'native.json'
    [IO.File]::WriteAllText($path,($result | ConvertTo-Json -Depth 5))
    Write-S3Object -BucketName $env:BOWER_LAB_BUCKET -Key ('runs/'+$env:BOWER_LAB_RUN+'/hosts/'+$env:BOWER_LAB_HOST+'/native.json') -File $path -Region $env:AWS_DEFAULT_REGION | Out-Null
    $os=Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{phase='native';host=$env:BOWER_LAB_HOST;written=100;service=(Get-Service Bower).Status.ToString();usedMemoryPercent=[math]::Round((1-$os.FreePhysicalMemory/$os.TotalVisibleMemorySize)*100,1)} | ConvertTo-Json -Compress
} catch {
    [pscustomobject]@{phase='native';host=$env:BOWER_LAB_HOST;status='failed';errorType=$_.Exception.GetType().Name;line=$_.InvocationInfo.ScriptLineNumber} | ConvertTo-Json -Compress
    exit 1
}
