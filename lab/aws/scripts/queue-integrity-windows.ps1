$ErrorActionPreference='Stop'
$cli=Join-Path $env:ProgramFiles 'Bower\bower.exe'
$database=Join-Path $env:ProgramData 'Bower\state\queue.db'
$output=& $cli queue verify --database $database 2>&1
$code=$LASTEXITCODE
[pscustomobject]@{phase='ledger';host=$env:BOWER_LAB_HOST;intact=($code -eq 0);exitCode=$code} | ConvertTo-Json -Compress
exit $code
