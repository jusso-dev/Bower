$ErrorActionPreference="Continue"
wecutil.exe gr Bower-Security-4625-dr | Select-Object -First 12
wecutil.exe gr Bower-Security-4625 | Select-Object -First 8
"fwd=$((Get-WinEvent -ListLog ForwardedEvents).RecordCount)"
