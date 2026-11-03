$ErrorActionPreference = 'Stop'
# Pre-fill only: larger WEF batches so ForwardedEvents fills quickly. The measured run
# restores the soak's settings (100 events, 1,000 ms) with MAX_ITEMS=100 LATENCY_MS=1000.
wecutil.exe ss Bower-Security-4625 /cm:Custom /dmi:{{MAX_ITEMS}} /dmlt:{{LATENCY_MS}}
if ($LASTEXITCODE -ne 0) { throw 'wecutil ss failed' }
$xml = [xml](wecutil.exe gs Bower-Security-4625 /f:xml)
Write-Output ("{0} maxItems={1} maxLatencyMs={2}" -f $env:COMPUTERNAME, $xml.Subscription.Delivery.Batching.MaxItems, $xml.Subscription.Delivery.Batching.MaxLatencyTime)
