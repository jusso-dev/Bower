$ErrorActionPreference = 'Stop'
# Destination outage: block only the Bower service's outbound HTTPS (Entra token and DCE).
$name = 'Bower lab destination outage'
if ('{{MODE}}' -eq 'on') {
    if (!(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $name -Direction Outbound -Service Bower -Protocol TCP -RemotePort 443 -Action Block | Out-Null
    }
} else {
    Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}
[ordered]@{ mode = '{{MODE}}'; at = [DateTimeOffset]::UtcNow.ToString('o'); rulePresent = [bool](Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) } | ConvertTo-Json -Compress
