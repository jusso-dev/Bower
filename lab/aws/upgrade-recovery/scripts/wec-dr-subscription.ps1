$ErrorActionPreference = 'Stop'
Set-Service Wecsvc -StartupType Automatic
wecutil.exe qc /q | Out-Null
winrm.cmd quickconfig -q | Out-Null
@'
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
 <SubscriptionId>Bower-Security-4625-dr</SubscriptionId>
 <SubscriptionType>SourceInitiated</SubscriptionType>
 <Description>Temporary Bower ws4 upgrade/recovery validation</Description>
 <Enabled>true</Enabled>
 <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
 <ConfigurationMode>Custom</ConfigurationMode>
 <Delivery Mode="Push"><Batching><MaxItems>1</MaxItems><MaxLatencyTime>1000</MaxLatencyTime></Batching><PushSettings><Heartbeat Interval="10000"/></PushSettings></Delivery>
 <Query><![CDATA[<QueryList><Query Id="0"><Select Path="Security">*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4625]]</Select></Query></QueryList>]]></Query>
 <ReadExistingEvents>{{READ_EXISTING}}</ReadExistingEvents>
 <TransportName>HTTP</TransportName>
 <ContentFormat>Events</ContentFormat>
 <Locale Language="en-US"/>
 <LogFile>ForwardedEvents</LogFile>
 <AllowedSourceDomainComputers>O:NSG:BAD:P(A;;GA;;;DC)(A;;GA;;;DD)(A;;GA;;;NS)</AllowedSourceDomainComputers>
</Subscription>
'@ | Set-Content C:\BowerLab\subscription-dr.xml -Encoding UTF8
$names = @(& wecutil.exe es)
if ($names -contains 'Bower-Security-4625-dr') { throw 'Subscription already exists' }
wecutil.exe cs C:\BowerLab\subscription-dr.xml
if ($LASTEXITCODE -ne 0) { throw 'WEC subscription creation failed' }
wevtutil.exe sl ForwardedEvents /ms:1073741824
if ($LASTEXITCODE -ne 0) { throw 'Unable to size ForwardedEvents' }
Write-Output "WEC subscription created on $env:COMPUTERNAME (readExisting={{READ_EXISTING}}); ForwardedEvents 1 GiB."
