using System.Xml;
using System.Xml.Linq;
using Bower.Source.WindowsEventLog;

namespace Bower.UnitTests;

/// <summary>
/// bower wec subscription generate: source-initiated WEF subscription XML from a validated
/// Bower subscription. Forwarders select at source exactly what the collector accepts.
/// </summary>
public sealed class WecSubscriptionTests
{
    private static readonly XNamespace Ns = WecSubscription.Namespace;

    private static WindowsEventSubscriptionOptions Security() =>
        WindowsEventLogSourceConfigurationLoader.Parse("""
            {"apiVersion":"bower.security/v1","kind":"WindowsEventLogSource","subscriptions":[
              {"id":"security-logon","channel":"Security","eventIds":[4625,4624],
               "providers":["Microsoft-Windows-Security-Auditing"],"pack":"windows-security-logon","parser":0}]}
            """).Subscriptions[0];

    [Fact]
    public void Generate_SelectsOnlyTheAllowListedChannelEventsAndProviders()
    {
        XDocument document = XDocument.Parse(WecSubscription.Generate(Security(), new WecSubscriptionOptions()));
        XElement root = document.Root!;

        Assert.Equal(Ns + "Subscription", root.Name);
        Assert.Equal("bower-security-logon", root.Element(Ns + "SubscriptionId")!.Value);
        Assert.Equal("SourceInitiated", root.Element(Ns + "SubscriptionType")!.Value);
        Assert.Equal("MinLatency", root.Element(Ns + "ConfigurationMode")!.Value);
        Assert.Equal("HTTPS", root.Element(Ns + "TransportName")!.Value);
        Assert.Equal("Events", root.Element(Ns + "ContentFormat")!.Value);
        Assert.Equal("false", root.Element(Ns + "ReadExistingEvents")!.Value);
        Assert.Equal("ForwardedEvents", root.Element(Ns + "LogFile")!.Value);
        Assert.Equal(WecSubscription.DefaultDomainComputers, root.Element(Ns + "AllowedSourceDomainComputers")!.Value);
        Assert.Null(root.Element(Ns + "Delivery")!.Element(Ns + "Batching"));

        // The query is a CDATA QueryList with one Select: the collector's XPath, IDs sorted.
        XNode cdata = root.Element(Ns + "Query")!.Nodes().Single();
        Assert.IsType<XCData>(cdata);
        XElement queryList = XElement.Parse(((XCData)cdata).Value);
        XElement select = queryList.Element("Query")!.Element("Select")!;
        Assert.Equal("Security", queryList.Element("Query")!.Attribute("Path")!.Value);
        Assert.Equal("Security", select.Attribute("Path")!.Value);
        Assert.Equal(
            "*[System[(EventID=4624 or EventID=4625) and (Provider[@Name='Microsoft-Windows-Security-Auditing'])]]",
            select.Value);
        Assert.Equal(WindowsEventQuery.For(Security(), 0).ToXPath(includeRecordPosition: false), select.Value);
        Assert.DoesNotContain("EventRecordID", select.Value, StringComparison.Ordinal);
    }

    [Fact]
    public void Generate_CustomBatchingCertificatesAndHeartbeat()
    {
        string xml = WecSubscription.Generate(Security(), new WecSubscriptionOptions(
            WecDeliveryMode.Custom, MaxItems: 50, MaxLatencySeconds: 10, HeartbeatSeconds: 600, ReadExistingEvents: true,
            SubscriptionId: "dmz-logons", IssuerCaThumbprints: ["0123456789abcdef0123456789abcdef01234567"]));
        XElement root = XDocument.Parse(xml).Root!;
        XElement delivery = root.Element(Ns + "Delivery")!;

        Assert.Equal("dmz-logons", root.Element(Ns + "SubscriptionId")!.Value);
        Assert.Equal("Push", delivery.Attribute("Mode")!.Value);
        Assert.Equal("50", delivery.Element(Ns + "Batching")!.Element(Ns + "MaxItems")!.Value);
        Assert.Equal("10000", delivery.Element(Ns + "Batching")!.Element(Ns + "MaxLatencyTime")!.Value);
        Assert.Equal("600000", delivery.Element(Ns + "PushSettings")!.Element(Ns + "Heartbeat")!.Attribute("Interval")!.Value);
        Assert.Equal("true", root.Element(Ns + "ReadExistingEvents")!.Value);
        Assert.Equal(
            "0123456789ABCDEF0123456789ABCDEF01234567",
            root.Element(Ns + "AllowedSourceNonDomainComputers")!.Element(Ns + "AllowedIssuerCAList")!.Element(Ns + "IssuerCA")!.Value);
    }

    [Theory]
    [InlineData(WecDeliveryMode.Custom, null, null, 900, null, null, null)]
    [InlineData(WecDeliveryMode.Custom, 0, 10, 900, null, null, null)]
    [InlineData(WecDeliveryMode.MinLatency, 5, null, 900, null, null, null)]
    [InlineData(WecDeliveryMode.MinLatency, null, null, 10, null, null, null)]
    [InlineData(WecDeliveryMode.MinLatency, null, null, 900, "bad name<x>", null, null)]
    [InlineData(WecDeliveryMode.MinLatency, null, null, 900, null, "O:NSG:NSD:(A;;GA;;;DC)<x/>", null)]
    [InlineData(WecDeliveryMode.MinLatency, null, null, 900, null, null, "not-a-thumbprint")]
    public void Generate_RejectsOptionsThatCouldWidenOrBreakTheSubscription(
        WecDeliveryMode mode, int? maxItems, int? maxLatency, int heartbeat, string? id, string? sddl, string? issuer)
    {
        WecSubscriptionOptions options = new(mode, maxItems, maxLatency, heartbeat, false, id, sddl,
            issuer is null ? null : [issuer]);

        Assert.Throws<ArgumentException>(() => WecSubscription.Generate(Security(), options));
    }

    [Fact]
    public void Generate_IsWellFormedAndHasNoDtd()
    {
        string xml = WecSubscription.Generate(Security(), new WecSubscriptionOptions());
        using XmlReader reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit });

        while (reader.Read())
        {
        }

        Assert.EndsWith("</Subscription>\n", xml, StringComparison.Ordinal);
    }

    [Fact]
    public void Cli_WritesTheSubscriptionForTheNamedBowerSubscription()
    {
        using TemporaryDirectory directory = new();
        string config = Path.Combine(directory.Path, "wel.json");
        File.WriteAllText(config, """
            {"apiVersion":"bower.security/v1","kind":"WindowsEventLogSource","subscriptions":[
              {"id":"security-logon","channel":"Security","eventIds":[4625],"pack":"windows-security-logon","parser":0}]}
            """);
        string output = Path.Combine(directory.Path, "sub.xml");

        int code = Bower.Cli.Commands.WecCommands.GenerateSubscription(
            ["--config", config, "--subscription", "security-logon", "--out", output]);

        Assert.Equal(0, code);
        Assert.Contains("EventID=4625", File.ReadAllText(output), StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => Bower.Cli.Commands.WecCommands.GenerateSubscription(
            ["--config", config, "--subscription", "missing"]));
        Assert.Throws<ArgumentException>(() => Bower.Cli.Commands.WecCommands.GenerateSubscription(
            ["--config", config, "--subscription", "security-logon", "--mode", "Fast"]));
    }
}
