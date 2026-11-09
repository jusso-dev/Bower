using Bower.Source.WindowsEventLog;

namespace Bower.Cli.Commands;

internal static class WecCommands
{
    /// <summary>
    /// bower wec subscription generate --config FILE --subscription ID [--mode MinLatency|Normal|MinBandwidth|Custom]
    ///   [--max-items N --max-latency-seconds N] [--heartbeat-seconds N] [--read-existing]
    ///   [--subscription-id NAME] [--allowed-domain-computers SDDL] [--issuer-ca THUMBPRINT]... [--log-file CHANNEL] [--out FILE]
    /// </summary>
    public static int GenerateSubscription(string[] args)
    {
        WindowsEventLogSourceConfiguration configuration =
            WindowsEventLogSourceConfigurationLoader.LoadFile(CliOptions.Required(args, "--config"));
        string id = CliOptions.Required(args, "--subscription");
        WindowsEventSubscriptionOptions subscription = configuration.Subscriptions.FirstOrDefault(item => item.Id == id)
            ?? throw new ArgumentException($"Subscription {id} is not in the configuration file.");
        string modeText = CliOptions.Get(args, "--mode") ?? nameof(WecDeliveryMode.MinLatency);
        if (!Enum.TryParse(modeText, ignoreCase: false, out WecDeliveryMode mode) || !Enum.IsDefined(mode))
        {
            throw new ArgumentException("--mode must be MinLatency, Normal, MinBandwidth or Custom.");
        }

        int? Optional(string name) => CliOptions.Has(args, name) ? CliOptions.Int(args, name, 0) : null;
        IReadOnlyList<string> issuers = CliOptions.All(args, "--issuer-ca");
        WecSubscriptionOptions options = new(
            mode,
            Optional("--max-items"),
            Optional("--max-latency-seconds"),
            CliOptions.Int(args, "--heartbeat-seconds", 900),
            CliOptions.Has(args, "--read-existing"),
            CliOptions.Get(args, "--subscription-id"),
            CliOptions.Get(args, "--allowed-domain-computers"),
            issuers.Count == 0 ? null : issuers,
            CliOptions.Get(args, "--log-file") ?? "ForwardedEvents");
        string xml = WecSubscription.Generate(subscription, options);
        if (CliOptions.Get(args, "--out") is string path)
        {
            File.WriteAllText(path, xml);
            Console.Error.WriteLine($"Wrote {path}. On the WEC host: wecutil cs \"{path}\"");
        }
        else
        {
            Console.Write(xml);
        }

        return 0;
    }
}
