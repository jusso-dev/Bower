using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bower.Source.Syslog;

/// <summary>BOWER_SYSLOG_CONFIG: the syslog listeners, their senders and pack routes.</summary>
public sealed record SyslogSourceConfiguration(
    string ApiVersion,
    string Kind,
    IReadOnlyList<SyslogListenerOptions> Listeners);

/// <param name="Protocol"><c>tcp</c>, <c>tls</c> or <c>udp</c>.</param>
/// <param name="Port">0 lets the operating system choose (tests and diagnostics).</param>
/// <param name="AllowedSenders">Addresses or CIDR ranges allowed to send. Everything else is refused and counted.</param>
/// <param name="Routes">First match wins. A message no route matches is dropped (default deny).</param>
/// <param name="MaximumConnections">Concurrent TCP/TLS connections; further connections are closed and counted.</param>
/// <param name="IdleTimeoutSeconds">Longest wait for one complete frame (or the TLS handshake) before the connection closes.</param>
/// <param name="AllowInsecureNonLoopback">Allow tcp or udp on a non-loopback address. Only on an isolated network.</param>
public sealed record SyslogListenerOptions(
    string Id,
    string Protocol,
    int Port,
    IReadOnlyList<string> AllowedSenders,
    IReadOnlyList<SyslogRoute> Routes,
    string Address = "127.0.0.1",
    int MaximumMessageBytes = 65_536,
    int MaximumConnections = 64,
    int IdleTimeoutSeconds = 60,
    SyslogTlsOptions? Tls = null,
    bool AllowInsecureNonLoopback = false)
{
    [JsonIgnore]
    internal IReadOnlyList<SyslogNetwork> Senders { get; init; } = [];

    /// <summary>Sender allow-list check; IPv4-mapped IPv6 senders match IPv4 ranges.</summary>
    public bool Allows(IPAddress sender)
    {
        ArgumentNullException.ThrowIfNull(sender);
        IPAddress address = sender.IsIPv4MappedToIPv6 ? sender.MapToIPv4() : sender;
        return Senders.Any(network => network.Contains(address));
    }

    public SyslogRoute? Route(SyslogMessage message, IPAddress sender)
    {
        ArgumentNullException.ThrowIfNull(sender);
        ArgumentNullException.ThrowIfNull(message);
        IPAddress address = sender.IsIPv4MappedToIPv6 ? sender.MapToIPv4() : sender;
        return Routes.FirstOrDefault(route =>
            (route.Hostname is null || string.Equals(route.Hostname, message.Hostname, StringComparison.Ordinal))
            && (route.AppName is null || string.Equals(route.AppName, message.AppName, StringComparison.Ordinal))
            && (route.AllowedSenders is null || route.Senders.Any(network => network.Contains(address))));
    }
}

/// <param name="CertificateFile">PEM server certificate, optionally followed by its intermediates.</param>
/// <param name="ClientCertificateAuthorityFile">PEM CA certificates. When set, senders must present a client certificate they issued.</param>
/// <param name="ClientCertificateRevocationListFile">
/// PEM or DER revocation lists from the client CAs (requires <paramref name="ClientCertificateAuthorityFile"/>).
/// When set, every client's issuer needs a current, validly signed list and listed certificates are refused.
/// </param>
/// <remarks>Every file is reloaded when it changes; see <see cref="SyslogSource"/>.</remarks>
public sealed record SyslogTlsOptions(
    string CertificateFile,
    string PrivateKeyFile,
    string? ClientCertificateAuthorityFile = null,
    string? ClientCertificateRevocationListFile = null);

/// <summary>
/// Maps matching messages to one active parser of a loaded signed pack. Hostname and
/// app-name are claimed by the sender; <paramref name="AllowedSenders"/> pins the route to
/// the addresses that may claim them.
/// </summary>
public sealed record SyslogRoute(
    string Pack,
    int Parser,
    string? Hostname = null,
    string? AppName = null,
    IReadOnlyList<string>? AllowedSenders = null)
{
    [JsonIgnore]
    internal IReadOnlyList<SyslogNetwork> Senders { get; init; } = [];
}

internal sealed record SyslogNetwork(IPAddress Network, int PrefixLength)
{
    public bool Contains(IPAddress address)
    {
        if (address.AddressFamily != Network.AddressFamily)
        {
            return false;
        }

        byte[] left = Network.GetAddressBytes();
        byte[] right = address.GetAddressBytes();
        int bits = PrefixLength;
        for (int index = 0; index < left.Length && bits > 0; index++, bits -= 8)
        {
            int mask = bits >= 8 ? 0xFF : (0xFF << (8 - bits)) & 0xFF;
            if ((left[index] & mask) != (right[index] & mask))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Address or address/prefix in canonical form; host bits must be zero.</summary>
    public static SyslogNetwork? Parse(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        int slash = text.IndexOf('/', StringComparison.Ordinal);
        string addressText = slash < 0 ? text : text[..slash];
        if (!SyslogSourceConfigurationLoader.TryParseAddress(addressText, out IPAddress? address))
        {
            return null;
        }

        int maximum = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        int prefix = maximum;
        if (slash >= 0)
        {
            string prefixText = text[(slash + 1)..];
            if (prefixText.Length is < 1 or > 3 || !prefixText.All(char.IsAsciiDigit)
                || (prefixText.Length > 1 && prefixText[0] == '0'))
            {
                return null;
            }

            prefix = int.Parse(prefixText, System.Globalization.CultureInfo.InvariantCulture);
            if (prefix > maximum)
            {
                return null;
            }
        }

        SyslogNetwork network = new(address, prefix);
        byte[] bytes = address.GetAddressBytes();
        for (int bit = prefix; bit < maximum; bit++)
        {
            if ((bytes[bit / 8] & (0x80 >> (bit % 8))) != 0)
            {
                return null;
            }
        }

        return network;
    }
}

public static class SyslogSourceConfigurationLoader
{
    public const int MaximumListeners = 16;
    public const int MaximumSenders = 64;
    public const int MaximumRoutes = 64;
    private const int MaximumBytes = 262_144;

    public static SyslogSourceConfiguration LoadFile(string path)
    {
        FileInfo info = new(path);
        if (!info.Exists)
        {
            throw new FileNotFoundException("Syslog source configuration file does not exist.", path);
        }

        if (info.Length > MaximumBytes)
        {
            throw new InvalidDataException("Syslog source configuration file exceeds 256 KiB.");
        }

        return Parse(File.ReadAllText(path));
    }

    public static SyslogSourceConfiguration Parse(string json)
    {
        SyslogSourceConfiguration? configuration;
        try
        {
            configuration = JsonSerializer.Deserialize(json, SyslogJsonContext.Default.SyslogSourceConfiguration);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"Syslog source configuration is invalid: {exception.Message}", exception);
        }

        if (configuration is null
            || !string.Equals(configuration.ApiVersion, "bower.security/v1", StringComparison.Ordinal)
            || !string.Equals(configuration.Kind, "SyslogSource", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Syslog source configuration needs apiVersion bower.security/v1 and kind SyslogSource.");
        }

        if (configuration.Listeners is not { Count: >= 1 and <= MaximumListeners })
        {
            throw new InvalidDataException($"Syslog source configuration must list 1–{MaximumListeners} listeners.");
        }

        HashSet<string> ids = new(StringComparer.Ordinal);
        List<SyslogListenerOptions> listeners = [];
        foreach (SyslogListenerOptions listener in configuration.Listeners)
        {
            SyslogListenerOptions validated = Validate(listener);
            if (!ids.Add(validated.Id))
            {
                throw new InvalidDataException($"Syslog listener {validated.Id} is listed more than once.");
            }

            listeners.Add(validated);
        }

        return configuration with { Listeners = listeners };
    }

    private static SyslogListenerOptions Validate(SyslogListenerOptions listener)
    {
        if (listener is null || !IsListenerId(listener.Id))
        {
            throw new InvalidDataException(
                "Syslog listener id must be 1–63 lowercase letters, digits or hyphens and start with a letter or digit.");
        }

        string id = listener.Id;
        if (listener.Protocol is not ("tcp" or "tls" or "udp"))
        {
            throw Invalid(id, "protocol must be tcp, tls or udp.");
        }

        if (!TryParseAddress(listener.Address, out IPAddress? address))
        {
            throw Invalid(id, "address must be an IP address.");
        }

        if (listener.Port is < 0 or > 65_535)
        {
            throw Invalid(id, "port must be between 0 and 65535.");
        }

        if (!IPAddress.IsLoopback(address) && listener.Protocol != "tls" && !listener.AllowInsecureNonLoopback)
        {
            throw Invalid(id, "a non-loopback address requires protocol tls; set allowInsecureNonLoopback only on an isolated network.");
        }

        if ((listener.Protocol == "tls") != (listener.Tls is not null)
            || (listener.Tls is { } tls && (string.IsNullOrWhiteSpace(tls.CertificateFile) || string.IsNullOrWhiteSpace(tls.PrivateKeyFile))))
        {
            throw Invalid(id, "tls settings are required for protocol tls and not allowed otherwise.");
        }

        if (listener.Tls is { ClientCertificateRevocationListFile: { } revocationList } withList
            && (string.IsNullOrWhiteSpace(revocationList) || withList.ClientCertificateAuthorityFile is null))
        {
            throw Invalid(id, "tls.clientCertificateRevocationListFile requires tls.clientCertificateAuthorityFile.");
        }

        if (listener.AllowedSenders is not { Count: >= 1 and <= MaximumSenders })
        {
            throw Invalid(id, $"allowedSenders must list 1–{MaximumSenders} addresses or CIDR ranges.");
        }

        List<SyslogNetwork> senders = [];
        foreach (string sender in listener.AllowedSenders)
        {
            senders.Add(SyslogNetwork.Parse(sender)
                ?? throw Invalid(id, $"allowed sender '{sender}' is not a valid address or CIDR range."));
        }

        if (listener.MaximumMessageBytes is < 480 or > 65_536)
        {
            throw Invalid(id, "maximumMessageBytes must be between 480 and 65536.");
        }

        if (listener.MaximumConnections is < 1 or > 1_024)
        {
            throw Invalid(id, "maximumConnections must be between 1 and 1024.");
        }

        if (listener.IdleTimeoutSeconds is < 1 or > 3_600)
        {
            throw Invalid(id, "idleTimeoutSeconds must be between 1 and 3600.");
        }

        if (listener.Routes is not { Count: >= 1 and <= MaximumRoutes })
        {
            throw Invalid(id, $"routes must list 1–{MaximumRoutes} entries.");
        }

        List<SyslogRoute> routes = [];
        foreach (SyslogRoute route in listener.Routes)
        {
            if (route is null || string.IsNullOrWhiteSpace(route.Pack) || route.Parser < 0)
            {
                throw Invalid(id, "each route needs a pack id and a parser index of 0 or more.");
            }

            if ((route.Hostname is not null && !IsPrintable(route.Hostname, 255))
                || (route.AppName is not null && !IsPrintable(route.AppName, 48)))
            {
                throw Invalid(id, "route hostname and appName must be 1–255 and 1–48 printable ASCII characters.");
            }

            if (route.AllowedSenders is null)
            {
                routes.Add(route);
                continue;
            }

            if (route.AllowedSenders is not { Count: >= 1 and <= MaximumSenders })
            {
                throw Invalid(id, $"route allowedSenders must list 1–{MaximumSenders} addresses or CIDR ranges.");
            }

            List<SyslogNetwork> routeSenders = [];
            foreach (string sender in route.AllowedSenders)
            {
                routeSenders.Add(SyslogNetwork.Parse(sender)
                    ?? throw Invalid(id, $"allowed sender '{sender}' is not a valid address or CIDR range."));
            }

            routes.Add(route with { Senders = routeSenders });
        }

        return listener with { Senders = senders, Routes = routes };
    }

    /// <summary>Canonical IP text only (no shorthand IPv4, no IPv6 scope), as the Rust port parses.</summary>
    internal static bool TryParseAddress(string? text, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out IPAddress? address)
    {
        address = null;
        // Hex digits, ':' and '.' only: no brackets, ports, scopes or whitespace, which
        // IPAddress.TryParse would otherwise accept (and silently drop a port).
        if (string.IsNullOrEmpty(text)
            || !text.All(character => char.IsAsciiHexDigit(character) || character is ':' or '.')
            || !IPAddress.TryParse(text, out IPAddress? parsed))
        {
            return false;
        }

        if (parsed.AddressFamily == AddressFamily.InterNetwork)
        {
            if (text != parsed.ToString())
            {
                return false;
            }
        }
        else if (text.Contains('.', StringComparison.Ordinal))
        {
            string embedded = text[(text.LastIndexOf(':') + 1)..];
            if (!IPAddress.TryParse(embedded, out IPAddress? ipv4) || embedded != ipv4.ToString())
            {
                return false;
            }
        }

        address = parsed;
        return true;
    }

    private static bool IsListenerId(string? id) =>
        id is { Length: >= 1 and <= 63 }
        && (char.IsAsciiLetterLower(id[0]) || char.IsAsciiDigit(id[0]))
        && id.All(character => char.IsAsciiLetterLower(character) || char.IsAsciiDigit(character) || character == '-');

    private static bool IsPrintable(string value, int maximum) =>
        value.Length >= 1 && value.Length <= maximum && value.All(character => character is >= '!' and <= '~');

    private static InvalidDataException Invalid(string id, string message) =>
        new($"Syslog listener {id}: {message}");
}

[JsonSourceGenerationOptions(
    JsonSerializerDefaults.Web,
    NumberHandling = JsonNumberHandling.Strict,
    PropertyNameCaseInsensitive = false,
    AllowDuplicateProperties = false,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectRequiredConstructorParameters = true,
    RespectNullableAnnotations = true)]
[JsonSerializable(typeof(SyslogSourceConfiguration))]
[JsonSerializable(typeof(IReadOnlyList<SyslogListenerStatus>))]
internal sealed partial class SyslogJsonContext : JsonSerializerContext;
