using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bower.Source.WindowsEventLog;

/// <summary>BOWER_WINDOWS_EVENTLOG_CONFIG: channel subscriptions, their allow-lists and pack parsers.</summary>
public sealed record WindowsEventLogSourceConfiguration(
    string ApiVersion,
    string Kind,
    IReadOnlyList<WindowsEventSubscriptionOptions> Subscriptions);

/// <summary>
/// One channel, an explicit event ID allow-list and the signed pack parser that maps
/// selected events. The Windows query (XPath) is generated from these values; there is no
/// free-text query and no "all events" form.
/// </summary>
/// <param name="Channel">Event log channel, for example <c>Security</c> or <c>Microsoft-Windows-Sysmon/Operational</c>.</param>
/// <param name="EventIds">1–16 event IDs. Only these are read from the channel.</param>
/// <param name="Providers">Optional 1–4 provider names; when set, only their events are read.</param>
/// <param name="ReadExisting">Read events already in the channel on first start. Default: start at the newest event.</param>
/// <param name="IncludeMessage">Render the publisher message string into the record's <c>message</c> field.</param>
/// <param name="PollIntervalSeconds">Wait between reads once the subscription has caught up.</param>
/// <param name="BatchSize">Events read per query; the bookmark is committed after each batch.</param>
public sealed record WindowsEventSubscriptionOptions(
    string Id,
    string Channel,
    IReadOnlyList<int> EventIds,
    string Pack,
    int Parser,
    IReadOnlyList<string>? Providers = null,
    bool ReadExisting = false,
    bool IncludeMessage = false,
    int PollIntervalSeconds = 2,
    int BatchSize = 64)
{
    /// <summary>Durable bookmark key in the queue database's source cursor table.</summary>
    [JsonIgnore]
    public string SourceId => "windows-eventlog:" + Id;
}

public static class WindowsEventLogSourceConfigurationLoader
{
    public const int MaximumSubscriptions = 16;

    /// <summary>
    /// Kept small on purpose (a narrow allow-list), and so the generated query stays well
    /// inside the Windows event query expression limit.
    /// </summary>
    public const int MaximumEventIds = 16;

    public const int MaximumProviders = 4;
    private const int MaximumBytes = 262_144;

    public static WindowsEventLogSourceConfiguration LoadFile(string path)
    {
        FileInfo info = new(path);
        if (!info.Exists)
        {
            throw new FileNotFoundException("Windows Event Log source configuration file does not exist.", path);
        }

        if (info.Length > MaximumBytes)
        {
            throw new InvalidDataException("Windows Event Log source configuration file exceeds 256 KiB.");
        }

        return Parse(File.ReadAllText(path));
    }

    public static WindowsEventLogSourceConfiguration Parse(string json)
    {
        WindowsEventLogSourceConfiguration? configuration;
        try
        {
            configuration = JsonSerializer.Deserialize(json, WindowsEventLogJsonContext.Default.WindowsEventLogSourceConfiguration);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"Windows Event Log source configuration is invalid: {exception.Message}", exception);
        }

        if (configuration is null
            || !string.Equals(configuration.ApiVersion, "bower.security/v1", StringComparison.Ordinal)
            || !string.Equals(configuration.Kind, "WindowsEventLogSource", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Windows Event Log source configuration needs apiVersion bower.security/v1 and kind WindowsEventLogSource.");
        }

        if (configuration.Subscriptions is not { Count: >= 1 and <= MaximumSubscriptions })
        {
            throw new InvalidDataException(
                $"Windows Event Log source configuration must list 1–{MaximumSubscriptions} subscriptions.");
        }

        HashSet<string> ids = new(StringComparer.Ordinal);
        // Channel names are case-insensitive in Windows; one (channel, event ID) pair has one owner.
        HashSet<(string Channel, int EventId)> selected = [];
        List<WindowsEventSubscriptionOptions> subscriptions = [];
        foreach (WindowsEventSubscriptionOptions subscription in configuration.Subscriptions)
        {
            WindowsEventSubscriptionOptions validated = Validate(subscription);
            if (!ids.Add(validated.Id))
            {
                throw new InvalidDataException($"Windows Event Log subscription {validated.Id} is listed more than once.");
            }

            foreach (int eventId in validated.EventIds)
            {
                if (!selected.Add((validated.Channel.ToUpperInvariant(), eventId)))
                {
                    throw Invalid(validated.Id, $"event ID {eventId} on channel {validated.Channel} is already selected by another subscription.");
                }
            }

            subscriptions.Add(validated);
        }

        return configuration with { Subscriptions = subscriptions };
    }

    private static WindowsEventSubscriptionOptions Validate(WindowsEventSubscriptionOptions subscription)
    {
        if (subscription is null || !IsSubscriptionId(subscription.Id))
        {
            throw new InvalidDataException(
                "Windows Event Log subscription id must be 1–63 lowercase letters, digits or hyphens and start with a letter or digit.");
        }

        string id = subscription.Id;
        if (!IsName(subscription.Channel, allowSlash: true))
        {
            throw Invalid(id, "channel must be 1–255 letters, digits, spaces or - _ . / characters, without leading or trailing spaces.");
        }

        if (subscription.EventIds is not { Count: >= 1 and <= MaximumEventIds })
        {
            throw Invalid(id, $"eventIds must list 1–{MaximumEventIds} event IDs; there is no collect-all form.");
        }

        if (subscription.EventIds.Any(eventId => eventId is < 0 or > 65_535)
            || subscription.EventIds.Distinct().Count() != subscription.EventIds.Count)
        {
            throw Invalid(id, "eventIds must be distinct values between 0 and 65535.");
        }

        if (subscription.Providers is not null
            && (subscription.Providers is not { Count: >= 1 and <= MaximumProviders }
                || subscription.Providers.Any(provider => !IsName(provider, allowSlash: false))
                || subscription.Providers.Distinct(StringComparer.OrdinalIgnoreCase).Count() != subscription.Providers.Count))
        {
            throw Invalid(id, $"providers must list 1–{MaximumProviders} distinct names of letters, digits, spaces or - _ . $ characters.");
        }

        if (string.IsNullOrWhiteSpace(subscription.Pack) || subscription.Parser < 0)
        {
            throw Invalid(id, "pack and a parser index of 0 or more are required.");
        }

        if (subscription.PollIntervalSeconds is < 1 or > 300)
        {
            throw Invalid(id, "pollIntervalSeconds must be between 1 and 300.");
        }

        if (subscription.BatchSize is < 1 or > 256)
        {
            throw Invalid(id, "batchSize must be between 1 and 256.");
        }

        return subscription with
        {
            EventIds = [.. subscription.EventIds.Order()],
            Providers = subscription.Providers is null ? null : [.. subscription.Providers.Order(StringComparer.Ordinal)]
        };
    }

    private static bool IsSubscriptionId(string? id) =>
        id is { Length: >= 1 and <= 63 }
        && (char.IsAsciiLetterLower(id[0]) || char.IsAsciiDigit(id[0]))
        && id.All(character => char.IsAsciiLetterLower(character) || char.IsAsciiDigit(character) || character == '-');

    /// <summary>
    /// Channel and provider names: no quotes, brackets, operators or wildcards, so a name can
    /// never change the meaning of the generated query.
    /// </summary>
    internal static bool IsName(string? value, bool allowSlash) =>
        value is { Length: >= 1 and <= 255 }
        && value[0] != ' ' && value[^1] != ' '
        && value.All(character => char.IsAsciiLetterOrDigit(character)
            || character is ' ' or '-' or '_' or '.'
            || (allowSlash ? character == '/' : character == '$'));

    private static InvalidDataException Invalid(string id, string message) =>
        new($"Windows Event Log subscription {id}: {message}");
}

[JsonSourceGenerationOptions(
    JsonSerializerDefaults.Web,
    NumberHandling = JsonNumberHandling.Strict,
    PropertyNameCaseInsensitive = false,
    AllowDuplicateProperties = false,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectRequiredConstructorParameters = true,
    RespectNullableAnnotations = true)]
[JsonSerializable(typeof(WindowsEventLogSourceConfiguration))]
[JsonSerializable(typeof(WindowsEventBookmark))]
[JsonSerializable(typeof(IReadOnlyList<WindowsEventSubscriptionStatus>))]
internal sealed partial class WindowsEventLogJsonContext : JsonSerializerContext;
