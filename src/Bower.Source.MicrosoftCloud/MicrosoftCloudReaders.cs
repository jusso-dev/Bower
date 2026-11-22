using System.Text.Json;

namespace Bower.Source.MicrosoftCloud;

/// <summary>The span one read covers: a time window, or one UTC day's snapshot.</summary>
/// <param name="Start">Window kinds: inclusive lower bound.</param>
/// <param name="End">Window kinds: exclusive upper bound. Snapshot kinds: when the snapshot started.</param>
/// <param name="SnapshotDate">Snapshot kinds: the UTC day (yyyy-MM-dd).</param>
internal sealed record MicrosoftCloudSpan(DateTimeOffset Start, DateTimeOffset End, string? SnapshotDate = null);

/// <summary>One page: finished records (each with its event id), the next page and how many items were out of scope.</summary>
/// <param name="OutOfScope">Items the source kind never turns into records (for example compliant devices): dropped in memory, before any parser.</param>
internal sealed record MicrosoftCloudPage(IReadOnlyList<string> Records, string? Next, int Items, int OutOfScope);

/// <summary>
/// One source kind: the API it reads, the one host its token may be sent to, and how an API
/// item becomes a bounded record. Readers only ever request the fields they map.
/// </summary>
internal abstract class MicrosoftCloudReader
{
    /// <summary>Microsoft documents a seven day window for most audit APIs; never read further back.</summary>
    public virtual TimeSpan MaximumLookback => TimeSpan.FromDays(7);

    /// <summary>Longest window read before the cursor commits its upper bound.</summary>
    public virtual TimeSpan MaximumWindow => TimeSpan.FromHours(24);

    /// <summary>Snapshot kinds read the full set once per UTC day instead of a time window.</summary>
    public virtual bool IsSnapshot => false;

    public abstract string Scope(MicrosoftCloudInputOptions input);

    public abstract string Host(MicrosoftCloudInputOptions input);

    public abstract Uri FirstPage(MicrosoftCloudInputOptions input, MicrosoftCloudSpan span);

    public abstract MicrosoftCloudPage Read(MicrosoftCloudInputOptions input, MicrosoftCloudSpan span, MicrosoftCloudResponse response);

    /// <summary>
    /// A next link is stored in the cursor and followed with a bearer token, so it must pass
    /// the same host check as a request before the page that returned it is committed.
    /// </summary>
    internal MicrosoftCloudPage Checked(MicrosoftCloudInputOptions input, MicrosoftCloudPage page)
    {
        if (page.Next is { } next
            && (!Uri.TryCreate(next, UriKind.Absolute, out Uri? uri) || !MicrosoftCloudHttp.IsAllowed(uri, Host(input))))
        {
            throw new MicrosoftCloudException(MicrosoftCloudFailures.HostRefused);
        }

        return page;
    }

    public virtual async Task<MicrosoftCloudPage> ReadPageAsync(
        MicrosoftCloudHttp http,
        MicrosoftCloudInputOptions input,
        MicrosoftCloudSpan span,
        string? page,
        CancellationToken cancellationToken)
    {
        Uri uri = page is null ? FirstPage(input, span) : new Uri(page, UriKind.Absolute);
        using MicrosoftCloudResponse response = await http.SendAsync(
            HttpMethod.Get, uri, input, Scope(input), Host(input), cancellationToken);
        return Checked(input, Read(input, span, response));
    }

    public static MicrosoftCloudReader For(string kind) => kind switch
    {
        MicrosoftCloudKinds.IntuneAudit => new IntuneAuditReader(),
        MicrosoftCloudKinds.IntuneDeviceCompliance => new IntuneComplianceReader(),
        _ => throw new InvalidDataException("Unsupported Microsoft cloud source kind.")
    };

    /// <summary>The <c>value</c> array of an OData collection and its <c>@odata.nextLink</c>.</summary>
    protected static (IReadOnlyList<JsonElement> Items, string? Next) ODataPage(MicrosoftCloudResponse response)
    {
        JsonElement root = response.Document.RootElement;
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("value", out JsonElement value)
            || value.ValueKind != JsonValueKind.Array)
        {
            throw new MicrosoftCloudException(MicrosoftCloudFailures.ResponseInvalid);
        }

        string? next = null;
        if (root.TryGetProperty("@odata.nextLink", out JsonElement link))
        {
            next = link.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(link.GetString())
                ? link.GetString()
                : throw new MicrosoftCloudException(MicrosoftCloudFailures.ResponseInvalid);
            if (!Uri.TryCreate(next, UriKind.Absolute, out _))
            {
                throw new MicrosoftCloudException(MicrosoftCloudFailures.ResponseInvalid);
            }
        }

        return ([.. value.EnumerateArray()], next);
    }
}

internal abstract class GraphReader : MicrosoftCloudReader
{
    public const string GraphHost = "graph.microsoft.com";

    public override string Scope(MicrosoftCloudInputOptions input) => "https://graph.microsoft.com/.default";

    public override string Host(MicrosoftCloudInputOptions input) => GraphHost;
}

/// <summary>
/// <c>GET /v1.0/deviceManagement/auditEvents</c>, filtered to the window on
/// <c>activityDateTime</c>. Least privileged application permission:
/// <c>DeviceManagementApps.Read.All</c>. Modified property values are never read: they can
/// carry configuration secrets and personal data. Only their names are kept.
/// </summary>
internal sealed class IntuneAuditReader : GraphReader
{
    /// <summary>Envelope limits: actions and target types hold 128 characters, labels and identities 256.</summary>
    internal const int Action = 128;
    internal const int Label = 256;

    public override Uri FirstPage(MicrosoftCloudInputOptions input, MicrosoftCloudSpan span)
    {
        string filter = $"activityDateTime ge {MicrosoftCloudHttp.Time(span.Start)} and activityDateTime lt {MicrosoftCloudHttp.Time(span.End)}";
        return new Uri($"https://{GraphHost}/v1.0/deviceManagement/auditEvents?$filter={MicrosoftCloudHttp.Escape(filter)}");
    }

    public override MicrosoftCloudPage Read(MicrosoftCloudInputOptions input, MicrosoftCloudSpan span, MicrosoftCloudResponse response)
    {
        (IReadOnlyList<JsonElement> items, string? next) = ODataPage(response);
        List<string> records = new(items.Count);
        int outOfScope = 0;
        foreach (JsonElement item in items)
        {
            string? id = MicrosoftCloudRecord.String(item, "id");
            string? time = MicrosoftCloudRecord.Time(MicrosoftCloudRecord.String(item, "activityDateTime"));
            if (id is null || time is null)
            {
                outOfScope++;
                continue;
            }

            JsonElement actor = MicrosoftCloudRecord.Object(item, "actor");
            JsonElement[] resources = [.. MicrosoftCloudRecord.Array(item, "resources").Where(resource => resource.ValueKind == JsonValueKind.Object)];
            JsonElement resource = resources.Length > 0 ? resources[0] : default;
            records.Add(new MicrosoftCloudRecord(input)
                .Add("auditEventId", id, Label)
                .Add("activityDateTime", time)
                .Add("activity", MicrosoftCloudRecord.String(item, "activity"), Action)
                .Add("activityType", MicrosoftCloudRecord.String(item, "activityType"), Action)
                .Add("activityOperationType", MicrosoftCloudRecord.String(item, "activityOperationType"), Label)
                .Add("activityResult", MicrosoftCloudRecord.String(item, "activityResult"), Label)
                .Add("category", MicrosoftCloudRecord.String(item, "category"), Label)
                .Add("componentName", MicrosoftCloudRecord.String(item, "componentName"), Label)
                .Add("correlationId", MicrosoftCloudRecord.String(item, "correlationId"), Label)
                .Add("actorType", MicrosoftCloudRecord.String(actor, "auditActorType") ?? MicrosoftCloudRecord.String(actor, "type"), Label)
                .Add("actorUserPrincipalName", MicrosoftCloudRecord.String(actor, "userPrincipalName"), Label)
                .Add("actorUserId", MicrosoftCloudRecord.String(actor, "userId"), Label)
                .Add("actorApplicationId", MicrosoftCloudRecord.String(actor, "applicationId"), Label)
                .Add("actorApplicationName", MicrosoftCloudRecord.String(actor, "applicationDisplayName"), Label)
                .Add("actorServicePrincipalName", MicrosoftCloudRecord.String(actor, "servicePrincipalName"), Label)
                .Add("actorIpAddress", MicrosoftCloudRecord.Address(MicrosoftCloudRecord.String(actor, "ipAddress")))
                .Add("resourceType", MicrosoftCloudRecord.String(resource, "auditResourceType") ?? MicrosoftCloudRecord.String(resource, "type"), Action)
                .Add("resourceId", MicrosoftCloudRecord.String(resource, "resourceId"), Label)
                .Add("resourceName", MicrosoftCloudRecord.String(resource, "displayName"), Label)
                .Add("resourceCount", resources.Length == 0 ? null : resources.Length.ToString(System.Globalization.CultureInfo.InvariantCulture))
                .Add("modifiedProperties", MicrosoftCloudRecord.Join(resources
                    .SelectMany(item => MicrosoftCloudRecord.Array(item, "modifiedProperties"))
                    .Select(property => MicrosoftCloudRecord.String(property, "displayName"))))
                .Build(id));
        }

        return new MicrosoftCloudPage(records, next, items.Count, outOfScope);
    }
}

/// <summary>
/// Once per UTC day, <c>GET /v1.0/deviceManagement/managedDevices</c> with <c>$select</c>
/// limited to compliance fields. Least privileged application permission:
/// <c>DeviceManagementManagedDevices.Read.All</c>. Device name, IMEI, serial number, phone
/// number, MAC addresses, email address and hardware inventory are never requested. Devices whose state
/// is not in the input's <c>complianceStates</c> are dropped in memory.
/// </summary>
internal sealed class IntuneComplianceReader : GraphReader
{
    internal const string Select =
        "id,complianceState,operatingSystem,osVersion,lastSyncDateTime,userPrincipalName,userId,"
        + "azureADDeviceId,managedDeviceOwnerType,isEncrypted,jailBroken,complianceGracePeriodExpirationDateTime";

    public override bool IsSnapshot => true;

    public override Uri FirstPage(MicrosoftCloudInputOptions input, MicrosoftCloudSpan span) =>
        new($"https://{GraphHost}/v1.0/deviceManagement/managedDevices?$select={Select}");

    public override MicrosoftCloudPage Read(MicrosoftCloudInputOptions input, MicrosoftCloudSpan span, MicrosoftCloudResponse response)
    {
        (IReadOnlyList<JsonElement> items, string? next) = ODataPage(response);
        HashSet<string> states = new(MicrosoftCloudSourceConfigurationLoader.ComplianceStates(input), StringComparer.Ordinal);
        string snapshotAt = MicrosoftCloudSourceConfigurationLoader.Format(span.End);
        List<string> records = [];
        int outOfScope = 0;
        foreach (JsonElement item in items)
        {
            string? id = MicrosoftCloudRecord.String(item, "id");
            string? state = MicrosoftCloudRecord.String(item, "complianceState");
            if (id is null || state is null || !states.Contains(state))
            {
                outOfScope++;
                continue;
            }

            records.Add(new MicrosoftCloudRecord(input)
                .Add("snapshotDate", span.SnapshotDate)
                .Add("snapshotAt", snapshotAt)
                .Add("deviceId", id, IntuneAuditReader.Label)
                .Add("complianceState", state, IntuneAuditReader.Label)
                .Add("operatingSystem", MicrosoftCloudRecord.String(item, "operatingSystem"), IntuneAuditReader.Label)
                .Add("osVersion", MicrosoftCloudRecord.String(item, "osVersion"), IntuneAuditReader.Label)
                .Add("lastSyncDateTime", MicrosoftCloudRecord.Time(MicrosoftCloudRecord.String(item, "lastSyncDateTime")))
                .Add("userPrincipalName", MicrosoftCloudRecord.String(item, "userPrincipalName"), IntuneAuditReader.Label)
                .Add("userId", MicrosoftCloudRecord.String(item, "userId"), IntuneAuditReader.Label)
                .Add("azureADDeviceId", MicrosoftCloudRecord.String(item, "azureADDeviceId"), IntuneAuditReader.Label)
                .Add("ownerType", MicrosoftCloudRecord.String(item, "managedDeviceOwnerType"), IntuneAuditReader.Label)
                .Add("isEncrypted", MicrosoftCloudRecord.String(item, "isEncrypted"), IntuneAuditReader.Label)
                .Add("jailBroken", MicrosoftCloudRecord.String(item, "jailBroken"), IntuneAuditReader.Label)
                .Add("gracePeriodExpires", MicrosoftCloudRecord.Time(MicrosoftCloudRecord.String(item, "complianceGracePeriodExpirationDateTime")))
                .Build(id + "\u001f" + span.SnapshotDate));
        }

        return new MicrosoftCloudPage(records, next, items.Count, outOfScope);
    }
}
