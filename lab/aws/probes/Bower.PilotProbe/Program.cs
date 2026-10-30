using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Redaction;
using Bower.Source.WindowsEventLog;
using Microsoft.Data.Sqlite;

if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
if (args.Length != 2 || args[0] is not ("source" or "wec")
    || !System.Text.RegularExpressions.Regex.IsMatch(args[1], @"(?:Z|[+-]\d{2}:\d{2})$"))
{
    throw new ArgumentException("Use source|wec followed by an explicit UTC/offset campaign start.");
}
string channel = args[0] == "source" ? "Security" : "ForwardedEvents";
DateTimeOffset since = DateTimeOffset.Parse(args[1], System.Globalization.CultureInfo.InvariantCulture);
const int MaximumRecords = 150_000;
int examinedNative = 0;
var identityRedactor = new JsonEventRedactor();
var rawNativeIds = new SortedSet<string>(StringComparer.Ordinal);
int redactedNativeIdentities = 0;
var nativeIds = new SortedSet<string>(StringComparer.Ordinal);
var perSecond = new SortedDictionary<long, int>();
int selected = 0, unselected = 0;
using (var reader = new EventLogReader(new EventLogQuery(channel, PathType.LogName,
    "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4625]]")))
{
    for (EventRecord? record = reader.ReadEvent(); record is not null; record = reader.ReadEvent())
    {
        using (record)
        {
            if (++examinedNative > MaximumRecords) throw new InvalidDataException("Native probe record limit exceeded");
            WindowsEvent parsed = WindowsEventXml.Parse(record.ToXml());
            if (parsed.TimeCreated < since) continue;
            string? type = parsed.Data.FirstOrDefault(p => p.Key == "data.LogonType").Value;
            string? address = parsed.Data.FirstOrDefault(p => p.Key == "data.IpAddress").Value;
            if (type != "3" || !IPAddress.TryParse(address, out _)) { unselected++; continue; }
            using var input = JsonDocument.Parse(WindowsEventRecord.Build(parsed, "wec-security", null));
            string originalId = input.RootElement.GetProperty("id").GetString()!;
            rawNativeIds.Add(originalId);
            // The deployed signed profile adds only actor.username HMAC to the
            // default detector policy. Event identity passes through that same
            // default privacy policy before persistence, including false positives.
            var redacted = identityRedactor.Redact(JsonSerializer.Serialize(new { eventId = originalId }));
            if (!redacted.Succeeded || redacted.RedactedJson is null) throw new InvalidDataException("Identity privacy failed");
            using var identity = JsonDocument.Parse(redacted.RedactedJson);
            string expectedId = identity.RootElement.GetProperty("eventId").GetString()!;
            if (expectedId != originalId) redactedNativeIdentities++;
            nativeIds.Add(expectedId);
            selected++;
            long second = parsed.TimeCreated.ToUnixTimeSeconds();
            perSecond[second] = perSecond.GetValueOrDefault(second) + 1;
        }
    }
}
string Digest(IEnumerable<string> values) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', values))));
var queueIds = new SortedSet<string>(StringComparer.Ordinal);
int delivered = 0;
bool noRaw = true, pseudonyms = true, integrity = true;
var policyHashes = new SortedSet<string>(StringComparer.Ordinal);
if (channel == "ForwardedEvents")
{
    using var db = new SqliteConnection(@"Data Source=C:\ProgramData\Bower\state\queue.db;Mode=ReadOnly");
    db.Open();
    using var cmd = db.CreateCommand();
    cmd.CommandText = "select event_id,payload,delivered_at from queue_events";
    using (var reader = cmd.ExecuteReader())
    {
        int examinedQueue = 0;
        while (reader.Read())
        {
            if (++examinedQueue > MaximumRecords) throw new InvalidDataException("Queue probe record limit exceeded");
            string payload = reader.GetString(1);
            using var envelope = JsonDocument.Parse(payload);
            if (envelope.RootElement.GetProperty("timeGenerated").GetDateTimeOffset() < since) continue;
            queueIds.Add(reader.GetString(0));
            if (!reader.IsDBNull(2)) delivered++;
            noRaw &= !payload.Contains("bower-probe", StringComparison.OrdinalIgnoreCase);
            pseudonyms &= envelope.RootElement.GetProperty("actor").GetProperty("username").GetString()!.StartsWith("hmac-sha256:", StringComparison.Ordinal);
            policyHashes.Add(envelope.RootElement.GetProperty("security").GetProperty("policyHash").GetString()!);
        }
    }
    cmd.CommandText = "pragma integrity_check";
    integrity = (string?)cmd.ExecuteScalar() == "ok";
}
bool diskClean = true;
if (channel == "ForwardedEvents")
{
    foreach (string file in Directory.GetFiles(@"C:\ProgramData\Bower\state", "queue.db*"))
    {
        using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (stream.Length > 1024L * 1024 * 1024) throw new InvalidDataException("Database scan size limit exceeded");
        byte[] buffer = new byte[1024 * 1024];
        string tail = "";
        int n;
        while ((n = stream.Read(buffer)) > 0)
        {
            string text = tail + Encoding.UTF8.GetString(buffer, 0, n);
            diskClean &= !text.Contains("bower-probe", StringComparison.OrdinalIgnoreCase);
            tail = text.Length > 32 ? text[^32..] : text;
        }
    }
}
int[] rates = perSecond.Values.Order().ToArray();
Console.WriteLine(JsonSerializer.Serialize(new
{
    phase = "native-windows-identities",
    channel,
    queriedAt = DateTimeOffset.UtcNow,
    selectedNativeRecords = selected,
    since = since == DateTimeOffset.MinValue ? (DateTimeOffset?)null : since,
    rawNativeIdentitySetSha256 = Digest(rawNativeIds),
    redactedNativeIdentities,
    noIdentityCollisions = rawNativeIds.Count == nativeIds.Count,
    distinctNativeIds = nativeIds.Count,
    unselectedNativeRecords = unselected,
    nativeIdentitySetSha256 = Digest(nativeIds),
    missingNativeCount = channel == "ForwardedEvents" ? nativeIds.Except(queueIds).Count() : (int?)null,
    unexpectedQueueCount = channel == "ForwardedEvents" ? queueIds.Except(nativeIds).Count() : (int?)null,
    queueRows = queueIds.Count,
    deliveredRows = delivered,
    queueIdentitySetSha256 = Digest(queueIds),
    nativeAndQueueMatch = channel == "ForwardedEvents" ? nativeIds.SetEquals(queueIds) : (bool?)null,
    noRawUsername = channel == "ForwardedEvents" ? (bool?)noRaw : null,
    usernamePseudonymized = channel == "ForwardedEvents" ? (bool?)pseudonyms : null,
    databaseAndWalExcludeUsername = channel == "ForwardedEvents" ? (bool?)diskClean : null,
    sqliteIntegrity = channel == "ForwardedEvents" ? (bool?)integrity : null,
    policyHashes,
    activeSeconds = rates.Length,
    maximumEventsInOneSecond = rates.LastOrDefault(),
    medianEventsPerActiveSecond = rates.Length > 0 ? rates[rates.Length / 2] : 0
}));
