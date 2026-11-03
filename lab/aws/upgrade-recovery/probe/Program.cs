using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bower.Redaction;
using Bower.Source.WindowsEventLog;
using Microsoft.Data.Sqlite;

// ws4 lab probe: metadata and synthetic identities only, never payloads.
//   queue  DB OUT       read-only queue snapshot (+ OUT.ids: eventId<TAB>state)
//   native CHANNEL SINCE OUT [UNTIL]   4625 identities (+ OUT.ids: expectedId<TAB>recordId<TAB>originRecordId<TAB>originalId<TAB>kind);
//          kind is 'canary' for the re-soak's per-minute canary account (bower-canary), else 'bulk'
//          originalId is the unredacted id: collectors whose privacy profile keeps ids compare against it
//          UNTIL (exclusive) bounds the native query to one window, as the soak exports hourly
//   queue-union DB UNION OUT   adds the queue's current identities to UNION (eventId<TAB>firstSeenAt<TAB>receivedAt),
//          so events later purged by retention stay accounted for (soak, every 30 minutes)
const int MaximumRecords = 400_000;
string Digest(IEnumerable<string> values) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', values))));

if (args is ["queue", string db, string output])
{
    using var connection = new SqliteConnection($"Data Source={db};Mode=ReadOnly;Pooling=False");
    connection.Open();
    using var cmd = connection.CreateCommand();
    cmd.CommandText = "PRAGMA quick_check;";
    string integrity = (string)cmd.ExecuteScalar()!;
    cmd.CommandText = "PRAGMA journal_mode;";
    string journal = (string)cmd.ExecuteScalar()!;
    cmd.CommandText = "SELECT MAX(version) FROM schema_history;";
    long schema = (long)cmd.ExecuteScalar()!;
    var states = new long[5];
    var ids = new List<string>();
    var lines = new StringBuilder();
    cmd.CommandText = "SELECT event_id, state, delivery_attempts FROM queue_events_v5 ORDER BY event_id;";
    long attemptsAboveOne = 0;
    using (var reader = cmd.ExecuteReader())
    {
        while (reader.Read())
        {
            if (ids.Count >= MaximumRecords) throw new InvalidDataException("queue limit");
            ids.Add(reader.GetString(0));
            states[reader.GetInt64(1)]++;
            if (reader.GetInt64(2) > 1) attemptsAboveOne++;
            lines.Append(reader.GetString(0)).Append('\t').Append(reader.GetInt64(1)).Append('\n');
        }
    }
    var cursors = new List<object>();
    cmd.CommandText = "SELECT \"SourceId\", \"Value\", \"Version\", \"UpdatedAt\" FROM source_cursors ORDER BY 1;";
    try
    {
        using var reader = cmd.ExecuteReader();
        while (reader.Read()) cursors.Add(new { sourceId = reader.GetString(0), value = reader.GetString(1), version = reader.GetInt64(2), updatedAt = reader.GetString(3) });
    }
    catch (SqliteException) { }
    cmd.CommandText = "SELECT sequence, chain_hash FROM (SELECT sequence, chain_hash FROM queue_ledger UNION ALL SELECT end_sequence, chain_hash FROM queue_ledger_segments) ORDER BY sequence DESC LIMIT 1;";
    long headSequence = 0; string headHash = "";
    using (var reader = cmd.ExecuteReader()) { if (reader.Read()) { headSequence = reader.GetInt64(0); headHash = reader.GetString(1); } }
    File.WriteAllText(output + ".ids", lines.ToString());
    File.WriteAllText(output, JsonSerializer.Serialize(new
    {
        kind = "queue",
        capturedAt = DateTimeOffset.UtcNow,
        integrity,
        journal,
        schemaVersion = schema,
        queued = states[0],
        uploading = states[1],
        retrying = states[2],
        delivered = states[3],
        deadLettered = states[4],
        total = ids.Count,
        attemptsAboveOne,
        identitySetSha256 = Digest(ids),
        ledgerHeadSequence = headSequence,
        ledgerHeadHash = headHash,
        cursors,
        files = Directory.GetFiles(Path.GetDirectoryName(db)!, Path.GetFileName(db) + "*").Select(f => new { name = Path.GetFileName(f), bytes = new FileInfo(f).Length })
    }));
    return 0;
}

if (args is ["receiving-position", string positionChannel])
{
    // The native channel implementation reads a bookmark, not the forwarded event's
    // origin RecordId, and validates the bounded XML without rendering event content.
    if (!OperatingSystem.IsWindows() || positionChannel is not ("ForwardedEvents" or "Application" or "System"))
    {
        Console.Error.WriteLine("receiving-position-unavailable");
        return 2;
    }
    try
    {
        using IWindowsEventChannel source = new WindowsEventLogChannelFactory().Open(positionChannel);
        WindowsChannelRange range = source.GetRange();
        // The channel was selected from the fixed allow-list above. Keep this
        // metadata-only protocol canonical for PowerShell 5.1's strict parser.
        string newest = range.NewestRecordId > 0
            ? range.NewestRecordId.ToString(System.Globalization.CultureInfo.InvariantCulture) : "null";
        Console.WriteLine($"{{\"kind\":\"receiving-position\",\"channel\":\"{positionChannel}\",\"newestRecordId\":{newest}}}");
        return 0;
    }
    catch (Exception)
    {
        Console.Error.WriteLine("receiving-position-unavailable");
        return 1;
    }
}

if (args is ["queue-union", string unionDb, string unionPath, string unionOutput])
{
    const int MaximumUnion = 3_000_000;
    var union = new Dictionary<string, string>(StringComparer.Ordinal);
    if (File.Exists(unionPath))
    {
        foreach (string line in ReadTsvLines(unionPath))
        {
            if (union.Count >= MaximumUnion) throw new InvalidDataException("union limit");
            string[] parts = line.Split('\t');
            if (parts.Length is < 2 or > 4 || !ValidUnionEventId(parts[0])
                || !TryNormalizedTimestamp(parts[1], out _)
                || (parts.Length >= 3 && !TryNormalizedTimestamp(parts[2], out _))
                || (parts.Length == 4 && parts[3].Length > 0 && !TryNormalizedTimestamp(parts[3], out _)))
                throw new InvalidDataException("Invalid queue union row");
            string eventId = parts[0];
            string value = string.Join('\t', parts.Skip(1)); // firstSeenAt, receivedAt, optional generation time
            if (!union.TryAdd(eventId, value) && !String.Equals(union[eventId], value, StringComparison.Ordinal))
            {
                throw new InvalidDataException("Conflicting entries for a queue event identity");
            }
        }
    }
    int before = union.Count, inQueue = 0;
    var states = new long[5];
    string seen = DateTimeOffset.UtcNow.ToString("o");
    using (var connection = new SqliteConnection($"Data Source={unionDb};Mode=ReadOnly;Pooling=False"))
    {
        connection.Open();
        using var cmd = connection.CreateCommand();
        // Only the normalized event time is exported from the already-redacted payload.
        // Do not write payloads or any other payload field to the union or logs.
        cmd.CommandText = "SELECT event_id, state, received_at, CASE WHEN substr(event_id, 1, 7) = 'winevt-' THEN payload ELSE NULL END FROM queue_events_v5;";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            if (++inQueue > MaximumRecords) throw new InvalidDataException("queue limit");
            states[reader.GetInt64(1)]++;
            // The union retains receivedAt for observation; the WEC reconciler scopes by generation time.
            string eventId = reader.GetString(0);
            if (!ValidUnionEventId(eventId)) throw new InvalidDataException("Invalid queue event identity");
            if (!TryNormalizedTimestamp(reader.GetString(2), out _))
                throw new InvalidDataException("Invalid queue event receipt time");
            string generated = reader.IsDBNull(3) ? "" : NormalizedGeneratedTime(reader.GetString(3));
            string value = seen + "\t" + reader.GetString(2) + "\t" + generated;
            if (!union.TryAdd(eventId, value) && generated.Length > 0)
            {
                // A legacy union may lack generation time. Enrich it only while the
                // original row is still present; preserve the original observation times.
                string old = union[eventId];
                string[] fields = old.Split('\t');
                if (fields.Length == 2 || (fields.Length == 3 && fields[2].Length == 0))
                {
                    union[eventId] = fields[0] + "\t" + fields[1] + "\t" + generated;
                }
                else if (fields.Length == 3 && TryNormalizedTimestamp(fields[2], out string prior)
                         && !String.Equals(prior, generated, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Conflicting generation times for a queue event identity");
                }
            }
        }
    }
    if (union.Count > MaximumUnion) throw new InvalidDataException("union limit");
    var text = new StringBuilder();
    foreach (var pair in union.OrderBy(p => p.Key, StringComparer.Ordinal)) text.Append(pair.Key).Append('\t').Append(pair.Value).Append('\n');
    File.WriteAllText(unionPath + ".new", text.ToString());
    File.Move(unionPath + ".new", unionPath, true);
    File.WriteAllText(unionOutput, JsonSerializer.Serialize(new
    {
        kind = "queue-union",
        capturedAt = seen,
        inQueue,
        queued = states[0],
        uploading = states[1],
        retrying = states[2],
        delivered = states[3],
        deadLettered = states[4],
        unionBefore = before,
        unionAfter = union.Count,
        added = union.Count - before
    }));
    return 0;
}

if (args is ["native", string channel, string sinceText, string nativeOutput, ..] && args.Length <= 5 && OperatingSystem.IsWindows())
{
    DateTimeOffset since = DateTimeOffset.Parse(sinceText, System.Globalization.CultureInfo.InvariantCulture);
    DateTimeOffset? until = args.Length == 5 ? DateTimeOffset.Parse(args[4], System.Globalization.CultureInfo.InvariantCulture) : null;
    if (until <= since)
    {
        // An empty window would export 'selected: 0' that reads as a complete window.
        Console.Error.WriteLine("UNTIL must be later than SINCE");
        return 2;
    }
    string window = until is null ? "" : string.Create(System.Globalization.CultureInfo.InvariantCulture,
        $" and TimeCreated[@SystemTime>='{since.UtcDateTime:yyyy-MM-ddTHH:mm:ss.fffZ}' and @SystemTime<'{until.Value.UtcDateTime:yyyy-MM-ddTHH:mm:ss.fffZ}']");
    var redactor = new JsonEventRedactor();
    var lines = new StringBuilder();
    var expected = new SortedSet<string>(StringComparer.Ordinal);
    int examined = 0, selected = 0, unselected = 0, changed = 0, duplicates = 0, canaries = 0;
    long minRecord = long.MaxValue, maxRecord = 0;
    DateTimeOffset captureStartedAt = DateTimeOffset.UtcNow;
    using var reader = new EventLogReader(new EventLogQuery(channel, PathType.LogName,
        "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4625" + window + "]]"));
    for (EventRecord? record = reader.ReadEvent(); record is not null; record = reader.ReadEvent())
    {
        using (record)
        {
            if (++examined > MaximumRecords) throw new InvalidDataException("native limit");
            WindowsEvent parsed = WindowsEventXml.Parse(record.ToXml());
            if (parsed.TimeCreated < since || parsed.TimeCreated >= until) continue;
            string? type = parsed.Data.FirstOrDefault(p => p.Key == "data.LogonType").Value;
            string? address = parsed.Data.FirstOrDefault(p => p.Key == "data.IpAddress").Value;
            if (type != "3" || !IPAddress.TryParse(address, out _)) { unselected++; continue; }
            using var input = JsonDocument.Parse(WindowsEventRecord.Build(parsed, "wec-security", null));
            string originalId = input.RootElement.GetProperty("id").GetString()!;
            var redacted = redactor.Redact(JsonSerializer.Serialize(new { eventId = originalId }));
            if (!redacted.Succeeded || redacted.RedactedJson is null) throw new InvalidDataException("identity privacy failed");
            using var identity = JsonDocument.Parse(redacted.RedactedJson);
            string id = identity.RootElement.GetProperty("eventId").GetString()!;
            if (id != originalId) changed++;
            if (!expected.Add(id)) duplicates++;
            selected++;
            long position = record.RecordId ?? -1;
            minRecord = Math.Min(minRecord, position); maxRecord = Math.Max(maxRecord, position);
            // Only the account class leaves the probe, never the account name.
            bool canary = string.Equals(parsed.Data.FirstOrDefault(p => p.Key == "data.TargetUserName").Value, "bower-canary", StringComparison.OrdinalIgnoreCase);
            if (canary) canaries++;
            lines.Append(id).Append('\t').Append(position).Append('\t').Append(parsed.RecordId).Append('\t').Append(originalId)
                .Append('\t').Append(canary ? "canary" : "bulk").Append('\n');
        }
    }
    File.WriteAllText(nativeOutput + ".ids", lines.ToString());
    File.WriteAllText(nativeOutput, JsonSerializer.Serialize(new
    {
        kind = "native",
        channel,
        since,
        until,
        captureStartedAt,
        capturedAt = DateTimeOffset.UtcNow,
        examined,
        selected,
        unselected,
        canaries,
        distinct = expected.Count,
        duplicateIdentities = duplicates,
        redactionChangedIds = changed,
        minRecordId = selected == 0 ? 0 : minRecord,
        maxRecordId = maxRecord,
        identitySetSha256 = Digest(expected)
    }));
    return 0;
}

if (args is ["redact", string idsIn, string idsOut])
{
    // Default detectors over {"eventId": ID}, as persisted identities are redacted.
    var redactor = new JsonEventRedactor();
    var mapped = new StringBuilder();
    foreach (string line in File.ReadLines(idsIn))
    {
        var redacted = redactor.Redact(JsonSerializer.Serialize(new { eventId = line }));
        if (!redacted.Succeeded || redacted.RedactedJson is null) throw new InvalidDataException("identity privacy failed");
        using var identity = JsonDocument.Parse(redacted.RedactedJson);
        mapped.Append(line).Append('\t').Append(identity.RootElement.GetProperty("eventId").GetString()).Append('\n');
    }
    File.WriteAllText(idsOut, mapped.ToString());
    return 0;
}

Console.Error.WriteLine("usage: queue DB OUT | queue-union DB UNION OUT | receiving-position CHANNEL | native CHANNEL SINCE OUT [UNTIL] | redact IN OUT");
return 2;

static string NormalizedGeneratedTime(string payload)
{
    try
    {
        using JsonDocument document = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 32 });
        if (document.RootElement.ValueKind != JsonValueKind.Object) return "";
        JsonElement value = default;
        int matches = 0;
        foreach (JsonProperty property in document.RootElement.EnumerateObject())
        {
            if (property.NameEquals("timeGenerated"))
            {
                value = property.Value;
                matches++;
            }
        }
        if (matches != 1 || value.ValueKind != JsonValueKind.String) return "";
        return TryNormalizedTimestamp(value.GetString(), out string generated) ? generated : "";
    }
    catch (JsonException)
    {
        return "";
    }
}

static bool ValidUnionEventId(string eventId) => eventId.Length > 0
    && !eventId.Any(c => char.IsControl(c) || char.GetUnicodeCategory(c) is
        System.Globalization.UnicodeCategory.LineSeparator or System.Globalization.UnicodeCategory.ParagraphSeparator)
    && (!eventId.StartsWith("winevt-", StringComparison.Ordinal)
        || System.Text.RegularExpressions.Regex.IsMatch(eventId, @"\Awinevt-[0-9a-f]{32}\z"));

static IEnumerable<string> ReadTsvLines(string path)
{
    using var reader = new StreamReader(path);
    char[] buffer = new char[8192];
    var line = new StringBuilder();
    bool pendingCarriageReturn = false;
    int count;
    while ((count = reader.Read(buffer, 0, buffer.Length)) > 0)
    {
        for (int i = 0; i < count; i++)
        {
            char current = buffer[i];
            if (pendingCarriageReturn)
            {
                if (current != '\n') throw new InvalidDataException("Bare carriage return in queue union");
                yield return line.ToString();
                line.Clear();
                pendingCarriageReturn = false;
            }
            else if (current == '\r')
            {
                pendingCarriageReturn = true;
            }
            else if (current == '\n')
            {
                yield return line.ToString();
                line.Clear();
            }
            else
            {
                line.Append(current);
            }
        }
    }
    if (pendingCarriageReturn) throw new InvalidDataException("Bare carriage return in queue union");
    if (line.Length > 0) yield return line.ToString();
}

static bool TryNormalizedTimestamp(string? raw, out string normalized)
{
    normalized = "";
    if (raw is null || !System.Text.RegularExpressions.Regex.IsMatch(raw,
        @"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})\z")
        || !DateTimeOffset.TryParse(raw, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.None, out DateTimeOffset timestamp)) return false;
    normalized = timestamp.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture);
    return true;
}
