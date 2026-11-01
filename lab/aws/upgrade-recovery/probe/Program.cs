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
//   native CHANNEL SINCE OUT   4625 identities (+ OUT.ids: expectedId<TAB>recordId<TAB>originRecordId)
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
        kind = "queue", capturedAt = DateTimeOffset.UtcNow, integrity, journal, schemaVersion = schema,
        queued = states[0], uploading = states[1], retrying = states[2], delivered = states[3], deadLettered = states[4],
        total = ids.Count, attemptsAboveOne, identitySetSha256 = Digest(ids), ledgerHeadSequence = headSequence, ledgerHeadHash = headHash, cursors,
        files = Directory.GetFiles(Path.GetDirectoryName(db)!, Path.GetFileName(db) + "*").Select(f => new { name = Path.GetFileName(f), bytes = new FileInfo(f).Length })
    }));
    return 0;
}

if (args is ["native", string channel, string sinceText, string nativeOutput] && OperatingSystem.IsWindows())
{
    DateTimeOffset since = DateTimeOffset.Parse(sinceText, System.Globalization.CultureInfo.InvariantCulture);
    var redactor = new JsonEventRedactor();
    var lines = new StringBuilder();
    var expected = new SortedSet<string>(StringComparer.Ordinal);
    int examined = 0, selected = 0, unselected = 0, changed = 0, duplicates = 0;
    long minRecord = long.MaxValue, maxRecord = 0;
    using var reader = new EventLogReader(new EventLogQuery(channel, PathType.LogName,
        "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4625]]"));
    for (EventRecord? record = reader.ReadEvent(); record is not null; record = reader.ReadEvent())
    {
        using (record)
        {
            if (++examined > MaximumRecords) throw new InvalidDataException("native limit");
            WindowsEvent parsed = WindowsEventXml.Parse(record.ToXml());
            if (parsed.TimeCreated < since) continue;
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
            lines.Append(id).Append('\t').Append(position).Append('\t').Append(parsed.RecordId).Append('\n');
        }
    }
    File.WriteAllText(nativeOutput + ".ids", lines.ToString());
    File.WriteAllText(nativeOutput, JsonSerializer.Serialize(new
    {
        kind = "native", channel, since, capturedAt = DateTimeOffset.UtcNow, examined, selected, unselected,
        distinct = expected.Count, duplicateIdentities = duplicates, redactionChangedIds = changed,
        minRecordId = selected == 0 ? 0 : minRecord, maxRecordId = maxRecord, identitySetSha256 = Digest(expected)
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

Console.Error.WriteLine("usage: queue DB OUT | native CHANNEL SINCE OUT | redact IN OUT");
return 2;
