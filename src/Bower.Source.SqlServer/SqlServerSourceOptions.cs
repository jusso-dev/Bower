using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;

namespace Bower.Source.SqlServer;

public enum SqlServerCursorKind
{
    Incrementing,
    Timestamp,
    Composite
}

public sealed record SqlServerColumnMappings
{
    public string Sequence { get; init; } = "AuditId";

    public string EventTime { get; init; } = "EventTime";

    public string Username { get; init; } = "Username";

    public string Action { get; init; } = "Action";

    public string TargetType { get; init; } = "TargetType";

    public string TargetId { get; init; } = "TargetId";

    public string PreviousValue { get; init; } = "PreviousValue";

    public string NewValue { get; init; } = "NewValue";

    public string SourceIpAddress { get; init; } = "SourceIp";
}

public sealed partial record SqlServerSourceOptions
{
    public required string SourceId { get; init; }

    public required string ConnectionString { get; init; }

    public string Schema { get; init; } = "dbo";

    public required string Table { get; init; }

    public SqlServerColumnMappings Columns { get; init; } = new();

    public SqlServerCursorKind CursorKind { get; init; } = SqlServerCursorKind.Incrementing;

    public int BatchSize { get; init; } = 1_000;

    public int CommandTimeoutSeconds { get; init; } = 30;

    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(30);

    public TimeSpan TimestampOverlap { get; init; } = TimeSpan.Zero;

    public long InitialSequence { get; init; }

    public DateTimeOffset InitialTimestamp { get; init; } = DateTimeOffset.UnixEpoch;

    public int MaximumRecordBytes { get; init; } = 65_536;

    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(SourceId);
        ArgumentException.ThrowIfNullOrWhiteSpace(ConnectionString);
        ArgumentException.ThrowIfNullOrWhiteSpace(Table);
        ArgumentNullException.ThrowIfNull(Columns);

        if (SourceId.Length > 128)
        {
            throw new ArgumentException("Source identifier cannot exceed 128 characters.");
        }

        ValidateIdentifier(Schema, nameof(Schema));
        ValidateIdentifier(Table, nameof(Table));
        ValidateIdentifier(Columns.Sequence, nameof(Columns.Sequence));
        ValidateIdentifier(Columns.EventTime, nameof(Columns.EventTime));
        ValidateIdentifier(Columns.Username, nameof(Columns.Username));
        ValidateIdentifier(Columns.Action, nameof(Columns.Action));
        ValidateIdentifier(Columns.TargetType, nameof(Columns.TargetType));
        ValidateIdentifier(Columns.TargetId, nameof(Columns.TargetId));
        ValidateIdentifier(Columns.PreviousValue, nameof(Columns.PreviousValue));
        ValidateIdentifier(Columns.NewValue, nameof(Columns.NewValue));
        ValidateIdentifier(Columns.SourceIpAddress, nameof(Columns.SourceIpAddress));

        if (BatchSize is < 1 or > 10_000)
        {
            throw new ArgumentOutOfRangeException(
                nameof(BatchSize),
                "Batch size must be between 1 and 10,000.");
        }

        if (CommandTimeoutSeconds is < 1 or > 300)
        {
            throw new ArgumentOutOfRangeException(
                nameof(CommandTimeoutSeconds),
                "Command timeout must be between 1 and 300 seconds.");
        }

        if (PollInterval < TimeSpan.FromSeconds(1))
        {
            throw new ArgumentOutOfRangeException(
                nameof(PollInterval),
                "Poll interval must be at least one second.");
        }

        if (TimestampOverlap < TimeSpan.Zero || TimestampOverlap > TimeSpan.FromDays(1))
        {
            throw new ArgumentOutOfRangeException(
                nameof(TimestampOverlap),
                "Timestamp overlap must be between zero and one day.");
        }

        if (CursorKind != SqlServerCursorKind.Timestamp && TimestampOverlap != TimeSpan.Zero)
        {
            throw new ArgumentException(
                "Timestamp overlap is only valid for timestamp cursors.");
        }

        if (InitialSequence < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(InitialSequence));
        }

        if (MaximumRecordBytes is < 1_024 or > 16_777_216)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaximumRecordBytes),
                "Maximum record size must be between 1 KiB and 16 MiB.");
        }

        if ((long)BatchSize * MaximumRecordBytes > 67_108_864)
        {
            throw new ArgumentException(
                "Batch size multiplied by maximum record size cannot exceed 64 MiB.");
        }

        SqlConnectionStringBuilder connection;
        try
        {
            connection = new SqlConnectionStringBuilder(ConnectionString);
        }
        catch (ArgumentException)
        {
            throw new ArgumentException(
                "SQL Server connection string is invalid.",
                nameof(ConnectionString));
        }

        if (connection.ApplicationIntent != ApplicationIntent.ReadOnly)
        {
            throw new ArgumentException(
                "SQL Server connection must set ApplicationIntent=ReadOnly.");
        }
    }

    internal string MappingKey =>
        string.Join(
            '|',
            Schema,
            Table,
            Columns.Sequence,
            Columns.EventTime,
            Columns.Username,
            Columns.Action,
            Columns.TargetType,
            Columns.TargetId,
            Columns.PreviousValue,
            Columns.NewValue,
            Columns.SourceIpAddress);

    private static void ValidateIdentifier(string value, string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, name);
        if (value.Length > 128 ||
            !IdentifierPattern().IsMatch(value))
        {
            throw new ArgumentException(
                "SQL identifiers must start with a letter or underscore and contain only letters, numbers or underscores.",
                name);
        }
    }

    [GeneratedRegex(
        "^[A-Za-z_][A-Za-z0-9_]*$",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 100)]
    private static partial Regex IdentifierPattern();
}
