namespace Bower.Source.Journald;

public sealed record JournaldSourceOptions
{
    public const int DefaultMaxRecordBytes = 32 * 1024;
    public const int MaxAllowedRecordBytes = 32 * 1024;
    public const int DefaultMaxBatchSize = 128;
    public const int MaxAllowedBatchSize = 500;
    public const int MaxAllowListEntries = 64;

    public required string SubscriptionName { get; init; }

    /// <summary>Explicit systemd unit names (for example <c>ssh.service</c>, <c>sshd.service</c>).</summary>
    public IReadOnlyList<string> Units { get; init; } = [];

    /// <summary>Explicit <c>SYSLOG_IDENTIFIER</c> values (for example <c>sshd</c>, <c>sudo</c>).</summary>
    public IReadOnlyList<string> Identifiers { get; init; } = [];

    public int MaxRecordBytes { get; init; } = DefaultMaxRecordBytes;

    public int MaxBatchSize { get; init; } = DefaultMaxBatchSize;

    public void Validate()
    {
        if (!IsSafeName(SubscriptionName, maxLength: 64))
        {
            throw new ArgumentException("SubscriptionName must be 1..64 ASCII letters, digits, '.', '_', or '-'.", nameof(SubscriptionName));
        }

        if (Units.Count == 0 && Identifiers.Count == 0)
        {
            throw new ArgumentException("Journald source requires at least one explicit unit or SYSLOG_IDENTIFIER allow-list entry.");
        }

        if (Units.Count + Identifiers.Count > MaxAllowListEntries)
        {
            throw new ArgumentOutOfRangeException(nameof(Units), $"Total allow-list entries cannot exceed {MaxAllowListEntries}.");
        }

        foreach (string unit in Units)
        {
            if (!IsSafeUnitOrIdentifier(unit))
            {
                throw new ArgumentException($"Invalid journald unit allow-list entry '{unit}'. Wildcards and control characters are refused.");
            }
        }

        foreach (string identifier in Identifiers)
        {
            if (!IsSafeUnitOrIdentifier(identifier))
            {
                throw new ArgumentException($"Invalid journald identifier allow-list entry '{identifier}'. Wildcards and control characters are refused.");
            }
        }

        if (MaxRecordBytes is < 512 or > MaxAllowedRecordBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxRecordBytes), $"MaxRecordBytes must be between 512 and {MaxAllowedRecordBytes}.");
        }

        if (MaxBatchSize is < 1 or > MaxAllowedBatchSize)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxBatchSize), $"MaxBatchSize must be between 1 and {MaxAllowedBatchSize}.");
        }
    }

    internal static bool IsSafeName(string? value, int maxLength) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= maxLength
        && value.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '.' or '_' or '-');

    internal static bool IsSafeUnitOrIdentifier(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128
        && !value.Contains('*')
        && !value.Contains('?')
        && value.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '.' or '_' or '-' or '@' or ':');
}
