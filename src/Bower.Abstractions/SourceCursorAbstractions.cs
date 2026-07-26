namespace Bower.Abstractions;

public sealed record SourceCursorSnapshot(string Value, long Version);

public interface ISourceCursorStore
{
    Task<SourceCursorSnapshot?> ReadAsync(
        string sourceId,
        CancellationToken cancellationToken = default);

    Task<bool> TryAdvanceAsync(
        string sourceId,
        long expectedVersion,
        string value,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken = default);
}
