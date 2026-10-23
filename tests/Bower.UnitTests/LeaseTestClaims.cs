using Bower.Abstractions;

namespace Bower.UnitTests;

internal static class LeaseTestClaims
{
    internal static string? Token(IEnumerable<QueuedEvent> leases, string id) =>
        leases.FirstOrDefault(item => item.EventId == id)?.LeaseToken;

    internal static IReadOnlyDictionary<string, string> Map(IEnumerable<QueuedEvent> leases) =>
        leases.ToDictionary(item => item.EventId, item => item.LeaseToken!, StringComparer.Ordinal);
}
