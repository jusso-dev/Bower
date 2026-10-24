using Bower.Collector;

namespace Bower.UnitTests;

public sealed class EventIdentityConflictsTests
{
    [Fact]
    public void Counts_BoundCredentialChurnAndNeverKeyAnonymousInput()
    {
        EventIdentityConflicts counts = new();
        Parallel.For(0, EventIdentityConflicts.MaximumProducers + 10, index =>
        {
            counts.Record($"producer-{index}", authenticated: true);
            counts.Record($"untrusted-{index}", authenticated: false);
        });
        EventIdentityConflictSnapshot before = counts.Snapshot();
        string retained = before.Producers[0].Producer;
        counts.Record(retained, authenticated: true);
        counts.Record(new string('x', 65), authenticated: true);
        EventIdentityConflictSnapshot snapshot = counts.Snapshot();
        Assert.Equal(EventIdentityConflicts.MaximumProducers, snapshot.Producers.Count);
        Assert.Equal(2, snapshot.Producers.Single(item => item.Producer == retained).Count);
        Assert.Equal(EventIdentityConflicts.MaximumProducers + 10, snapshot.Unattributed);
        Assert.Equal(11, snapshot.Overflow);
        Assert.All(snapshot.Producers, item => Assert.StartsWith("producer-", item.Producer, StringComparison.Ordinal));
        Assert.Equal(1, before.Producers[0].Count);
    }
}
