using Bower.Contracts;
using Bower.Persistence;

namespace Bower.Core;

public static class EventFingerprint
{
    public static string Create(SecurityEventEnvelope value) => EventIdentity.Create(value);
}
