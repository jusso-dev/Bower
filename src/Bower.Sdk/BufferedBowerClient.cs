using System.Threading.Channels;
using Bower.Contracts;

namespace Bower.Sdk;

internal sealed class BufferedBowerClient : IBowerTelemetry, IAsyncDisposable
{
    private readonly BowerOptions options;
    private readonly Channel<SecurityEventEnvelope> channel;
    private readonly LocalCollectorTransport transport;
    private readonly CancellationTokenSource shutdown = new();
    private readonly Task sender;

    public BufferedBowerClient(BowerOptions options)
    {
        options.Validate();
        this.options = options;
        channel = Channel.CreateBounded<SecurityEventEnvelope>(
            new BoundedChannelOptions(options.BufferCapacity)
            {
                FullMode = BoundedChannelFullMode.DropWrite,
                SingleReader = true,
                SingleWriter = false,
                AllowSynchronousContinuations = false
            });
        transport = new LocalCollectorTransport(options.LocalCollector);
        sender = Task.Run(() => SendLoopAsync(shutdown.Token));
    }

    public ValueTask<EmitResult> AuthenticationFailedAsync(
        AuthenticationFailedEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.Username);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.FailureReason);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.CorrelationId);

        SecurityEventEnvelope envelope = CreateEnvelope(
            SecurityEventCategories.Authentication,
            SecurityEventTypes.AuthenticationFailure,
            "authentication.attempt",
            EventResult.Failure,
            securityEvent.FailureReason,
            new ActorContext
            {
                UserId = securityEvent.UserId,
                Username = securityEvent.Username,
                Type = ActorType.Human
            },
            null,
            securityEvent.SourceIpAddress is null
                ? null
                : new SourceContext { IpAddress = securityEvent.SourceIpAddress.ToString() },
            securityEvent.CorrelationId,
            securityEvent.OriginalEventId);
        return EnqueueAsync(envelope, cancellationToken);
    }

    public ValueTask<EmitResult> RoleMembershipChangedAsync(
        RoleMembershipChangedEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.ActorUserId);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.TargetUserId);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.Role);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.CorrelationId);

        SecurityEventEnvelope envelope = CreateEnvelope(
            SecurityEventCategories.IdentityManagement,
            SecurityEventTypes.RoleMembershipChanged,
            securityEvent.Change == MembershipChange.Added ? "role.add" : "role.remove",
            EventResult.Success,
            securityEvent.Reason,
            new ActorContext { UserId = securityEvent.ActorUserId, Type = ActorType.Human },
            new TargetContext { Type = "user", Id = securityEvent.TargetUserId },
            null,
            securityEvent.CorrelationId,
            null) with
        {
            Change = new ChangeContext
            {
                Field = "role",
                PreviousValue = securityEvent.Change == MembershipChange.Added ? null : securityEvent.Role,
                NewValue = securityEvent.Change == MembershipChange.Added ? securityEvent.Role : null
            }
        };
        return EnqueueAsync(envelope, cancellationToken);
    }

    public ValueTask<EmitResult> SensitiveDataExportedAsync(
        SensitiveDataExportedEvent securityEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.ActorUserId);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.ExportId);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.DataClassification);
        ArgumentException.ThrowIfNullOrWhiteSpace(securityEvent.CorrelationId);
        if (securityEvent.RecordCount < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(securityEvent),
                "RecordCount cannot be negative.");
        }

        Dictionary<string, System.Text.Json.JsonElement> attributes = new()
        {
            ["recordCount"] = System.Text.Json.JsonSerializer.SerializeToElement(
                securityEvent.RecordCount),
            ["exportFormat"] = System.Text.Json.JsonSerializer.SerializeToElement(
                securityEvent.ExportFormat)
        };
        SecurityEventEnvelope envelope = CreateEnvelope(
            SecurityEventCategories.DataAccess,
            SecurityEventTypes.SensitiveDataExported,
            "data.export",
            EventResult.Success,
            null,
            new ActorContext { UserId = securityEvent.ActorUserId, Type = ActorType.Human },
            new TargetContext { Type = "export", Id = securityEvent.ExportId },
            null,
            securityEvent.CorrelationId,
            securityEvent.ExportId) with
        {
            Labels = new Dictionary<string, string>
            {
                ["dataClassification"] = securityEvent.DataClassification
            },
            Attributes = attributes
        };
        return EnqueueAsync(envelope, cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        channel.Writer.TryComplete();
        using CancellationTokenSource timeout = new(options.ShutdownFlushTimeout);
        try
        {
            await sender.WaitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            shutdown.Cancel();
        }
        finally
        {
            shutdown.Dispose();
            transport.Dispose();
        }
    }

    private ValueTask<EmitResult> EnqueueAsync(
        SecurityEventEnvelope envelope,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (channel.Writer.TryWrite(envelope))
        {
            return ValueTask.FromResult(new EmitResult(true, envelope.EventId, null));
        }

        if (options.FailApplicationOnTelemetryFailure)
        {
            throw new BowerDeliveryException("bounded-buffer-full");
        }

        return ValueTask.FromResult(
            new EmitResult(false, envelope.EventId, "bounded-buffer-full"));
    }

    private async Task SendLoopAsync(CancellationToken cancellationToken)
    {
        await foreach (SecurityEventEnvelope envelope in channel.Reader.ReadAllAsync(
                           cancellationToken))
        {
            try
            {
                await transport.SendAsync(envelope, cancellationToken);
            }
            catch (Exception exception) when (
                exception is HttpRequestException or TaskCanceledException)
            {
                if (options.FailApplicationOnTelemetryFailure)
                {
                    shutdown.Cancel();
                    return;
                }

                // Transport failures stay payload-free. Host can observe failed send count
                // through a future metrics adapter without exposing event content.
            }
        }
    }

    private SecurityEventEnvelope CreateEnvelope(
        string category,
        string eventType,
        string action,
        EventResult result,
        string? reason,
        ActorContext? actor,
        TargetContext? target,
        SourceContext? source,
        string correlationId,
        string? originalId)
    {
        return new SecurityEventEnvelope
        {
            SchemaVersion = SecurityEventEnvelope.CurrentSchemaVersion,
            EventId = Guid.CreateVersion7().ToString(),
            EventOriginalId = originalId,
            TimeGenerated = DateTimeOffset.UtcNow,
            EventCategory = category,
            EventType = eventType,
            EventAction = action,
            EventResult = result,
            EventOutcomeReason = reason,
            Application = new ApplicationContext
            {
                Name = options.Application.Name,
                Version = options.Application.Version,
                Environment = options.Application.Environment,
                Instance = options.Application.Instance,
                TenantId = options.Application.TenantId
            },
            Actor = actor,
            Target = target,
            Source = source,
            Request = new RequestContext { CorrelationId = correlationId }
        };
    }
}

public sealed class BowerDeliveryException(string safeFailureCode)
    : Exception($"Bower telemetry delivery failed: {safeFailureCode}")
{
}
