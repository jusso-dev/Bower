using System.Threading.Channels;
using Bower.Contracts;

namespace Bower.Sdk;

internal sealed class BufferedBowerClient : IBowerTelemetry, IBowerTelemetryDiagnostics, IAsyncDisposable
{
    private readonly BowerOptions options;
    private readonly Channel<SecurityEventEnvelope> channel;
    private readonly LocalCollectorTransport transport;
    private readonly CancellationTokenSource shutdown = new();
    private readonly Task sender;
    private readonly object stateLock = new();
    private long accepted, delivered, failed, rejected, retries;
    private string? lastFailureCode;
    private string? stoppedCode;
    private bool disposed;

    public DeliveryStatus DeliveryStatus
    {
        get
        {
            lock (stateLock)
                return new(accepted, delivered, failed, accepted - delivered - failed,
                    rejected, retries, stoppedCode ?? "running", lastFailureCode);
        }
    }

    private readonly TimeProvider clock;

    public BufferedBowerClient(BowerOptions options, TimeProvider? clock = null)
    {
        options.Validate();
        this.options = options;
        this.clock = clock ?? TimeProvider.System;
        channel = Channel.CreateBounded<SecurityEventEnvelope>(
            new BoundedChannelOptions(options.BufferCapacity)
            {
                FullMode = BoundedChannelFullMode.Wait,
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
                securityEvent.RecordCount,
                SdkJsonContext.Default.Int64),
            ["exportFormat"] = System.Text.Json.JsonSerializer.SerializeToElement(
                securityEvent.ExportFormat,
                SdkJsonContext.Default.String)
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
        lock (stateLock)
        {
            if (disposed) return;
            disposed = true;
            stoppedCode ??= "sender-stopped";
            channel.Writer.TryComplete();
        }
        try
        {
            await sender.WaitAsync(options.ShutdownFlushTimeout);
        }
        catch (TimeoutException)
        {
            shutdown.Cancel();
            // HttpClient and delay honour cancellation. Join before disposing resources
            // so every accepted item has a final accounting state on return.
            await sender;
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
        string code;
        lock (stateLock)
        {
            if (stoppedCode is null && channel.Writer.TryWrite(envelope))
            {
                accepted++;
                return ValueTask.FromResult(new EmitResult(true, envelope.EventId, null));
            }
            rejected++;
            code = stoppedCode ?? "bounded-buffer-full";
        }
        if (options.FailApplicationOnTelemetryFailure) throw new BowerDeliveryException(code);
        return ValueTask.FromResult(new EmitResult(false, envelope.EventId, code));
    }

    private async Task SendLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await foreach (SecurityEventEnvelope envelope in channel.Reader.ReadAllAsync(cancellationToken))
            {
                bool sent = false;
                for (int attempt = 1; attempt <= options.MaximumSendAttempts; attempt++)
                {
                    try
                    {
                        await transport.SendAsync(envelope, cancellationToken);
                        sent = true;
                        break;
                    }
                    catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        int status = exception is HttpRequestException { StatusCode: { } code } ? (int)code : 0;
                        lock (stateLock) lastFailureCode = status == 0 ? "collector-unavailable" : $"collector-http-{status}";
                        if (attempt == options.MaximumSendAttempts || status is > 0 and not (408 or 429 or >= 500)) break;
                        lock (stateLock) retries++;
                        await Task.Delay(options.RetryDelay, cancellationToken);
                    }
                }
                lock (stateLock)
                {
                    if (sent) delivered++;
                    else failed++;
                    if (!sent && options.FailApplicationOnTelemetryFailure)
                    {
                        stoppedCode = "sender-faulted";
                        channel.Writer.TryComplete();
                    }
                }
                if (!sent && options.FailApplicationOnTelemetryFailure) return;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            lock (stateLock) lastFailureCode = "shutdown-timeout";
        }
        catch (Exception)
        {
            // Never expose exception text, response bodies or event data.
            lock (stateLock)
            {
                lastFailureCode = "sender-unexpected-failure";
                stoppedCode = "sender-faulted";
            }
        }
        finally
        {
            lock (stateLock)
            {
                stoppedCode ??= "sender-stopped";
                channel.Writer.TryComplete();
                // Includes cancelled in-flight item and all unsent accepted items.
                failed = accepted - delivered;
                while (channel.Reader.TryRead(out _)) { }
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
            TimeGenerated = clock.GetUtcNow(),
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

/// <summary>Source-generated metadata for SDK attribute values (Native AOT safe).</summary>
[System.Text.Json.Serialization.JsonSerializable(typeof(long))]
[System.Text.Json.Serialization.JsonSerializable(typeof(string))]
internal sealed partial class SdkJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
