using Bower.Sdk;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.Services.AddBower(options =>
{
    options.Application.Name = "BowerMinimalApiExample";
    options.Application.Environment = builder.Environment.EnvironmentName;
    options.Application.Instance = Environment.MachineName;
    options.LocalCollector.Endpoint = "http://127.0.0.1:4319";
    options.FailApplicationOnTelemetryFailure = false;
});

WebApplication app = builder.Build();

app.MapPost(
    "/login",
    async (
        LoginRequest request,
        HttpContext httpContext,
        IBowerTelemetry bower,
        CancellationToken cancellationToken) =>
    {
        // Example always denies. Event is emitted only after authentication decision.
        EmitResult telemetry = await bower.AuthenticationFailedAsync(
            new AuthenticationFailedEvent
            {
                Username = request.Username,
                SourceIpAddress = httpContext.Connection.RemoteIpAddress,
                FailureReason = "InvalidPassword",
                CorrelationId = httpContext.TraceIdentifier
            },
            cancellationToken);

        return Results.Json(
            new
            {
                authenticated = false,
                telemetryAcceptedLocally = telemetry.AcceptedForDelivery,
                correlationId = httpContext.TraceIdentifier
            },
            statusCode: StatusCodes.Status401Unauthorized);
    });

app.Run();

internal sealed record LoginRequest(string Username);
