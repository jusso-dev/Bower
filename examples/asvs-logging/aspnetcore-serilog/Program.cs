// ASP.NET Core with Serilog, forwarded headers from trusted proxies only, request IDs and Bower
// security events. Optional example: not in Bower.sln.
//   BOWER_COLLECTOR_URL=... BOWER_INGEST_TOKEN=... TRUSTED_PROXIES=10.0.0.0/8 dotnet run
//   dotnet run -- contract ../contract/cases.json      (prints the cross-language contract events)
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using AsvsSerilogExample;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.HttpOverrides;
using Serilog;
using Serilog.Formatting.Compact;

if (args is ["contract", string casesPath])
{
    Contract.Print(casesPath);
    return;
}

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Application logs: compact JSON (CR and LF escaped, V16.4.1), UTC, and secret-named
// properties dropped before any sink sees them (V16.2.5). Security events go to Bower.
builder.Host.UseSerilog((context, configuration) => configuration
    .ReadFrom.Configuration(context.Configuration)
    .Enrich.FromLogContext()
    .Filter.ByExcluding(log => log.Properties.Keys.Any(BowerEvents.IsSecret))
    .WriteTo.Console(new RenderedCompactJsonFormatter()));

// V15.3.4, V4.1.3: believe X-Forwarded-For only from the listed proxies. Clearing both lists
// and adding nothing would make ASP.NET Core trust every peer, so the middleware is only
// enabled when TRUSTED_PROXIES names at least one network.
string[] trustedProxies = (Environment.GetEnvironmentVariable("TRUSTED_PROXIES") ?? string.Empty)
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor;
    options.ForwardLimit = null; // walk every hop, stopping at the first untrusted one
    options.KnownProxies.Clear();
    options.KnownIPNetworks.Clear();
    foreach (string cidr in trustedProxies)
    {
        options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(cidr.Contains('/') ? cidr : cidr + (cidr.Contains(':') ? "/128" : "/32")));
    }
});

string collector = Environment.GetEnvironmentVariable("BOWER_COLLECTOR_URL") ?? "http://127.0.0.1:4319";
builder.Services.AddHttpClient<BowerSender>(http =>
{
    http.BaseAddress = new Uri(collector.TrimEnd('/') + "/");
    http.Timeout = TimeSpan.FromSeconds(2);
    if (Environment.GetEnvironmentVariable("BOWER_INGEST_TOKEN") is { Length: > 0 } token)
    {
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }
});

WebApplication app = builder.Build();
JsonObject appInfo = new() { ["name"] = "aspnetcore-serilog-example", ["environment"] = app.Environment.EnvironmentName, ["version"] = "1.0.0" };

if (trustedProxies.Length > 0)
{
    app.UseForwardedHeaders();
}

app.Use(async (context, next) =>
{
    // Request ID: W3C trace id from Activity (honours traceparent), else TraceIdentifier.
    string requestId = System.Diagnostics.Activity.Current?.TraceId.ToHexString() ?? context.TraceIdentifier;
    context.Items["bower.requestId"] = requestId;
    context.Response.Headers["X-Request-Id"] = requestId;
    using (Serilog.Context.LogContext.PushProperty("RequestId", requestId))
    {
        await next();
    }
});
app.UseSerilogRequestLogging();

void Security(HttpContext context, JsonObject spec)
{
    spec["sourceIp"] = context.Connection.RemoteIpAddress?.ToString();
    spec["userAgent"] = context.Request.Headers.UserAgent.ToString();
    spec["route"] ??= (context.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText ?? context.Request.Path.Value;
    spec["request"] = new JsonObject
    {
        ["correlationId"] = context.Items["bower.requestId"]?.ToString(),
        ["method"] = context.Request.Method,
        ["path"] = context.Request.Path.Value,
    };
    context.RequestServices.GetRequiredService<BowerSender>().Send(BowerEvents.Build(appInfo, spec));
}

// Last resort (V16.3.4, V16.5.1, V16.5.4): generic body out, event to Bower.
app.UseExceptionHandler(handler => handler.Run(async context =>
{
    Exception? error = context.Features.Get<IExceptionHandlerFeature>()?.Error;
    bool malformed = error is BadHttpRequestException;
    Security(context, malformed
        ? new JsonObject { ["eventCategory"] = "application-security", ["eventType"] = "input_validation_failure", ["eventAction"] = "validation.reject",
            ["eventResult"] = "failure", ["eventSeverity"] = "low", ["reason"] = "MalformedJson" }
        : new JsonObject { ["eventCategory"] = "application-security", ["eventType"] = "application_error", ["eventAction"] = "error.unhandled",
            ["eventResult"] = "failure", ["eventSeverity"] = "medium", ["reason"] = "UnhandledException",
            ["labels"] = new JsonObject { ["errorType"] = error?.GetType().Name ?? "Exception" } });
    context.Response.StatusCode = malformed ? 400 : 500;
    await context.Response.WriteAsJsonAsync(new { error = malformed ? "bad request" : "internal error", requestId = context.Items["bower.requestId"] });
}));

app.MapPost("/login", async (HttpContext context) =>
{
    LoginRequest? body;
    try
    {
        body = await context.Request.ReadFromJsonAsync<LoginRequest>();
    }
    catch (System.Text.Json.JsonException)
    {
        body = null;
    }

    if (body is null)
    {
        Security(context, new JsonObject { ["eventCategory"] = "application-security", ["eventType"] = "input_validation_failure",
            ["eventAction"] = "validation.reject", ["eventResult"] = "failure", ["eventSeverity"] = "low", ["reason"] = "MalformedJson" });
        return Results.Json(new { error = "bad request" }, statusCode: (int)HttpStatusCode.BadRequest);
    }

    // Demo credential check; use ASP.NET Core Identity or your identity provider.
    bool ok = System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
        System.Text.Encoding.UTF8.GetBytes($"{body.Username}:{body.Password}"), "demo:demo-password"u8);
    if (!ok)
    {
        Security(context, new JsonObject { ["eventCategory"] = "authentication", ["eventType"] = "authentication_failure",
            ["eventAction"] = "authentication.attempt", ["eventResult"] = "failure", ["eventSeverity"] = "low",
            ["reason"] = "InvalidCredentials", ["actor"] = new JsonObject { ["username"] = body.Username } });
        return Results.Json(new { error = "invalid credentials" }, statusCode: (int)HttpStatusCode.Unauthorized);
    }

    Security(context, new JsonObject { ["eventCategory"] = "authentication", ["eventType"] = "authentication_success",
        ["eventAction"] = "authentication.login", ["eventResult"] = "success",
        ["actor"] = new JsonObject { ["userId"] = "user-demo", ["username"] = body.Username },
        ["labels"] = new JsonObject { ["authMethod"] = "password" } });
    return Results.NoContent();
});

app.MapGet("/admin/users", (HttpContext context) =>
{
    Security(context, new JsonObject { ["eventCategory"] = "authorisation", ["eventType"] = "authorisation_failure",
        ["eventAction"] = "authz.function", ["eventResult"] = "denied", ["eventSeverity"] = "medium",
        ["actor"] = new JsonObject { ["userId"] = "user-demo", ["role"] = "member" },
        ["target"] = new JsonObject { ["type"] = "function", ["id"] = "admin.users.list" } });
    return Results.Json(new { error = "forbidden" }, statusCode: (int)HttpStatusCode.Forbidden);
});

app.Run();

internal sealed record LoginRequest(string Username, string Password);
