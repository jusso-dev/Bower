using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Bower.Cli.Commands;

/// <summary>
/// <c>bower tap</c> streams post-redaction outcomes from a collector's <c>/v1/tap</c> as JSON
/// lines on stdout (no file export); <c>bower top</c> renders per-stage throughput from
/// <c>/v1/status</c>. Both send BOWER_INGEST_TOKEN when it is set and never print it.
/// </summary>
internal static class TapAndTopCommands
{
    public const string DefaultCollector = "http://127.0.0.1:4319";

    public static async Task<int> TapAsync(string[] args)
    {
        string collector = Collector(args);
        string stage = CliOptions.Get(args, "--stage") ?? "redacted";
        if (stage is not ("redacted" or "decided" or "queued"))
        {
            return Fail(stage == "parsed" || stage == "raw"
                ? "There is no pre-redaction tap point; the earliest is 'redacted'."
                : "--stage must be redacted, decided or queued.");
        }

        List<string> query = [$"stage={stage}"];
        foreach ((string option, string name) in new[]
                 {
                     ("--source", "source"), ("--event-type", "eventType"), ("--limit", "limit"),
                     ("--duration", "durationSeconds"), ("--sample", "sample")
                 })
        {
            if (CliOptions.Get(args, option) is { } value)
            {
                query.Add($"{name}={Uri.EscapeDataString(value)}");
            }
        }

        using HttpClient http = new() { BaseAddress = new Uri(EnsureSlash(collector)), Timeout = Timeout.InfiniteTimeSpan };
        using HttpRequestMessage request = new(HttpMethod.Get, "v1/tap?" + string.Join('&', query));
        Authorize(request);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        using HttpResponseMessage response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        if (!response.IsSuccessStatusCode)
        {
            return Fail(TapRefusal(response.StatusCode, await ErrorCodeAsync(response)));
        }

        await using Stream body = await response.Content.ReadAsStreamAsync();
        using StreamReader reader = new(body, Encoding.UTF8);
        string? eventName = null;
        while (await reader.ReadLineAsync() is { } line)
        {
            if (line.StartsWith("event: ", StringComparison.Ordinal))
            {
                eventName = line["event: ".Length..];
            }
            else if (line.StartsWith("data: ", StringComparison.Ordinal))
            {
                string data = line["data: ".Length..];
                switch (eventName)
                {
                    case "frame":
                        Console.WriteLine(data);
                        break;
                    case "start":
                        Console.Error.WriteLine($"tap started: {data}");
                        break;
                    case "end":
                        Console.Error.WriteLine($"tap ended: {data}");
                        return 0;
                }
            }
        }

        return 0;
    }

    public static async Task<int> TopAsync(string[] args)
    {
        string collector = Collector(args);
        if (!TryInteger(CliOptions.Get(args, "--interval"), 2, 1, 60, out int interval))
        {
            return Fail("--interval must be a whole number of seconds from 1 to 60.");
        }

        bool once = CliOptions.Has(args, "--once");
        int? iterations = null;
        if (CliOptions.Get(args, "--iterations") is { } count)
        {
            if (!TryInteger(count, 1, 1, int.MaxValue, out int parsed))
            {
                return Fail("--iterations must be a positive whole number.");
            }

            iterations = parsed;
        }

        using HttpClient http = new() { BaseAddress = new Uri(EnsureSlash(collector)), Timeout = TimeSpan.FromSeconds(10) };
        JsonDocument? previous = null;
        Stopwatch watch = Stopwatch.StartNew();
        long previousAt = 0;
        try
        {
            // --once samples twice, an interval apart, so rates are real.
            for (int sample = 0; ; sample++)
            {
                JsonDocument current = await StatusAsync(http);
                long at = watch.ElapsedMilliseconds;
                if (!once || previous is not null)
                {
                    string view = TopView.Render(collector, previous?.RootElement, current.RootElement, at - previousAt, DateTimeOffset.UtcNow);
                    if (!once && !Console.IsOutputRedirected)
                    {
                        Console.Write("\u001b[H\u001b[2J");
                    }

                    Console.Write(view);
                    if (once || (iterations is { } limit && sample + 1 >= limit))
                    {
                        return 0;
                    }
                }

                previous?.Dispose();
                previous = current;
                previousAt = at;
                await Task.Delay(TimeSpan.FromSeconds(interval));
            }
        }
        finally
        {
            previous?.Dispose();
        }
    }

    private static async Task<JsonDocument> StatusAsync(HttpClient http)
    {
        using HttpRequestMessage request = new(HttpMethod.Get, "v1/status");
        Authorize(request);
        using HttpResponseMessage response = await http.SendAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(response.StatusCode == HttpStatusCode.Unauthorized
                ? "/v1/status returned HTTP 401: set BOWER_INGEST_TOKEN."
                : $"/v1/status returned HTTP {(int)response.StatusCode}.");
        }

        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    internal static string TapRefusal(HttpStatusCode status, string? error) => status switch
    {
        HttpStatusCode.Unauthorized => "Tap refused: a valid collector ingest token is required (set BOWER_INGEST_TOKEN).",
        HttpStatusCode.Forbidden => "Tap refused: this credential may not tap (use the shared ingest token or a BOWER_TAP_PRODUCERS producer).",
        HttpStatusCode.NotFound => "Tap is disabled on this collector (BOWER_TAP_ENABLED=false) or not supported.",
        HttpStatusCode.TooManyRequests => "Tap refused: the collector's concurrent tap session limit is reached; retry later.",
        _ => $"Tap refused: HTTP {(int)status}{(error is null ? string.Empty : $" ({error})")}."
    };

    private static async Task<string?> ErrorCodeAsync(HttpResponseMessage response)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return document.RootElement.TryGetProperty("error", out JsonElement error) ? error.GetString() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static void Authorize(HttpRequestMessage request)
    {
        if (Environment.GetEnvironmentVariable("BOWER_INGEST_TOKEN") is { Length: > 0 } token)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
    }

    private static string Collector(string[] args) =>
        CliOptions.Get(args, "--collector") ?? CliOptions.Get(args, "--collector-url") ?? DefaultCollector;

    private static bool TryInteger(string? value, int fallback, int minimum, int maximum, out int result)
    {
        if (value is null)
        {
            result = fallback;
            return true;
        }

        return int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out result)
            && result >= minimum && result <= maximum;
    }

    private static string EnsureSlash(string value) => value.EndsWith('/') ? value : value + "/";

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return 1;
    }
}
