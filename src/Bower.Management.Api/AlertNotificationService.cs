using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.Json;

namespace Bower.Management.Api;

/// <summary>
/// Server-side notification channel configuration. Secrets (Teams webhook URL, SMTP password)
/// come strictly from files on disk and are never stored in the database or returned via HTTP.
/// </summary>
public sealed class AlertNotificationOptions
{
    public const string TeamsWebhookFileSetting = "BOWER_ALERT_TEAMS_WEBHOOK_FILE";
    public const string EmailHostSetting = "BOWER_ALERT_EMAIL_HOST";
    public const string EmailPortSetting = "BOWER_ALERT_EMAIL_PORT";
    public const string EmailFromSetting = "BOWER_ALERT_EMAIL_FROM";
    public const string EmailToSetting = "BOWER_ALERT_EMAIL_TO";
    public const string EmailUsernameSetting = "BOWER_ALERT_EMAIL_USERNAME";
    public const string EmailPasswordFileSetting = "BOWER_ALERT_EMAIL_PASSWORD_FILE";
    public const string EmailUseTlsSetting = "BOWER_ALERT_EMAIL_USE_TLS";
    public const string ConsoleUrlSetting = "BOWER_ALERT_CONSOLE_URL";
    public const string DedupMinutesSetting = "BOWER_ALERT_DEDUP_MINUTES";

    public Uri? TeamsWebhookUri { get; init; }
    public string? EmailHost { get; init; }
    public int EmailPort { get; init; } = 587;
    public string? EmailFrom { get; init; }
    public IReadOnlyList<string> EmailRecipients { get; init; } = [];
    public string? EmailUsername { get; init; }
    public string? EmailPassword { get; init; }
    public bool EmailUseTls { get; init; } = true;
    public Uri? ConsoleBaseUrl { get; init; }
    public TimeSpan DedupWindow { get; init; } = TimeSpan.FromMinutes(60);

    public bool TeamsConfigured => TeamsWebhookUri is not null;

    public bool EmailConfigured =>
        !string.IsNullOrWhiteSpace(EmailHost)
        && !string.IsNullOrWhiteSpace(EmailFrom)
        && EmailRecipients.Count > 0;

    public AlertChannelStatus Status() => new(
        TeamsConfigured,
        EmailConfigured,
        ConsoleBaseUrl is not null,
        (int)Math.Round(DedupWindow.TotalMinutes));

    public static AlertNotificationOptions FromConfiguration(IConfiguration configuration)
    {
        Uri? webhook = ReadHttpsUriFile(configuration[TeamsWebhookFileSetting], TeamsWebhookFileSetting);
        Uri? consoleUrl = ReadOptionalConsoleUrl(configuration[ConsoleUrlSetting]);
        int dedupMinutes = configuration.GetValue(DedupMinutesSetting, 60);
        if (dedupMinutes is < 5 or > 1440)
        {
            throw new InvalidOperationException($"{DedupMinutesSetting} must be between 5 and 1440.");
        }

        string? host = Blank(configuration[EmailHostSetting]);
        int port = configuration.GetValue(EmailPortSetting, 587);
        if (port is < 1 or > 65535)
        {
            throw new InvalidOperationException($"{EmailPortSetting} must be between 1 and 65535.");
        }

        string? from = Blank(configuration[EmailFromSetting]);
        string[] recipients = (configuration[EmailToSetting] ?? string.Empty)
            .Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        string? username = Blank(configuration[EmailUsernameSetting]);
        string? passwordFile = Blank(configuration[EmailPasswordFileSetting]);
        string? password = passwordFile is null ? null : File.ReadAllText(passwordFile).Trim();
        bool useTls = configuration.GetValue(EmailUseTlsSetting, true);

        return new AlertNotificationOptions
        {
            TeamsWebhookUri = webhook,
            EmailHost = host,
            EmailPort = port,
            EmailFrom = from,
            EmailRecipients = recipients,
            EmailUsername = username,
            EmailPassword = password,
            EmailUseTls = useTls,
            ConsoleBaseUrl = consoleUrl,
            DedupWindow = TimeSpan.FromMinutes(dedupMinutes)
        };
    }

    private static Uri? ReadHttpsUriFile(string? path, string settingName)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        string raw = File.ReadAllText(path.Trim()).Trim();
        if (!Uri.TryCreate(raw, UriKind.Absolute, out Uri? uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"{settingName} must contain an absolute https:// URL.");
        }

        return uri;
    }

    private static Uri? ReadOptionalConsoleUrl(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        if (!Uri.TryCreate(raw.Trim(), UriKind.Absolute, out Uri? uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"{ConsoleUrlSetting} must be an absolute https:// URL.");
        }

        return uri;
    }

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

/// <summary>Outbound plain-language alert notification channel.</summary>
public interface IAlertNotificationChannel
{
    string Name { get; }
    bool IsConfigured { get; }
    Task SendAsync(AlertNotificationMessage message, CancellationToken cancellationToken);
}

/// <summary>Posts metadata-only plain-language alerts to a Microsoft Teams webhook over HTTPS.</summary>
public sealed class TeamsWebhookAlertChannel(
    AlertNotificationOptions options,
    IHttpClientFactory httpClientFactory) : IAlertNotificationChannel
{
    public const string HttpClientName = "bower-alert-teams";

    public string Name => "teams";
    public bool IsConfigured => options.TeamsConfigured;

    public async Task SendAsync(AlertNotificationMessage message, CancellationToken cancellationToken)
    {
        if (options.TeamsWebhookUri is null)
        {
            return;
        }

        string title = $"Bower alert ({message.Severity.ToUpperInvariant()}): {message.ConditionId}";
        StringBuilder text = new();
        text.Append(message.Summary).Append("\n\nSuggested fix: ").Append(message.SuggestedFix);
        if (message.ConsoleAlertsUrl is not null)
        {
            text.Append("\n\nConsole (sign-in required): ").Append(message.ConsoleAlertsUrl);
        }

        TeamsWebhookPayload payload = new(title, text.ToString());
        string json = JsonSerializer.Serialize(payload, ManagementJsonContext.Default.TeamsWebhookPayload);
        using HttpClient client = httpClientFactory.CreateClient(HttpClientName);
        using HttpRequestMessage request = new(HttpMethod.Post, options.TeamsWebhookUri)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
    }
}

public sealed record TeamsWebhookPayload(string Title, string Text);

/// <summary>Sends metadata-only plain-language alerts via SMTP email (zero extra dependencies).</summary>
public sealed class SmtpEmailAlertChannel(AlertNotificationOptions options) : IAlertNotificationChannel
{
    public string Name => "email";
    public bool IsConfigured => options.EmailConfigured;

    public async Task SendAsync(AlertNotificationMessage message, CancellationToken cancellationToken)
    {
        if (!options.EmailConfigured)
        {
            return;
        }

        using MailMessage mail = new()
        {
            From = new MailAddress(options.EmailFrom!),
            Subject = $"[Bower {message.Severity.ToUpperInvariant()}] {message.Summary}",
            Body = BuildBody(message),
            IsBodyHtml = false
        };
        foreach (string recipient in options.EmailRecipients)
        {
            mail.To.Add(recipient);
        }

        using SmtpClient smtp = new(options.EmailHost!, options.EmailPort)
        {
            EnableSsl = options.EmailUseTls
        };
        if (options.EmailUsername is not null && options.EmailPassword is not null)
        {
            smtp.Credentials = new NetworkCredential(options.EmailUsername, options.EmailPassword);
        }

        await smtp.SendMailAsync(mail, cancellationToken);
    }

    private static string BuildBody(AlertNotificationMessage message)
    {
        StringBuilder builder = new();
        builder.AppendLine("Bower fleet alert (metadata only; no event content is included).");
        builder.AppendLine();
        builder.Append("Condition: ").AppendLine(message.ConditionId);
        builder.Append("Severity: ").AppendLine(message.Severity);
        builder.Append("Summary: ").AppendLine(message.Summary);
        builder.Append("Suggested fix: ").AppendLine(message.SuggestedFix);
        if (message.ConsoleAlertsUrl is not null)
        {
            builder.Append("Open console (sign-in required): ").AppendLine(message.ConsoleAlertsUrl);
        }

        return builder.ToString();
    }
}
