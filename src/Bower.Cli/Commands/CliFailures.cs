namespace Bower.Cli.Commands;

/// <summary>Which exceptions the CLI reports as a one-line error with exit code 1.</summary>
internal static class CliFailures
{
    /// <summary>
    /// <see cref="HttpClient"/> reports its own timeout as a <see cref="TaskCanceledException"/>
    /// wrapping a <see cref="TimeoutException"/>; a caller's cancellation has no such inner exception.
    /// </summary>
    public static bool IsHttpTimeout(Exception exception) =>
        exception is OperationCanceledException { InnerException: TimeoutException };

    /// <summary>
    /// Everything except a genuine cancellation (for example Ctrl+C), which is not an error to
    /// report. HTTP timeouts are failures: "The request was canceled due to the configured
    /// HttpClient.Timeout of N seconds elapsing."
    /// </summary>
    public static bool IsReportable(Exception exception) =>
        exception is not OperationCanceledException || IsHttpTimeout(exception);
}
