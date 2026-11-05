using System.Text.Json;
using System.Text.Json.Serialization;

namespace Bower.Source.File;

/// <summary>
/// BOWER_FILE_CONFIG: the files an operator selected for security signal, the roots they
/// must stay inside and the signed pack parser each file is routed to. There is no wildcard,
/// directory or "all files" form: every input names one file.
/// </summary>
/// <param name="AllowedRoots">1–8 directories; every input path must lie below one of them.</param>
/// <param name="PollIntervalMilliseconds">Wait between reads once an input has caught up.</param>
/// <param name="MaxLinesPerBatch">Lines read per poll; the cursor is committed after each poll.</param>
/// <param name="MaxBytesPerBatch">Bytes scanned per poll (one line may run up to its own limit past it).</param>
/// <param name="RotationGracePolls">Polls <c>path.1</c> must stay unchanged before the cursor moves to the new file.</param>
/// <param name="RotationDrainMaxPolls">Counted polls a drain may take before the cursor moves on anyway (bounds a <c>path.1</c> that keeps changing); at least <paramref name="RotationGracePolls"/> + 2, so a settling rename is never cut off.</param>
public sealed record FileTailSourceConfiguration(
    string ApiVersion,
    string Kind,
    IReadOnlyList<string> AllowedRoots,
    IReadOnlyList<FileTailInputOptions> Inputs,
    int PollIntervalMilliseconds = 1_000,
    int MaxLinesPerBatch = 256,
    int MaxBytesPerBatch = 1_048_576,
    int RotationGracePolls = FileTailSourceConfigurationLoader.DefaultRotationGracePolls,
    int RotationDrainMaxPolls = FileTailSourceConfigurationLoader.DefaultRotationDrainMaxPolls);

/// <summary>The active parser of a loaded signed pack that maps this input's lines.</summary>
public sealed record FileTailRoute(string Pack, int Parser);

/// <param name="Path">Absolute, normalised path of one file below an allowed root.</param>
/// <param name="Format"><c>text</c> (each line becomes <c>message</c>) or <c>json-lines</c> (each line is a JSON object, carried as <c>json</c>).</param>
/// <param name="StartAt"><c>end</c> (default: only lines written after the first start) or <c>beginning</c>.</param>
/// <param name="MaxLineBytes">Longer lines are discarded without being buffered, and counted.</param>
/// <param name="AllowSymlink">Allow the file itself to be one symbolic link whose target is a regular file below an allowed root.</param>
public sealed record FileTailInputOptions(
    string Id,
    string Path,
    FileTailRoute Route,
    string Format = FileTailFormats.Text,
    string StartAt = "end",
    int MaxLineBytes = FileTailSourceConfigurationLoader.DefaultMaxLineBytes,
    bool AllowSymlink = false)
{
    /// <summary>Durable cursor key in the queue database's source cursor table.</summary>
    [JsonIgnore]
    public string SourceId => "file:" + Id;

    [JsonIgnore]
    public bool IsJsonLines => string.Equals(Format, FileTailFormats.JsonLines, StringComparison.Ordinal);
}

public static class FileTailFormats
{
    public const string Text = "text";
    public const string JsonLines = "json-lines";
}

public static class FileTailSourceConfigurationLoader
{
    public const int MaximumInputs = 16;
    public const int MaximumRoots = 8;
    public const int MaximumPathLength = 1_024;
    public const int DefaultMaxLineBytes = 16_384;

    /// <summary>
    /// A pack parser reads records of at most 32 KiB (<c>PackRuntime.MaximumRecordBytes</c>);
    /// this leaves room for the record's metadata fields, so a longer line could never be parsed.
    /// </summary>
    public const int MaximumMaxLineBytes = 30_720;

    public const int MinimumMaxLineBytes = 256;
    public const int DefaultRotationGracePolls = 5;
    public const int MaximumRotationGracePolls = 60;
    public const int DefaultRotationDrainMaxPolls = 300;
    public const int MaximumRotationDrainMaxPolls = 3_600;
    private const int MaximumBytes = 262_144;

    public static FileTailSourceConfiguration LoadFile(string path)
    {
        FileInfo info = new(path);
        if (!info.Exists)
        {
            throw new FileNotFoundException("File tail source configuration file does not exist.", path);
        }

        if (info.Length > MaximumBytes)
        {
            throw new InvalidDataException("File tail source configuration file exceeds 256 KiB.");
        }

        FileTailSourceConfiguration configuration = Parse(System.IO.File.ReadAllText(path));
        ValidateLinks(configuration);
        return configuration;
    }

    public static FileTailSourceConfiguration Parse(string json)
    {
        FileTailSourceConfiguration? configuration;
        try
        {
            configuration = JsonSerializer.Deserialize(json, FileTailJsonContext.Default.FileTailSourceConfiguration);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"File tail source configuration is invalid: {exception.Message}", exception);
        }

        if (configuration is null
            || !string.Equals(configuration.ApiVersion, "bower.security/v1", StringComparison.Ordinal)
            || !string.Equals(configuration.Kind, "FileTailSource", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "File tail source configuration needs apiVersion bower.security/v1 and kind FileTailSource.");
        }

        if (configuration.AllowedRoots is not { Count: >= 1 and <= MaximumRoots })
        {
            throw new InvalidDataException($"File tail source configuration must list 1–{MaximumRoots} allowedRoots.");
        }

        foreach (string root in configuration.AllowedRoots)
        {
            if (!FileTailPaths.IsCanonical(root) || FileTailPaths.IsFileSystemRoot(root))
            {
                throw new InvalidDataException(
                    "File tail allowedRoots must be absolute, normalised directories without wildcards, and not the file system root.");
            }
        }

        if (configuration.Inputs is not { Count: >= 1 and <= MaximumInputs })
        {
            throw new InvalidDataException($"File tail source configuration must list 1–{MaximumInputs} inputs.");
        }

        if (configuration.PollIntervalMilliseconds is < 100 or > 60_000)
        {
            throw new InvalidDataException("File tail pollIntervalMilliseconds must be between 100 and 60000.");
        }

        if (configuration.MaxLinesPerBatch is < 1 or > 1_024)
        {
            throw new InvalidDataException("File tail maxLinesPerBatch must be between 1 and 1024.");
        }

        if (configuration.MaxBytesPerBatch is < 65_536 or > 4_194_304)
        {
            throw new InvalidDataException("File tail maxBytesPerBatch must be between 65536 and 4194304.");
        }

        if (configuration.RotationGracePolls is < 1 or > MaximumRotationGracePolls)
        {
            throw new InvalidDataException($"File tail rotationGracePolls must be between 1 and {MaximumRotationGracePolls}.");
        }

        // Settling a rename takes rotationGracePolls + 1 end-of-file polls; a lower cap would end
        // every drain first and turn a static path.1's unterminated last line into a gap.
        if (configuration.RotationDrainMaxPolls < configuration.RotationGracePolls + 2 || configuration.RotationDrainMaxPolls > MaximumRotationDrainMaxPolls)
        {
            throw new InvalidDataException(
                $"File tail rotationDrainMaxPolls must be between rotationGracePolls + 2 and {MaximumRotationDrainMaxPolls}.");
        }

        HashSet<string> ids = new(StringComparer.Ordinal);
        List<FileTailInputOptions> earlier = [];
        foreach (FileTailInputOptions input in configuration.Inputs)
        {
            Validate(input, configuration.AllowedRoots);
            if (!ids.Add(input.Id))
            {
                throw new InvalidDataException($"File tail input {input.Id} is listed more than once.");
            }

            // Case-only differences count as the same file everywhere, for simplicity.
            if (earlier.Any(other => string.Equals(Fold(other.Path), Fold(input.Path), StringComparison.Ordinal)))
            {
                throw Invalid(input.Id, "path is already read by another input.");
            }

            if (earlier.Any(other => Overlaps(input.Path, other.Path)))
            {
                throw Invalid(input.Id, "path overlaps another input's rotated file (path.1).");
            }

            earlier.Add(input);
        }

        return configuration;
    }

    /// <summary>
    /// Allowed links must not lead to another input's file or rotated file. Read once at
    /// load (one hop, as at read time); a link that does not exist yet is checked when read.
    /// </summary>
    public static void ValidateLinks(FileTailSourceConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        List<FileTailInputOptions> earlier = [];
        foreach (FileTailInputOptions input in configuration.Inputs)
        {
            if (LinkTarget(input) is { } resolved && OverlapsAnother(configuration, input, resolved))
            {
                throw Invalid(input.Id, "allowSymlink target is another input's file or rotated file.");
            }

            // The same file through linked directories (/var/run and /run, for example):
            // the text rules again, on canonical paths.
            string canonical = FileTailPaths.Canonical(input.Path);
            if (earlier.Any(other => string.Equals(Fold(FileTailPaths.Canonical(other.Path)), Fold(canonical), StringComparison.Ordinal)))
            {
                throw Invalid(input.Id, "path is already read by another input.");
            }

            if (earlier.Any(other => Overlaps(canonical, FileTailPaths.Canonical(other.Path))))
            {
                throw Invalid(input.Id, "path overlaps another input's rotated file (path.1).");
            }

            earlier.Add(input);
        }
    }

    /// <summary>
    /// Whether <paramref name="resolved"/> (the file <paramref name="input"/> reads now: its
    /// path or where its link leads) is another input's configured file, its link target, or
    /// either one's rotated file, compared on canonical paths.
    /// </summary>
    public static bool OverlapsAnother(FileTailSourceConfiguration configuration, FileTailInputOptions input, string resolved)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        string canonical = FileTailPaths.Canonical(resolved);
        return configuration.Inputs.Any(other => !ReferenceEquals(other, input)
            && (Overlaps(canonical, FileTailPaths.Canonical(other.Path))
                || (LinkTarget(other) is { } target && Overlaps(canonical, FileTailPaths.Canonical(target)))));
    }

    /// <summary>Where an allowed link leads (one hop, normalised), or null when the input has no link now.</summary>
    public static string? LinkTarget(FileTailInputOptions input)
    {
        ArgumentNullException.ThrowIfNull(input);
        return input.AllowSymlink && new FileInfo(input.Path).LinkTarget is { } target
            ? Path.GetFullPath(target, Path.GetDirectoryName(input.Path)!)
            : null;
    }

    /// <summary>The same file, or one is the other's rotated file (<c>path.1</c>), ignoring ASCII case.</summary>
    public static bool Overlaps(string path, string other)
    {
        string left = Fold(path);
        string right = Fold(other);
        return string.Equals(left, right, StringComparison.Ordinal)
            || string.Equals(left, right + ".1", StringComparison.Ordinal)
            || string.Equals(left + ".1", right, StringComparison.Ordinal);
    }

    /// <summary>ASCII-only case folding, identical in both runtimes.</summary>
    private static string Fold(string value) =>
        string.Create(value.Length, value, static (span, source) =>
        {
            for (int index = 0; index < source.Length; index++)
            {
                char character = source[index];
                span[index] = character is >= 'A' and <= 'Z' ? (char)(character + 32) : character;
            }
        });

    private static void Validate(FileTailInputOptions input, IReadOnlyList<string> roots)
    {
        if (input is null || !IsInputId(input.Id))
        {
            throw new InvalidDataException(
                "File tail input id must be 1–63 lowercase letters, digits or hyphens and start with a letter or digit.");
        }

        string id = input.Id;
        if (!FileTailPaths.IsCanonical(input.Path))
        {
            throw Invalid(id, "path must be an absolute, normalised file path without wildcards; there is no directory or glob form.");
        }

        if (FileTailPaths.RootOf(input.Path, roots) is null)
        {
            throw Invalid(id, "path is not below an allowed root.");
        }

        if (input.Route is null || string.IsNullOrWhiteSpace(input.Route.Pack) || input.Route.Parser < 0)
        {
            throw Invalid(id, "route needs a pack and a parser index of 0 or more.");
        }

        if (input.Format is not (FileTailFormats.Text or FileTailFormats.JsonLines))
        {
            throw Invalid(id, "format must be text or json-lines.");
        }

        if (input.StartAt is not ("end" or "beginning"))
        {
            throw Invalid(id, "startAt must be end or beginning.");
        }

        if (input.MaxLineBytes is < MinimumMaxLineBytes or > MaximumMaxLineBytes)
        {
            throw Invalid(id, $"maxLineBytes must be between {MinimumMaxLineBytes} and {MaximumMaxLineBytes}.");
        }
    }

    private static bool IsInputId(string? id) =>
        id is { Length: >= 1 and <= 63 }
        && (char.IsAsciiLetterLower(id[0]) || char.IsAsciiDigit(id[0]))
        && id.All(character => char.IsAsciiLetterLower(character) || char.IsAsciiDigit(character) || character == '-');

    private static InvalidDataException Invalid(string id, string message) => new($"File tail input {id}: {message}");
}

[JsonSourceGenerationOptions(
    JsonSerializerDefaults.Web,
    NumberHandling = JsonNumberHandling.Strict,
    PropertyNameCaseInsensitive = false,
    AllowDuplicateProperties = false,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectRequiredConstructorParameters = true,
    RespectNullableAnnotations = true)]
[JsonSerializable(typeof(FileTailSourceConfiguration))]
[JsonSerializable(typeof(IReadOnlyList<FileTailInputStatus>))]
internal sealed partial class FileTailJsonContext : JsonSerializerContext;
