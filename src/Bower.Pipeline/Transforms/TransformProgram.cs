using System.Text.Json;

namespace Bower.Pipeline.Transforms;

/// <summary>Static and runtime bounds. Shared with the Rust port (<c>bower_pipeline::transform</c>).</summary>
public static class TransformLimits
{
    public const int MaximumStatements = 64;
    public const int MaximumStatementLength = 1024;
    public const int MaximumNodesPerStatement = 256;
    public const int MaximumExpressionDepth = 16;
    public const int MaximumBlockDepth = 4;
    public const int MaximumArguments = 8;
    public const int MaximumRegexes = 16;
    public const int MaximumRegexPatternLength = 512;
    public const int MaximumRegexInstructions = 2048;
    public const int MaximumRegexRepeat = 100;
    public const int MaximumRegexGroups = 32;
    public const int MaximumTables = 16;
    public const int MaximumTableEntries = 1024;
    public const int MaximumTotalTableEntries = 4096;
    public const int MaximumTableKeyLength = 256;
    public const int MaximumTableValueLength = 1024;
    public const int MaximumTableNameLength = 64;
    public const long StepBudget = 1_000_000;
    public const int MaximumStringLength = 32_768;
    public const int MaximumArrayLength = 256;
    public const int MaximumRecordFields = 128;
    public const int MaximumOutputLength = 65_536;
    public const int MaximumInputDepth = 16;
}

/// <summary>Stable, metadata-only failure codes. Never followed by a value.</summary>
public static class TransformErrorCodes
{
    // Static (validation) codes.
    public const string Syntax = "transform-syntax";
    public const string LimitExceeded = "transform-limit-exceeded";
    public const string UnknownFunction = "transform-unknown-function";
    public const string Arity = "transform-arity";
    public const string InvalidArgument = "transform-invalid-argument";
    public const string InvalidRegex = "transform-invalid-regex";
    public const string UnknownTable = "transform-unknown-table";
    public const string InvalidTable = "transform-invalid-table";
    public const string InvalidTarget = "transform-invalid-target";
    public const string ProhibitedField = "transform-prohibited-field";
    public const string SensitiveField = "transform-sensitive-field";
    public const string SensitiveFlow = "transform-sensitive-flow";

    // Runtime codes.
    public const string TypeError = "transform-type-error";
    public const string BudgetExceeded = "transform-budget-exceeded";
    public const string SizeExceeded = "transform-size-exceeded";
    public const string InputInvalid = "transform-input-invalid";
}

/// <summary>
/// One validation issue: statement number (1-based; 0 for the program or its tables), UTF-16
/// column (1-based) and code. Never contains statement text or values.
/// </summary>
public sealed record TransformIssue(int Statement, int Column, string Code)
{
    public override string ToString() => Statement == 0
        ? $"Transform program: {Code}."
        : $"Transform statement {Statement} column {Column}: {Code}.";
}

/// <summary>A transform failure. <see cref="Exception.Message"/> is the stable code only.</summary>
public sealed class TransformException(string code) : Exception(code)
{
    public string Code => Message;
}

/// <summary>
/// A transform program as a pack parser carries it: <c>runtime.transforms</c>, optional
/// <c>runtime.tables</c>, and the parser's declared fields, which decide what is sensitive.
/// </summary>
public sealed record TransformDefinition(
    IReadOnlyList<string?>? Statements,
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>>? Tables,
    IReadOnlyList<CustomLogField> Fields);

/// <summary>Canonical output record JSON and the steps it took.</summary>
public sealed record TransformOutput(string RecordJson, long Steps);

/// <summary>
/// A validated, compiled transform program. Total (no loops or recursion), side-effect free,
/// deterministic, and bounded by <see cref="TransformLimits"/>. Reads no clock, randomness,
/// environment, file or network: the evaluation time is an explicit input.
/// </summary>
public sealed class TransformProgram
{
    private readonly IReadOnlyList<TransformStatement> statements;

    private TransformProgram(IReadOnlyList<TransformStatement> statements) => this.statements = statements;

    /// <summary>Every issue, at most one per statement, in statement order.</summary>
    public static IReadOnlyList<TransformIssue> Validate(TransformDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(definition);
        return TransformCompiler.Compile(definition, out _);
    }

    /// <summary>Compiles a valid program; throws <see cref="InvalidDataException"/> listing issues otherwise.</summary>
    public static TransformProgram Compile(TransformDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(definition);
        IReadOnlyList<TransformIssue> issues = TransformCompiler.Compile(definition, out List<TransformStatement> compiled);
        if (issues.Count > 0)
        {
            throw new InvalidDataException(string.Join(" ", issues));
        }

        return new TransformProgram(compiled);
    }

    /// <summary>
    /// Runs the program over one record. Throws <see cref="TransformException"/> with a
    /// runtime code; the record is never echoed.
    /// </summary>
    public TransformOutput Execute(JsonElement record, DateTimeOffset evaluationTime)
    {
        List<KeyValuePair<string, TransformValue>> fields = TransformValue.RecordFrom(record);
        TransformEvaluator evaluator = new(fields, evaluationTime.UtcTicks);
        foreach (TransformStatement statement in statements)
        {
            evaluator.Execute(statement);
        }

        string json = TransformValue.Serialize(fields);
        if (json.Length > TransformLimits.MaximumOutputLength)
        {
            throw new TransformException(TransformErrorCodes.SizeExceeded);
        }

        return new TransformOutput(json, evaluator.Steps);
    }

    /// <summary>Parses <paramref name="recordJson"/> (a JSON object) and runs the program.</summary>
    public TransformOutput Execute(string recordJson, DateTimeOffset evaluationTime)
    {
        ArgumentNullException.ThrowIfNull(recordJson);
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(recordJson, new JsonDocumentOptions { MaxDepth = 64 });
        }
        catch (JsonException)
        {
            throw new TransformException(TransformErrorCodes.InputInvalid);
        }

        using (document)
        {
            return Execute(document.RootElement, evaluationTime);
        }
    }
}
