using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Bower.Pipeline.Transforms;

internal enum TransformKind
{
    Null,
    Bool,
    Int,
    String,
    Number,
    Array,
    Object
}

/// <summary>
/// One immutable transform value. Integers are signed 64-bit; any other JSON number is an
/// opaque <see cref="TransformKind.Number"/> that keeps its source text and only
/// <c>to_string</c> or a copy can use. Objects keep key order.
/// </summary>
internal sealed class TransformValue
{
    public static readonly TransformValue Null = new(TransformKind.Null);
    public static readonly TransformValue True = new(TransformKind.Bool) { Bool = true };
    public static readonly TransformValue False = new(TransformKind.Bool);

    private TransformValue(TransformKind kind) => Kind = kind;

    public TransformKind Kind { get; }

    public bool Bool { get; private init; }

    public long Int { get; private init; }

    /// <summary>String value, or the source text of an opaque number.</summary>
    public string Text { get; private init; } = string.Empty;

    public IReadOnlyList<TransformValue> Items { get; private init; } = [];

    public IReadOnlyList<KeyValuePair<string, TransformValue>> Fields { get; private init; } = [];

    public static TransformValue FromBool(bool value) => value ? True : False;

    public static TransformValue FromInt(long value) => new(TransformKind.Int) { Int = value };

    public static TransformValue FromString(string value) => new(TransformKind.String) { Text = value };

    public static TransformValue FromArray(IReadOnlyList<TransformValue> items) =>
        new(TransformKind.Array) { Items = items };

    public static TransformValue FromObject(IReadOnlyList<KeyValuePair<string, TransformValue>> fields) =>
        new(TransformKind.Object) { Fields = fields };

    private static TransformValue FromNumberText(string text) =>
        IsIntegerText(text) && long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long value)
            ? FromInt(value)
            : new TransformValue(TransformKind.Number) { Text = text };

    /// <summary>
    /// Converts a parsed record. Duplicate keys, invalid UTF-16 and nesting deeper than
    /// <see cref="TransformLimits.MaximumInputDepth"/> fail with
    /// <see cref="TransformErrorCodes.InputInvalid"/>.
    /// </summary>
    public static List<KeyValuePair<string, TransformValue>> RecordFrom(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new TransformException(TransformErrorCodes.InputInvalid);
        }

        List<KeyValuePair<string, TransformValue>> record = [.. From(root, 1).Fields];
        if (record.Count > TransformLimits.MaximumRecordFields)
        {
            throw new TransformException(TransformErrorCodes.InputInvalid);
        }

        return record;
    }

    private static TransformValue From(JsonElement element, int depth)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                {
                    if (depth > TransformLimits.MaximumInputDepth)
                    {
                        throw new TransformException(TransformErrorCodes.InputInvalid);
                    }

                    List<KeyValuePair<string, TransformValue>> fields = [];
                    HashSet<string> names = new(StringComparer.Ordinal);
                    foreach (JsonProperty property in element.EnumerateObject())
                    {
                        string name = ValidText(property.Name);
                        if (!names.Add(name))
                        {
                            throw new TransformException(TransformErrorCodes.InputInvalid);
                        }

                        fields.Add(new(name, From(property.Value, depth + 1)));
                    }

                    return FromObject(fields);
                }
            case JsonValueKind.Array:
                {
                    if (depth > TransformLimits.MaximumInputDepth)
                    {
                        throw new TransformException(TransformErrorCodes.InputInvalid);
                    }

                    List<TransformValue> items = [];
                    foreach (JsonElement item in element.EnumerateArray())
                    {
                        items.Add(From(item, depth + 1));
                    }

                    return FromArray(items);
                }
            case JsonValueKind.String:
                string text;
                try
                {
                    text = element.GetString() ?? string.Empty;
                }
                catch (InvalidOperationException)
                {
                    throw new TransformException(TransformErrorCodes.InputInvalid);
                }

                return FromString(ValidText(text));
            case JsonValueKind.Number:
                return FromNumberText(element.GetRawText());
            case JsonValueKind.True:
                return True;
            case JsonValueKind.False:
                return False;
            default:
                return Null;
        }
    }

    private static string ValidText(string text) =>
        IsWellFormed(text) ? text : throw new TransformException(TransformErrorCodes.InputInvalid);

    internal static bool IsWellFormed(string text)
    {
        for (int index = 0; index < text.Length; index++)
        {
            char current = text[index];
            if (char.IsHighSurrogate(current))
            {
                if (index + 1 >= text.Length || !char.IsLowSurrogate(text[index + 1]))
                {
                    return false;
                }

                index++;
            }
            else if (char.IsLowSurrogate(current))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary><c>-?(0|[1-9][0-9]*)</c>: JSON integer text with no fraction or exponent.</summary>
    private static bool IsIntegerText(string text)
    {
        int start = text.StartsWith('-') ? 1 : 0;
        if (start >= text.Length || (text[start] == '0' && text.Length > start + 1))
        {
            return false;
        }

        for (int index = start; index < text.Length; index++)
        {
            if (!char.IsAsciiDigit(text[index]))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Canonical output: no whitespace, keys in record order, integers in decimal, opaque
    /// numbers as their source text, and only <c>"</c>, <c>\</c> and control characters
    /// escaped. Byte-identical to the Rust port.
    /// </summary>
    public static string Serialize(IReadOnlyList<KeyValuePair<string, TransformValue>> record)
    {
        StringBuilder builder = new();
        WriteObject(builder, record);
        return builder.ToString();
    }

    private static void Write(StringBuilder builder, TransformValue value)
    {
        switch (value.Kind)
        {
            case TransformKind.Null:
                builder.Append("null");
                break;
            case TransformKind.Bool:
                builder.Append(value.Bool ? "true" : "false");
                break;
            case TransformKind.Int:
                builder.Append(value.Int.ToString(CultureInfo.InvariantCulture));
                break;
            case TransformKind.Number:
                builder.Append(value.Text);
                break;
            case TransformKind.String:
                WriteString(builder, value.Text);
                break;
            case TransformKind.Array:
                builder.Append('[');
                for (int index = 0; index < value.Items.Count; index++)
                {
                    if (index > 0)
                    {
                        builder.Append(',');
                    }

                    Write(builder, value.Items[index]);
                }

                builder.Append(']');
                break;
            default:
                WriteObject(builder, value.Fields);
                break;
        }
    }

    private static void WriteObject(StringBuilder builder, IReadOnlyList<KeyValuePair<string, TransformValue>> fields)
    {
        builder.Append('{');
        for (int index = 0; index < fields.Count; index++)
        {
            if (index > 0)
            {
                builder.Append(',');
            }

            WriteString(builder, fields[index].Key);
            builder.Append(':');
            Write(builder, fields[index].Value);
        }

        builder.Append('}');
    }

    private static void WriteString(StringBuilder builder, string text)
    {
        builder.Append('"');
        foreach (char current in text)
        {
            switch (current)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\b':
                    builder.Append("\\b");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                default:
                    if (current < ' ')
                    {
                        builder.Append("\\u00").Append(((int)current).ToString("x2", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        builder.Append(current);
                    }

                    break;
            }
        }

        builder.Append('"');
    }
}
