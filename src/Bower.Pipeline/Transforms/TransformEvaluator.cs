using System.Globalization;
using System.Text;

namespace Bower.Pipeline.Transforms;

/// <summary>
/// Executes compiled statements over one record. Every statement and expression node costs
/// one step; regex execution adds its VM steps. Evaluation order is left to right, with
/// short-circuit <c>&amp;&amp;</c>, <c>||</c> and <c>coalesce</c>.
/// </summary>
internal sealed class TransformEvaluator(
    List<KeyValuePair<string, TransformValue>> record,
    long evaluationTicks)
{
    private readonly TransformBudget budget = new();

    public long Steps => budget.Steps;

    public void Execute(TransformStatement statement)
    {
        budget.Step();
        switch (statement)
        {
            case AssignStatement assign:
                Set(assign.Target, Evaluate(assign.Value));
                break;
            case DeleteStatement delete:
                Remove(delete.Target);
                break;
            case RenameStatement rename:
                int index = IndexOf(rename.From);
                if (index >= 0)
                {
                    TransformValue value = record[index].Value;
                    record.RemoveAt(index);
                    Set(rename.To, value);
                }

                break;
            case IfStatement conditional:
                IReadOnlyList<TransformStatement>? branch = Truthy(Evaluate(conditional.Condition))
                    ? conditional.Then
                    : conditional.Else;
                foreach (TransformStatement item in branch ?? [])
                {
                    Execute(item);
                }

                break;
        }
    }

    private int IndexOf(string name) => record.FindIndex(field => string.Equals(field.Key, name, StringComparison.Ordinal));

    private void Set(string name, TransformValue value)
    {
        int index = IndexOf(name);
        if (index >= 0)
        {
            record[index] = new(name, value);
            return;
        }

        if (record.Count >= TransformLimits.MaximumRecordFields)
        {
            throw new TransformException(TransformErrorCodes.SizeExceeded);
        }

        record.Add(new(name, value));
    }

    private void Remove(string name)
    {
        int index = IndexOf(name);
        if (index >= 0)
        {
            record.RemoveAt(index);
        }
    }

    private static TransformException TypeError() => new(TransformErrorCodes.TypeError);

    private static bool Truthy(TransformValue value) => value.Kind switch
    {
        TransformKind.Bool => value.Bool,
        TransformKind.Null => false,
        _ => throw TypeError()
    };

    private TransformValue Evaluate(TransformExpression expression)
    {
        budget.Step();
        switch (expression)
        {
            case LiteralExpression literal:
                return literal.Value;
            case PathExpression path:
                return Read(path.Segments);
            case NotExpression not:
                return TransformValue.FromBool(!Truthy(Evaluate(not.Operand)));
            case BinaryExpression { Operator: "&&" } and:
                return TransformValue.FromBool(Truthy(Evaluate(and.Left)) && Truthy(Evaluate(and.Right)));
            case BinaryExpression { Operator: "||" } or:
                return TransformValue.FromBool(Truthy(Evaluate(or.Left)) || Truthy(Evaluate(or.Right)));
            case BinaryExpression binary:
                return Compare(binary.Operator, Evaluate(binary.Left), Evaluate(binary.Right));
            default:
                return Call((CallExpression)expression);
        }
    }

    private TransformValue Read(IReadOnlyList<string> segments)
    {
        IReadOnlyList<KeyValuePair<string, TransformValue>> fields = record;
        TransformValue current = TransformValue.Null;
        foreach (string segment in segments)
        {
            current = TransformValue.Null;
            foreach (KeyValuePair<string, TransformValue> field in fields)
            {
                if (string.Equals(field.Key, segment, StringComparison.Ordinal))
                {
                    current = field.Value;
                    break;
                }
            }

            if (current.Kind != TransformKind.Object)
            {
                fields = [];
            }
            else
            {
                fields = current.Fields;
            }
        }

        return current;
    }

    private static TransformValue Compare(string op, TransformValue left, TransformValue right)
    {
        if (IsComposite(left) || IsComposite(right))
        {
            throw TypeError();
        }

        if (op is "==" or "!=")
        {
            bool equal = left.Kind == right.Kind && left.Kind switch
            {
                TransformKind.Null => true,
                TransformKind.Bool => left.Bool == right.Bool,
                TransformKind.Int => left.Int == right.Int,
                _ => string.Equals(left.Text, right.Text, StringComparison.Ordinal)
            };
            return TransformValue.FromBool(op == "==" ? equal : !equal);
        }

        if (left.Kind == TransformKind.Null || right.Kind == TransformKind.Null)
        {
            return TransformValue.False;
        }

        if (left.Kind != TransformKind.Int || right.Kind != TransformKind.Int)
        {
            throw TypeError();
        }

        return TransformValue.FromBool(op switch
        {
            "<" => left.Int < right.Int,
            "<=" => left.Int <= right.Int,
            ">" => left.Int > right.Int,
            _ => left.Int >= right.Int
        });
    }

    private static bool IsComposite(TransformValue value) =>
        value.Kind is TransformKind.Array or TransformKind.Object or TransformKind.Number;

    private static TransformValue Text(string value) =>
        value.Length > TransformLimits.MaximumStringLength
            ? throw new TransformException(TransformErrorCodes.SizeExceeded)
            : TransformValue.FromString(value);

    private static string RequireString(TransformValue value) =>
        value.Kind == TransformKind.String ? value.Text : throw TypeError();

    private TransformValue Call(CallExpression call)
    {
        IReadOnlyList<TransformExpression> arguments = call.Arguments;
        if (call.Name == "coalesce")
        {
            foreach (TransformExpression argument in arguments)
            {
                TransformValue value = Evaluate(argument);
                if (value.Kind != TransformKind.Null)
                {
                    return value;
                }
            }

            return TransformValue.Null;
        }

        TransformValue[] values = [.. arguments.Select(Evaluate)];
        TransformValue first = values.Length > 0 ? values[0] : TransformValue.Null;
        switch (call.Name)
        {
            case "now":
                return TransformValue.FromString(TransformTime.Format(evaluationTicks));
            case "concat":
                if (values.Any(value => value.Kind is not (TransformKind.String or TransformKind.Null)))
                {
                    throw TypeError();
                }

                if (values.Any(value => value.Kind == TransformKind.Null))
                {
                    return TransformValue.Null;
                }

                long length = values.Sum(value => (long)value.Text.Length);
                return length > TransformLimits.MaximumStringLength
                    ? throw new TransformException(TransformErrorCodes.SizeExceeded)
                    : TransformValue.FromString(string.Concat(values.Select(value => value.Text)));
            case "to_string":
                return first.Kind switch
                {
                    TransformKind.Null or TransformKind.String => first,
                    TransformKind.Int => TransformValue.FromString(first.Int.ToString(CultureInfo.InvariantCulture)),
                    TransformKind.Bool => TransformValue.FromString(first.Bool ? "true" : "false"),
                    TransformKind.Number => TransformValue.FromString(first.Text),
                    _ => throw TypeError()
                };
            case "to_int":
                return first.Kind switch
                {
                    TransformKind.Null or TransformKind.Int => first,
                    TransformKind.String => ParseInt(first.Text),
                    TransformKind.Number => TransformValue.Null,
                    _ => throw TypeError()
                };
            case "to_bool":
                return first.Kind switch
                {
                    TransformKind.Null or TransformKind.Bool => first,
                    TransformKind.String when MapAscii(first.Text, upper: false) == "true" => TransformValue.True,
                    TransformKind.String when MapAscii(first.Text, upper: false) == "false" => TransformValue.False,
                    TransformKind.String => TransformValue.Null,
                    _ => throw TypeError()
                };
            case "at":
                {
                    if (values[1].Kind != TransformKind.Int || first.Kind is not (TransformKind.Null or TransformKind.Array))
                    {
                        throw TypeError();
                    }

                    if (first.Kind == TransformKind.Null)
                    {
                        return TransformValue.Null;
                    }

                    long position = values[1].Int < 0 ? first.Items.Count + values[1].Int : values[1].Int;
                    return position >= 0 && position < first.Items.Count ? first.Items[(int)position] : TransformValue.Null;
                }
            case "join":
                {
                    string separator = RequireString(values[1]);
                    if (first.Kind == TransformKind.Null)
                    {
                        return TransformValue.Null;
                    }

                    if (first.Kind != TransformKind.Array || first.Items.Any(item => item.Kind != TransformKind.String))
                    {
                        throw TypeError();
                    }

                    long total = first.Items.Sum(item => (long)item.Text.Length)
                        + ((long)separator.Length * Math.Max(0, first.Items.Count - 1));
                    return total > TransformLimits.MaximumStringLength
                        ? throw new TransformException(TransformErrorCodes.SizeExceeded)
                        : TransformValue.FromString(string.Join(separator, first.Items.Select(item => item.Text)));
                }
            case "lookup":
                if (values[1].Kind == TransformKind.Null)
                {
                    return TransformValue.Null;
                }

                return ((IReadOnlyDictionary<string, string>)call.Bound!).TryGetValue(RequireString(values[1]), out string? found)
                    ? TransformValue.FromString(found)
                    : TransformValue.Null;
            case "parse_timestamp":
                {
                    string format = (string)call.Bound!;
                    bool unix = format.StartsWith("unix_", StringComparison.Ordinal);
                    if (first.Kind == TransformKind.Null)
                    {
                        return TransformValue.Null;
                    }

                    if (first.Kind != TransformKind.String && !(unix && first.Kind == TransformKind.Int))
                    {
                        throw TypeError();
                    }

                    return TransformTime.Parse(format, first, evaluationTicks) is { } ticks
                        ? TransformValue.FromString(TransformTime.Format(ticks))
                        : TransformValue.Null;
                }
        }

        // The remaining functions take a string subject first; null in gives null out.
        string?[] extra = [.. values.Skip(1).Select(value => call.Name == "split" && value.Kind == TransformKind.Int ? null : RequireString(value))];
        if (first.Kind == TransformKind.Null)
        {
            return TransformValue.Null;
        }

        string subject = RequireString(first);
        switch (call.Name)
        {
            case "lower":
                return TransformValue.FromString(MapAscii(subject, upper: false));
            case "upper":
                return TransformValue.FromString(MapAscii(subject, upper: true));
            case "trim":
                return TransformValue.FromString(subject.Trim(' ', '\t', '\n', '\v', '\f', '\r'));
            case "contains":
                return TransformValue.FromBool(subject.Contains(extra[0]!, StringComparison.Ordinal));
            case "starts_with":
                return TransformValue.FromBool(subject.StartsWith(extra[0]!, StringComparison.Ordinal));
            case "ends_with":
                return TransformValue.FromBool(subject.EndsWith(extra[0]!, StringComparison.Ordinal));
            case "replace":
                {
                    string from = extra[0]!;
                    string to = extra[1]!;
                    if (from.Length == 0)
                    {
                        throw TypeError();
                    }

                    long count = 0;
                    for (int index = subject.IndexOf(from, StringComparison.Ordinal);
                        index >= 0;
                        index = subject.IndexOf(from, index + from.Length, StringComparison.Ordinal))
                    {
                        count++;
                    }

                    return subject.Length + (count * (to.Length - from.Length)) > TransformLimits.MaximumStringLength
                        ? throw new TransformException(TransformErrorCodes.SizeExceeded)
                        : TransformValue.FromString(subject.Replace(from, to, StringComparison.Ordinal));
                }
            case "split":
                {
                    string separator = extra[0]!;
                    if (separator.Length == 0)
                    {
                        throw TypeError();
                    }

                    int limit = values.Length == 3 ? (int)values[2].Int : TransformLimits.MaximumArrayLength + 1;
                    string[] parts = subject.Split(separator, limit, StringSplitOptions.None);
                    return parts.Length > TransformLimits.MaximumArrayLength
                        ? throw new TransformException(TransformErrorCodes.SizeExceeded)
                        : TransformValue.FromArray([.. parts.Select(TransformValue.FromString)]);
                }
            case "regex_match":
                return TransformValue.FromBool(((TransformRegex)call.Bound!).IsMatch(Scalars(subject), budget));
            default:
                {
                    TransformRegex regex = (TransformRegex)call.Bound!;
                    int[] text = Scalars(subject);
                    if (regex.Search(text, budget) is not { } slots)
                    {
                        return TransformValue.Null;
                    }

                    List<KeyValuePair<string, TransformValue>> groups = [];
                    for (int group = 0; group < regex.GroupNames.Count; group++)
                    {
                        int start = slots[2 * (group + 1)];
                        int end = slots[(2 * (group + 1)) + 1];
                        groups.Add(new(
                            regex.GroupNames[group],
                            start >= 0 && end >= start ? Text(FromScalars(text, start, end)) : TransformValue.Null));
                    }

                    return TransformValue.FromObject(groups);
                }
        }
    }

    private static TransformValue ParseInt(string text)
    {
        int start = text.Length > 0 && text[0] is '+' or '-' ? 1 : 0;
        if (start >= text.Length)
        {
            return TransformValue.Null;
        }

        for (int index = start; index < text.Length; index++)
        {
            if (!char.IsAsciiDigit(text[index]))
            {
                return TransformValue.Null;
            }
        }

        return long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long value)
            ? TransformValue.FromInt(value)
            : TransformValue.Null;
    }

    private static string MapAscii(string text, bool upper)
    {
        StringBuilder builder = new(text.Length);
        foreach (char character in text)
        {
            builder.Append(upper ? (char.IsAsciiLetterLower(character) ? (char)(character - 32) : character)
                : (char.IsAsciiLetterUpper(character) ? (char)(character + 32) : character));
        }

        return builder.ToString();
    }

    private static int[] Scalars(string text) => [.. text.EnumerateRunes().Select(rune => rune.Value)];

    private static string FromScalars(int[] text, int start, int end)
    {
        StringBuilder builder = new();
        for (int index = start; index < end; index++)
        {
            builder.Append(char.ConvertFromUtf32(text[index]));
        }

        return builder.ToString();
    }
}
