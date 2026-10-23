using System.Text.Json;

namespace Bower.Detection;

// Internal encoding is JSON string[][]: [field, modifier, alternative, ...].
// Public model shape stays unchanged; ambiguous legacy flattened strings fail closed.
internal sealed class DetectionSemantics
{
    internal const int MaximumSelections = 64;
    private readonly Dictionary<string, string[][]> selections = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> program;

    internal DetectionSemantics(IReadOnlyDictionary<string, string> fields, string condition)
    {
        if (fields.Count is < 1 or > MaximumSelections)
        {
            throw Invalid();
        }

        foreach ((string name, string encoded) in fields)
        {
            if (!Identifier(name) || IsOperator(name) || encoded.Length > 256 * 1024)
            {
                throw Invalid();
            }

            string[][] clauses;
            try
            {
                clauses = JsonSerializer.Deserialize(encoded, DetectionJsonContext.Default.StringArrayArray) ?? throw Invalid();
            }
            catch (JsonException)
            {
                throw Invalid();
            }

            ValidateClauses(clauses);
            if (!selections.TryAdd(name, clauses))
            {
                throw Invalid();
            }
        }

        program = new ConditionParser(condition, selections.Keys).Parse();
    }

    internal static InvalidDataException Invalid() => new("Unsupported or over-limit detection syntax.");

    internal static bool Identifier(string value) => value.Length is > 0 and <= 64
        && (char.IsAsciiLetter(value[0]) || value[0] == '_')
        && value.All(c => char.IsAsciiLetterOrDigit(c) || c == '_');

    private static bool IsOperator(string value) => value.Equals("not", StringComparison.OrdinalIgnoreCase)
        || value.Equals("and", StringComparison.OrdinalIgnoreCase)
        || value.Equals("or", StringComparison.OrdinalIgnoreCase);

    internal static void ValidateClauses(string[][] clauses)
    {
        if (clauses.Length is < 1 or > 64)
        {
            throw Invalid();
        }

        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        foreach (string[] clause in clauses)
        {
            if (clause is null || clause.Length is < 3 or > 66 || clause.Any(v => v is null)
                || clause[0].Length is < 1 or > 128
                || !clause[0].All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or '-')
                || !seen.Add(clause[0] + "|" + clause[1])
                || clause[1] is not ("equals" or "contains" or "startswith" or "endswith")
                || clause.Skip(2).Any(v => v.Length is < 1 or > 4096 || v.Contains('*') || v.Contains('?')))
            {
                throw Invalid();
            }
        }
    }

    internal bool Matches(IReadOnlyDictionary<string, string> haystack, out List<string> matchedFields)
    {
        Dictionary<string, (bool Match, List<string> Fields)> results = new(StringComparer.OrdinalIgnoreCase);
        foreach ((string name, string[][] clauses) in selections)
        {
            List<string> fields = [];
            bool match = true;
            foreach (string[] clause in clauses)
            {
                if (!haystack.TryGetValue(clause[0], out string? value) || value.Length > 65536
                    || !clause.Skip(2).Any(pattern => clause[1] switch
                    {
                        "equals" => value.Equals(pattern, StringComparison.OrdinalIgnoreCase),
                        "contains" => value.Contains(pattern, StringComparison.OrdinalIgnoreCase),
                        "startswith" => value.StartsWith(pattern, StringComparison.OrdinalIgnoreCase),
                        "endswith" => value.EndsWith(pattern, StringComparison.OrdinalIgnoreCase),
                        _ => false
                    }))
                {
                    match = false;
                    break;
                }

                fields.Add(clause[0]);
            }

            results.Add(name, (match, match ? fields : []));
        }

        Stack<(bool Match, List<string> Fields)> stack = new();
        foreach (string token in program)
        {
            if (token == "not")
            {
                stack.Push((!stack.Pop().Match, []));
            }
            else if (token is "and" or "or")
            {
                var right = stack.Pop();
                var left = stack.Pop();
                bool match = token == "and" ? left.Match && right.Match : left.Match || right.Match;
                stack.Push((match, match ? [.. left.Fields, .. right.Fields] : []));
            }
            else
            {
                stack.Push(results[token]);
            }
        }

        var result = stack.Pop();
        matchedFields = result.Fields.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return result.Match;
    }

    private sealed class ConditionParser(string condition, IEnumerable<string> names)
    {
        private readonly HashSet<string> names = new(names, StringComparer.OrdinalIgnoreCase);
        private readonly List<string> tokens = [];
        private readonly List<string> output = [];
        private int position;

        internal List<string> Parse()
        {
            if (condition.Length is < 1 or > 4096)
            {
                throw Invalid();
            }

            for (int i = 0; i < condition.Length;)
            {
                char c = condition[i];
                if (c is ' ' or '\t' or '\r' or '\n') { i++; continue; }
                int start = i++;
                if (char.IsAsciiLetter(c) || c == '_')
                {
                    while (i < condition.Length && (char.IsAsciiLetterOrDigit(condition[i]) || condition[i] == '_')) { i++; }
                }
                else if (c is not ('(' or ')')) { throw Invalid(); }
                tokens.Add(condition[start..i]);
                if (tokens.Count > 256) { throw Invalid(); }
            }

            Or(0);
            if (position != tokens.Count) { throw Invalid(); }
            return output;
        }

        private bool Take(string token)
        {
            if (position < tokens.Count && tokens[position].Equals(token, StringComparison.OrdinalIgnoreCase))
            {
                position++;
                return true;
            }
            return false;
        }

        private void Or(int depth)
        {
            And(depth);
            while (Take("or")) { And(depth); output.Add("or"); }
        }

        private void And(int depth)
        {
            Unary(depth);
            while (Take("and")) { Unary(depth); output.Add("and"); }
        }

        private void Unary(int depth)
        {
            if (depth > 32) { throw Invalid(); }
            if (Take("not")) { Unary(depth + 1); output.Add("not"); }
            else if (Take("("))
            {
                Or(depth + 1);
                if (!Take(")")) { throw Invalid(); }
            }
            else if (position < tokens.Count && names.Contains(tokens[position])) { output.Add(tokens[position++]); }
            else { throw Invalid(); }
        }
    }
}

[System.Text.Json.Serialization.JsonSerializable(typeof(string[][]))]
internal sealed partial class DetectionJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
