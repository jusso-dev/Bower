namespace Bower.Pipeline.Transforms;

/// <summary>Validation and binding: syntax, functions, literals, targets, tables and sensitivity flow.</summary>
internal static class TransformCompiler
{
    /// <summary>Allow-listed functions and their arity. Nothing else can be called.</summary>
    internal static readonly IReadOnlyDictionary<string, (int Minimum, int Maximum)> Functions =
        new Dictionary<string, (int, int)>(StringComparer.Ordinal)
        {
            ["lower"] = (1, 1),
            ["upper"] = (1, 1),
            ["trim"] = (1, 1),
            ["replace"] = (3, 3),
            ["split"] = (2, 3),
            ["join"] = (2, 2),
            ["at"] = (2, 2),
            ["concat"] = (2, 8),
            ["contains"] = (2, 2),
            ["starts_with"] = (2, 2),
            ["ends_with"] = (2, 2),
            ["coalesce"] = (2, 8),
            ["lookup"] = (2, 2),
            ["regex_match"] = (2, 2),
            ["regex_extract"] = (2, 2),
            ["parse_timestamp"] = (2, 2),
            ["to_string"] = (1, 1),
            ["to_int"] = (1, 1),
            ["to_bool"] = (1, 1),
            ["now"] = (0, 0)
        };

    public static IReadOnlyList<TransformIssue> Compile(TransformDefinition definition, out List<TransformStatement> compiled)
    {
        compiled = [];
        List<TransformIssue> issues = [];
        IReadOnlyList<string?>? statements = definition.Statements;
        if (statements is null || statements.Count is < 1 or > TransformLimits.MaximumStatements)
        {
            issues.Add(new TransformIssue(0, 0, TransformErrorCodes.LimitExceeded));
            return issues;
        }

        if (definition.Tables is not null && !ValidTables(definition.Tables))
        {
            issues.Add(new TransformIssue(0, 0, TransformErrorCodes.InvalidTable));
        }

        Dictionary<string, bool> declared = new(StringComparer.Ordinal);
        foreach (CustomLogField field in definition.Fields ?? [])
        {
            if (field?.SourceName is { } name)
            {
                declared[name] = declared.GetValueOrDefault(name) || field.Sensitive;
            }
        }

        Binder binder = new(definition.Tables);
        Dictionary<string, bool> taint = new(StringComparer.Ordinal);
        for (int number = 1; number <= statements.Count; number++)
        {
            string? text = statements[number - 1];
            if (string.IsNullOrWhiteSpace(text))
            {
                issues.Add(new TransformIssue(number, 1, TransformErrorCodes.Syntax));
                continue;
            }

            if (text.Length > TransformLimits.MaximumStatementLength)
            {
                issues.Add(new TransformIssue(number, 1, TransformErrorCodes.LimitExceeded));
                continue;
            }

            try
            {
                TransformStatement statement = TransformParser.Parse(text);
                binder.Bind(statement);
                Dictionary<string, bool> next = new(taint, StringComparer.Ordinal);
                new FlowChecker(declared, next).Statement(statement, false);
                taint = next;
                compiled.Add(statement);
            }
            catch (TransformSyntaxException exception)
            {
                issues.Add(new TransformIssue(number, exception.Position + 1, exception.Code));
            }
        }

        return issues;
    }

    private static bool ValidTables(IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> tables)
    {
        if (tables.Count > TransformLimits.MaximumTables)
        {
            return false;
        }

        int total = 0;
        foreach ((string name, IReadOnlyDictionary<string, string>? entries) in tables)
        {
            if (!IsTableName(name) || entries is null || entries.Count > TransformLimits.MaximumTableEntries)
            {
                return false;
            }

            total += entries.Count;
            foreach ((string key, string? value) in entries)
            {
                if (key.Length is < 1 or > TransformLimits.MaximumTableKeyLength
                    || value is null || value.Length > TransformLimits.MaximumTableValueLength
                    || !TransformValue.IsWellFormed(key) || !TransformValue.IsWellFormed(value))
                {
                    return false;
                }
            }
        }

        return total <= TransformLimits.MaximumTotalTableEntries;
    }

    private static bool IsTableName(string name) =>
        name.Length is >= 1 and <= TransformLimits.MaximumTableNameLength
        && (char.IsAsciiLetter(name[0]) || name[0] == '_')
        && name.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-');

    /// <summary>
    /// Write targets: a valid parser field name that is not credential-like and not
    /// reserved for Bower or the security decision.
    /// </summary>
    internal static bool IsWritable(string name) =>
        CustomLogParser.IsValidFieldName(name)
        && !CustomLogParser.IsProhibited(name)
        && !name.Equals("security", StringComparison.OrdinalIgnoreCase)
        && !name.StartsWith("security.", StringComparison.OrdinalIgnoreCase)
        && !name.StartsWith("bower", StringComparison.OrdinalIgnoreCase);

    private sealed class Binder(IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>>? tables)
    {
        private int regexes;

        public void Bind(TransformStatement statement)
        {
            switch (statement)
            {
                case AssignStatement assign:
                    Target(assign.Target, assign.Position);
                    Bind(assign.Value);
                    break;
                case DeleteStatement delete:
                    Target(delete.Target, delete.Position);
                    break;
                case RenameStatement rename:
                    Target(rename.From, rename.Position);
                    Target(rename.To, rename.ToPosition);
                    if (string.Equals(rename.From, rename.To, StringComparison.Ordinal))
                    {
                        throw new TransformSyntaxException(rename.ToPosition, TransformErrorCodes.InvalidTarget);
                    }

                    break;
                case IfStatement conditional:
                    Bind(conditional.Condition);
                    conditional.Then.ToList().ForEach(Bind);
                    conditional.Else?.ToList().ForEach(Bind);
                    break;
            }
        }

        private static void Target(string name, int position)
        {
            if (!IsWritable(name))
            {
                throw new TransformSyntaxException(position, TransformErrorCodes.InvalidTarget);
            }
        }

        private void Bind(TransformExpression expression)
        {
            switch (expression)
            {
                case PathExpression path:
                    if (path.Segments.Any(CustomLogParser.IsProhibited))
                    {
                        throw new TransformSyntaxException(path.Position, TransformErrorCodes.ProhibitedField);
                    }

                    break;
                case NotExpression not:
                    Bind(not.Operand);
                    break;
                case BinaryExpression binary:
                    Bind(binary.Left);
                    Bind(binary.Right);
                    break;
                case CallExpression call:
                    BindCall(call);
                    call.Arguments.ToList().ForEach(Bind);
                    break;
            }
        }

        private void BindCall(CallExpression call)
        {
            if (!Functions.TryGetValue(call.Name, out (int Minimum, int Maximum) arity))
            {
                throw new TransformSyntaxException(call.Position, TransformErrorCodes.UnknownFunction);
            }

            if (call.Arguments.Count < arity.Minimum || call.Arguments.Count > arity.Maximum)
            {
                throw new TransformSyntaxException(call.Position, TransformErrorCodes.Arity);
            }

            switch (call.Name)
            {
                case "replace":
                    RejectEmptyLiteral(call.Arguments[1]);
                    break;
                case "split":
                    RejectEmptyLiteral(call.Arguments[1]);
                    if (call.Arguments.Count == 3
                        && call.Arguments[2] is not LiteralExpression { Value.Kind: TransformKind.Int, Value.Int: >= 1 and <= TransformLimits.MaximumArrayLength })
                    {
                        throw new TransformSyntaxException(call.Arguments[2].Position, TransformErrorCodes.InvalidArgument);
                    }

                    break;
                case "lookup":
                    {
                        string name = StringLiteral(call.Arguments[0]);
                        if (tables is null || !tables.TryGetValue(name, out IReadOnlyDictionary<string, string>? table))
                        {
                            throw new TransformSyntaxException(call.Arguments[0].Position, TransformErrorCodes.UnknownTable);
                        }

                        call.Bound = table;
                        break;
                    }
                case "regex_match":
                case "regex_extract":
                    {
                        string pattern = StringLiteral(call.Arguments[1]);
                        if (++regexes > TransformLimits.MaximumRegexes)
                        {
                            throw new TransformSyntaxException(call.Position, TransformErrorCodes.LimitExceeded);
                        }

                        TransformRegex? regex = TransformRegex.TryCompile(pattern);
                        if (regex is null || (call.Name == "regex_extract" && regex.GroupNames.Count == 0))
                        {
                            throw new TransformSyntaxException(call.Arguments[1].Position, TransformErrorCodes.InvalidRegex);
                        }

                        call.Bound = regex;
                        break;
                    }
                case "parse_timestamp":
                    {
                        string format = StringLiteral(call.Arguments[1]);
                        if (!TransformTime.Formats.Contains(format, StringComparer.Ordinal))
                        {
                            throw new TransformSyntaxException(call.Arguments[1].Position, TransformErrorCodes.InvalidArgument);
                        }

                        call.Bound = format;
                        break;
                    }
            }
        }

        private static void RejectEmptyLiteral(TransformExpression argument)
        {
            if (argument is LiteralExpression { Value: { Kind: TransformKind.String, Text.Length: 0 } })
            {
                throw new TransformSyntaxException(argument.Position, TransformErrorCodes.InvalidArgument);
            }
        }

        private static string StringLiteral(TransformExpression argument) =>
            argument is LiteralExpression { Value.Kind: TransformKind.String } literal
                ? literal.Value.Text
                : throw new TransformSyntaxException(argument.Position, TransformErrorCodes.InvalidArgument);
    }

    /// <summary>
    /// Static sensitivity flow. Declared sensitive fields and every undeclared input field
    /// start sensitive. A value read from a sensitive field, or written under a condition
    /// that reads one, is sensitive. Declared non-sensitive fields may never receive a
    /// sensitive value or change under a sensitive condition, and declared sensitive fields
    /// may never be deleted or renamed away from redaction's view.
    /// </summary>
    private sealed class FlowChecker(IReadOnlyDictionary<string, bool> declared, Dictionary<string, bool> state)
    {
        public void Statement(TransformStatement statement, bool context)
        {
            switch (statement)
            {
                case AssignStatement assign:
                    Write(assign.Target, Tainted(assign.Value) || context, assign.Position);
                    break;
                case DeleteStatement delete:
                    Delete(delete.Target, context, delete.Position);
                    break;
                case RenameStatement rename:
                    if (declared.TryGetValue(rename.From, out bool sensitive) && sensitive)
                    {
                        throw new TransformSyntaxException(rename.Position, TransformErrorCodes.SensitiveField);
                    }

                    Write(rename.To, IsTainted(rename.From) || context, rename.ToPosition);
                    Delete(rename.From, context, rename.Position);
                    break;
                case IfStatement conditional:
                    {
                        bool inner = context || Tainted(conditional.Condition);
                        Dictionary<string, bool> before = new(state, StringComparer.Ordinal);
                        conditional.Then.ToList().ForEach(item => Statement(item, inner));
                        Dictionary<string, bool> afterThen = new(state, StringComparer.Ordinal);
                        state.Clear();
                        foreach ((string key, bool value) in before)
                        {
                            state[key] = value;
                        }

                        conditional.Else?.ToList().ForEach(item => Statement(item, inner));
                        foreach ((string key, bool value) in afterThen)
                        {
                            state[key] = value || IsTainted(key);
                        }

                        break;
                    }
            }
        }

        private bool IsTainted(string name) =>
            state.TryGetValue(name, out bool tainted) ? tainted : !declared.TryGetValue(name, out bool sensitive) || sensitive;

        private bool Tainted(TransformExpression expression) => expression switch
        {
            PathExpression path => IsTainted(path.Segments[0]),
            NotExpression not => Tainted(not.Operand),
            BinaryExpression binary => Tainted(binary.Left) | Tainted(binary.Right),
            CallExpression call => call.Arguments.Aggregate(false, (tainted, argument) => tainted | Tainted(argument)),
            _ => false
        };

        private void Write(string target, bool tainted, int position)
        {
            if (declared.TryGetValue(target, out bool sensitive))
            {
                if (!sensitive && tainted)
                {
                    throw new TransformSyntaxException(position, TransformErrorCodes.SensitiveFlow);
                }

                state[target] = sensitive;
                return;
            }

            state[target] = tainted;
        }

        private void Delete(string target, bool context, int position)
        {
            if (declared.TryGetValue(target, out bool sensitive))
            {
                if (sensitive)
                {
                    throw new TransformSyntaxException(position, TransformErrorCodes.SensitiveField);
                }

                if (context)
                {
                    throw new TransformSyntaxException(position, TransformErrorCodes.SensitiveFlow);
                }

                state[target] = false;
                return;
            }

            state[target] = context;
        }
    }
}
