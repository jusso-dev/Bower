using System.Globalization;
using System.Text;

namespace Bower.Pipeline.Transforms;

// Abstract syntax. Positions are 0-based UTF-16 offsets within one statement string.

internal abstract record TransformExpression(int Position);

internal sealed record LiteralExpression(int Position, TransformValue Value) : TransformExpression(Position);

internal sealed record PathExpression(int Position, IReadOnlyList<string> Segments) : TransformExpression(Position);

internal sealed record NotExpression(int Position, TransformExpression Operand) : TransformExpression(Position);

internal sealed record BinaryExpression(int Position, string Operator, TransformExpression Left, TransformExpression Right)
    : TransformExpression(Position);

internal sealed record CallExpression(int Position, string Name, IReadOnlyList<TransformExpression> Arguments)
    : TransformExpression(Position)
{
    /// <summary>Resolved at compile time: regex, table or timestamp format.</summary>
    public object? Bound { get; set; }
}

internal abstract record TransformStatement(int Position);

internal sealed record AssignStatement(int Position, string Target, TransformExpression Value) : TransformStatement(Position);

internal sealed record DeleteStatement(int Position, string Target) : TransformStatement(Position);

internal sealed record RenameStatement(int Position, string From, string To, int ToPosition) : TransformStatement(Position);

internal sealed record IfStatement(
    int Position,
    TransformExpression Condition,
    IReadOnlyList<TransformStatement> Then,
    IReadOnlyList<TransformStatement>? Else) : TransformStatement(Position);

internal sealed class TransformSyntaxException(int position, string code) : Exception(code)
{
    public int Position { get; } = position;

    public string Code { get; } = code;
}

internal enum TokenKind
{
    Path,
    String,
    Int,
    Identifier,
    Operator,
    End
}

internal sealed record Token(TokenKind Kind, int Position, string Text, IReadOnlyList<string>? Segments = null, long Int = 0);

/// <summary>Lexer and recursive-descent parser for one statement.</summary>
internal sealed class TransformParser
{
    private static readonly string[] TwoCharacterOperators = ["==", "!=", "<=", ">=", "&&", "||"];
    private const string SingleCharacterOperators = "<>!=(){},;";

    private readonly List<Token> tokens;
    private int index;
    private int depth;
    private int blockDepth;
    private int nodes;

    private TransformParser(List<Token> tokens) => this.tokens = tokens;

    public static TransformStatement Parse(string text)
    {
        TransformParser parser = new(Lex(text));
        TransformStatement statement = parser.ParseStatement();
        if (parser.Current.Kind != TokenKind.End)
        {
            throw new TransformSyntaxException(parser.Current.Position, TransformErrorCodes.Syntax);
        }

        return statement;
    }

    private Token Current => tokens[index];

    private static bool IsSegmentCharacter(char character) =>
        char.IsAsciiLetterOrDigit(character) || character is '_' or '@' or '-';

    private static List<Token> Lex(string text)
    {
        if (!TransformValue.IsWellFormed(text))
        {
            throw new TransformSyntaxException(0, TransformErrorCodes.Syntax);
        }

        List<Token> tokens = [];
        int position = 0;
        while (position < text.Length)
        {
            char current = text[position];
            if (current is ' ' or '\t' or '\r' or '\n')
            {
                position++;
                continue;
            }

            int start = position;
            if (current == '.')
            {
                List<string> segments = [];
                while (position < text.Length && text[position] == '.')
                {
                    position++;
                    if (position < text.Length && text[position] == '"')
                    {
                        int quote = position;
                        string segment = ReadQuoted(text, ref position);
                        if (segment.Length == 0)
                        {
                            throw new TransformSyntaxException(quote, TransformErrorCodes.Syntax);
                        }

                        segments.Add(segment);
                    }
                    else
                    {
                        int segmentStart = position;
                        while (position < text.Length && IsSegmentCharacter(text[position]))
                        {
                            position++;
                        }

                        if (position == segmentStart)
                        {
                            throw new TransformSyntaxException(segmentStart - 1, TransformErrorCodes.Syntax);
                        }

                        segments.Add(text[segmentStart..position]);
                    }
                }

                tokens.Add(new Token(TokenKind.Path, start, string.Empty, segments));
            }
            else if (current == '"')
            {
                tokens.Add(new Token(TokenKind.String, start, ReadQuoted(text, ref position)));
            }
            else if (current == '\'')
            {
                position++;
                int end = text.IndexOf('\'', position);
                if (end < 0)
                {
                    throw new TransformSyntaxException(start, TransformErrorCodes.Syntax);
                }

                for (int scan = position; scan < end; scan++)
                {
                    if (text[scan] < ' ')
                    {
                        throw new TransformSyntaxException(scan, TransformErrorCodes.Syntax);
                    }
                }

                tokens.Add(new Token(TokenKind.String, start, text[position..end]));
                position = end + 1;
            }
            else if (char.IsAsciiDigit(current) || current == '-')
            {
                position++;
                if (current == '-' && (position >= text.Length || !char.IsAsciiDigit(text[position])))
                {
                    throw new TransformSyntaxException(start, TransformErrorCodes.Syntax);
                }

                int digits = current == '-' ? position : start;
                while (position < text.Length && char.IsAsciiDigit(text[position]))
                {
                    position++;
                }

                string number = text[start..position];
                if ((text[digits] == '0' && position - digits > 1)
                    || !long.TryParse(number, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long value))
                {
                    throw new TransformSyntaxException(start, TransformErrorCodes.Syntax);
                }

                tokens.Add(new Token(TokenKind.Int, start, number, Int: value));
            }
            else if (char.IsAsciiLetter(current) || current == '_')
            {
                while (position < text.Length && (char.IsAsciiLetterOrDigit(text[position]) || text[position] == '_'))
                {
                    position++;
                }

                tokens.Add(new Token(TokenKind.Identifier, start, text[start..position]));
            }
            else
            {
                string? two = position + 1 < text.Length
                    ? TwoCharacterOperators.FirstOrDefault(item => string.CompareOrdinal(text, position, item, 0, 2) == 0)
                    : null;
                if (two is not null)
                {
                    tokens.Add(new Token(TokenKind.Operator, start, two));
                    position += 2;
                }
                else if (SingleCharacterOperators.Contains(current, StringComparison.Ordinal))
                {
                    tokens.Add(new Token(TokenKind.Operator, start, current.ToString()));
                    position++;
                }
                else
                {
                    throw new TransformSyntaxException(start, TransformErrorCodes.Syntax);
                }
            }
        }

        tokens.Add(new Token(TokenKind.End, text.Length, string.Empty));
        return tokens;
    }

    /// <summary>Double-quoted text with <c>\" \\ \n \r \t</c> escapes; no raw control characters.</summary>
    private static string ReadQuoted(string text, ref int position)
    {
        int start = position;
        position++;
        StringBuilder value = new();
        while (true)
        {
            if (position >= text.Length)
            {
                throw new TransformSyntaxException(start, TransformErrorCodes.Syntax);
            }

            char current = text[position];
            if (current == '"')
            {
                position++;
                return value.ToString();
            }

            if (current < ' ')
            {
                throw new TransformSyntaxException(position, TransformErrorCodes.Syntax);
            }

            if (current == '\\')
            {
                char? escaped = position + 1 < text.Length
                    ? text[position + 1] switch
                    {
                        '"' => '"',
                        '\\' => '\\',
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        _ => null
                    }
                    : null;
                if (escaped is null)
                {
                    throw new TransformSyntaxException(position, TransformErrorCodes.Syntax);
                }

                value.Append(escaped.Value);
                position += 2;
                continue;
            }

            value.Append(current);
            position++;
        }
    }

    private bool IsOperator(string text) => Current.Kind == TokenKind.Operator && Current.Text == text;

    private bool IsKeyword(string text) => Current.Kind == TokenKind.Identifier && Current.Text == text;

    private Token Expect(string text)
    {
        if (!IsOperator(text))
        {
            throw new TransformSyntaxException(Current.Position, TransformErrorCodes.Syntax);
        }

        return tokens[index++];
    }

    private void CountNode(int position)
    {
        if (++nodes > TransformLimits.MaximumNodesPerStatement)
        {
            throw new TransformSyntaxException(position, TransformErrorCodes.LimitExceeded);
        }
    }

    private void Enter(int position)
    {
        if (++depth > TransformLimits.MaximumExpressionDepth)
        {
            throw new TransformSyntaxException(position, TransformErrorCodes.LimitExceeded);
        }
    }

    private (string Name, int Position) Target()
    {
        Token token = Current;
        if (token.Kind != TokenKind.Path)
        {
            throw new TransformSyntaxException(token.Position, TransformErrorCodes.Syntax);
        }

        index++;
        if (token.Segments!.Count != 1)
        {
            throw new TransformSyntaxException(token.Position, TransformErrorCodes.InvalidTarget);
        }

        return (token.Segments[0], token.Position);
    }

    private TransformStatement ParseStatement()
    {
        Token start = Current;
        CountNode(start.Position);
        if (IsKeyword("if"))
        {
            index++;
            return ParseIf(start.Position);
        }

        if (IsKeyword("del"))
        {
            index++;
            Expect("(");
            (string target, _) = Target();
            Expect(")");
            return new DeleteStatement(start.Position, target);
        }

        if (IsKeyword("rename"))
        {
            index++;
            Expect("(");
            (string from, _) = Target();
            Expect(",");
            (string to, int toPosition) = Target();
            Expect(")");
            return new RenameStatement(start.Position, from, to, toPosition);
        }

        if (start.Kind == TokenKind.Path)
        {
            (string target, _) = Target();
            Expect("=");
            return new AssignStatement(start.Position, target, ParseExpression());
        }

        throw new TransformSyntaxException(start.Position, TransformErrorCodes.Syntax);
    }

    private IfStatement ParseIf(int position)
    {
        if (++blockDepth > TransformLimits.MaximumBlockDepth)
        {
            throw new TransformSyntaxException(position, TransformErrorCodes.LimitExceeded);
        }

        TransformExpression condition = ParseExpression();
        IReadOnlyList<TransformStatement> then = ParseBlock();
        IReadOnlyList<TransformStatement>? otherwise = null;
        if (IsKeyword("else"))
        {
            index++;
            if (IsKeyword("if"))
            {
                Token nested = Current;
                CountNode(nested.Position);
                index++;
                otherwise = [ParseIf(nested.Position)];
            }
            else
            {
                otherwise = ParseBlock();
            }
        }

        blockDepth--;
        return new IfStatement(position, condition, then, otherwise);
    }

    private List<TransformStatement> ParseBlock()
    {
        Expect("{");
        List<TransformStatement> statements = [ParseStatement()];
        while (IsOperator(";"))
        {
            index++;
            if (IsOperator("}"))
            {
                break;
            }

            statements.Add(ParseStatement());
        }

        Expect("}");
        return statements;
    }

    private TransformExpression ParseExpression()
    {
        TransformExpression left = ParseAnd();
        while (IsOperator("||"))
        {
            Token token = tokens[index++];
            CountNode(token.Position);
            left = new BinaryExpression(token.Position, token.Text, left, ParseAnd());
        }

        return left;
    }

    private TransformExpression ParseAnd()
    {
        TransformExpression left = ParseUnary();
        while (IsOperator("&&"))
        {
            Token token = tokens[index++];
            CountNode(token.Position);
            left = new BinaryExpression(token.Position, token.Text, left, ParseUnary());
        }

        return left;
    }

    private TransformExpression ParseUnary()
    {
        if (IsOperator("!"))
        {
            Token token = tokens[index++];
            CountNode(token.Position);
            Enter(token.Position);
            TransformExpression operand = ParseUnary();
            depth--;
            return new NotExpression(token.Position, operand);
        }

        TransformExpression left = ParsePrimary();
        if (Current.Kind == TokenKind.Operator && Current.Text is "==" or "!=" or "<" or "<=" or ">" or ">=")
        {
            Token token = tokens[index++];
            CountNode(token.Position);
            return new BinaryExpression(token.Position, token.Text, left, ParsePrimary());
        }

        return left;
    }

    private TransformExpression ParsePrimary()
    {
        Token token = Current;
        CountNode(token.Position);
        switch (token.Kind)
        {
            case TokenKind.String:
                index++;
                return new LiteralExpression(token.Position, TransformValue.FromString(token.Text));
            case TokenKind.Int:
                index++;
                return new LiteralExpression(token.Position, TransformValue.FromInt(token.Int));
            case TokenKind.Path:
                index++;
                return new PathExpression(token.Position, token.Segments!);
            case TokenKind.Identifier:
                index++;
                switch (token.Text)
                {
                    case "true":
                        return new LiteralExpression(token.Position, TransformValue.True);
                    case "false":
                        return new LiteralExpression(token.Position, TransformValue.False);
                    case "null":
                        return new LiteralExpression(token.Position, TransformValue.Null);
                }

                Expect("(");
                Enter(token.Position);
                List<TransformExpression> arguments = [];
                if (!IsOperator(")"))
                {
                    arguments.Add(ParseExpression());
                    while (IsOperator(","))
                    {
                        index++;
                        if (arguments.Count == TransformLimits.MaximumArguments)
                        {
                            throw new TransformSyntaxException(token.Position, TransformErrorCodes.Arity);
                        }

                        arguments.Add(ParseExpression());
                    }
                }

                Expect(")");
                depth--;
                return new CallExpression(token.Position, token.Text, arguments);
            default:
                if (IsOperator("("))
                {
                    index++;
                    Enter(token.Position);
                    TransformExpression inner = ParseExpression();
                    Expect(")");
                    depth--;
                    return inner;
                }

                throw new TransformSyntaxException(token.Position, TransformErrorCodes.Syntax);
        }
    }
}
