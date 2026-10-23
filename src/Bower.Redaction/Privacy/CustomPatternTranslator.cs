using System.Text;

namespace Bower.Redaction.Privacy;

/// <summary>A custom detector pattern translated to the canonical form that is compiled.</summary>
/// <param name="CanonicalPattern">Pattern text compiled by both the C# and Rust engines.</param>
/// <param name="Complexity">Expansion estimate, saturated just above <see cref="CustomPatternTranslator.MaximumComplexity"/>.</param>
/// <param name="MatchesEmpty">True when the pattern can produce a zero-length match.</param>
public sealed record CustomPatternTranslation(string CanonicalPattern, int Complexity, bool MatchesEmpty);

/// <summary>A custom detector pattern uses syntax outside the restricted subset.</summary>
public sealed class CustomPatternSyntaxException : Exception
{
    public CustomPatternSyntaxException()
        : this(0, CustomPatternReasons.UnsupportedEscape)
    {
    }

    public CustomPatternSyntaxException(string message)
        : this(0, message)
    {
    }

    public CustomPatternSyntaxException(string message, Exception innerException)
        : base(message, innerException)
    {
        Reason = message;
    }

    public CustomPatternSyntaxException(int position, string reason)
        : base(reason)
    {
        Position = position;
        Reason = reason;
    }

    /// <summary>Zero-based index of the offending character in the pattern.</summary>
    public int Position { get; }

    /// <summary>One of <see cref="CustomPatternReasons"/>.</summary>
    public string Reason { get; } = CustomPatternReasons.UnsupportedEscape;
}

/// <summary>
/// Fixed rejection reasons for custom detector patterns. The Rust port uses the same
/// list, so profile errors are identical in both engines.
/// </summary>
public static class CustomPatternReasons
{
    public const string Lookaround = "lookaround is not supported";
    public const string BackReference = "back-references are not supported";
    public const string UnicodeProperty = "unicode properties are not supported";
    public const string InlineFlags = "inline flags are not supported";
    public const string NamedGroup = "named groups are not supported";
    public const string UnsupportedGroup = "unsupported group construct";
    public const string UnbalancedParenthesis = "unbalanced parenthesis";
    public const string UnterminatedClass = "unterminated character class";
    public const string EmptyClass = "empty character class";
    public const string NestedClass = "nested character classes are not supported";
    public const string PosixClass = "POSIX character classes are not supported";
    public const string SetOperation = "character class set operations are not supported";
    public const string InvalidRange = "invalid character class range";
    public const string NegatedShorthandInClass = "negated shorthand classes are not supported inside character classes";
    public const string InvalidQuantifier = "invalid quantifier";
    public const string QuantifierBound = "quantifier bound above 1000";
    public const string NothingToRepeat = "nothing to repeat";
    public const string RepeatedQuantifier = "quantifier follows another quantifier";
    public const string WordBoundary = "word boundaries are not supported; use wholeWord";
    public const string AnchorEscape = "anchor escapes are not supported; use ^ and $";
    public const string UnsupportedEscape = "unsupported escape";
    public const string TrailingBackslash = "trailing backslash";
    public const string SupplementaryCharacter = "characters outside the Basic Multilingual Plane are not supported";
    public const string ReservedCharacter = "character U+FFFF is not supported";

    /// <summary>Every reason, in a stable order (documentation and parity tests).</summary>
    public static IReadOnlyList<string> All { get; } =
    [
        Lookaround,
        BackReference,
        UnicodeProperty,
        InlineFlags,
        NamedGroup,
        UnsupportedGroup,
        UnbalancedParenthesis,
        UnterminatedClass,
        EmptyClass,
        NestedClass,
        PosixClass,
        SetOperation,
        InvalidRange,
        NegatedShorthandInClass,
        InvalidQuantifier,
        QuantifierBound,
        NothingToRepeat,
        RepeatedQuantifier,
        WordBoundary,
        AnchorEscape,
        UnsupportedEscape,
        TrailingBackslash,
        SupplementaryCharacter,
        ReservedCharacter
    ];
}

/// <summary>
/// Validates a custom detector pattern against the restricted syntax and emits the
/// canonical pattern that is actually compiled. The canonical form is identical in the
/// C# and Rust engines: ASCII-only shorthand classes, <c>.</c> as <c>[^\n]</c>, anchors as
/// <c>\A</c>/<c>\z</c>, non-capturing groups, explicit escapes, case-insensitivity expanded
/// into classes, and character ranges never covering UTF-16 surrogates. No engine
/// option changes its meaning, so .NET (UTF-16 units) and Rust (scalars over a
/// surrogate-preserving haystack) find the same spans.
/// </summary>
public static class CustomPatternTranslator
{
    public const int MaximumComplexity = 1000;
    public const int MaximumRepeat = 1000;

    private const int Saturated = MaximumComplexity + 1;
    private const string Digit = "0-9";
    private const string Word = "0-9A-Z_a-z";
    private const string Space = "\\t\\n\\x0B\\f\\r ";

    /// <exception cref="CustomPatternSyntaxException">The pattern uses unsupported syntax.</exception>
    public static CustomPatternTranslation Translate(string pattern, bool ignoreCase)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        Parser parser = new(pattern, ignoreCase);
        Piece piece = parser.ParseAlternation();
        if (!parser.AtEnd)
        {
            // Only an unmatched ')' stops the top-level alternation early.
            throw new CustomPatternSyntaxException(parser.Position, CustomPatternReasons.UnbalancedParenthesis);
        }

        return new CustomPatternTranslation(piece.Text, piece.Complexity, piece.Nullable);
    }

    private readonly record struct Piece(string Text, int Complexity, bool Nullable, bool Quantifiable);

    private static int Add(int left, int right) => Math.Min(left + right, Saturated);

    private static int Multiply(int left, int right) => (int)Math.Min((long)left * right, Saturated);

    private static bool IsAsciiLetter(char value) => value is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z');

    private static char SwapCase(char value) => (char)(value ^ 0x20);

    private static bool IsAsciiPunctuationOrSpace(char value) =>
        value is >= ' ' and <= '~' && !char.IsAsciiLetterOrDigit(value);

    private sealed class Parser(string pattern, bool ignoreCase)
    {
        private int position;

        public int Position => position;

        public bool AtEnd => position >= pattern.Length;

        private char Peek(int offset = 0) =>
            position + offset < pattern.Length ? pattern[position + offset] : '\0';

        private bool Has(int offset = 0) => position + offset < pattern.Length;

        public Piece ParseAlternation()
        {
            Piece first = ParseConcatenation();
            if (!Has() || Peek() != '|')
            {
                return first;
            }

            StringBuilder text = new(first.Text);
            int complexity = first.Complexity;
            bool nullable = first.Nullable;
            while (Has() && Peek() == '|')
            {
                position++;
                Piece branch = ParseConcatenation();
                text.Append('|').Append(branch.Text);
                complexity = Add(complexity, branch.Complexity);
                nullable |= branch.Nullable;
            }

            return new Piece(text.ToString(), complexity, nullable, Quantifiable: false);
        }

        private Piece ParseConcatenation()
        {
            StringBuilder text = new();
            int complexity = 0;
            bool nullable = true;
            while (Has() && Peek() is not ('|' or ')'))
            {
                Piece atom = ParseAtom();
                atom = ParseQuantifiers(atom);
                text.Append(atom.Text);
                complexity = Add(complexity, atom.Complexity);
                nullable &= atom.Nullable;
            }

            return new Piece(text.ToString(), complexity, nullable, Quantifiable: false);
        }

        private Piece ParseQuantifiers(Piece atom)
        {
            if (!Has() || !StartsQuantifier())
            {
                return atom;
            }

            int start = position;
            if (!atom.Quantifiable)
            {
                ReadQuantifier();
                throw new CustomPatternSyntaxException(start, CustomPatternReasons.NothingToRepeat);
            }

            (string suffix, int minimum, int multiplier) = ReadQuantifier();
            if (Has() && Peek() == '?')
            {
                position++;
                suffix += "?";
            }

            if (Has() && StartsQuantifier())
            {
                throw new CustomPatternSyntaxException(position, CustomPatternReasons.RepeatedQuantifier);
            }

            return new Piece(
                atom.Text + suffix,
                Multiply(atom.Complexity, multiplier),
                minimum == 0 || atom.Nullable,
                Quantifiable: false);
        }

        private bool StartsQuantifier() => Peek() is '*' or '+' or '?' or '{';

        /// <summary>Reads <c>* + ?</c> or a valid <c>{n}</c>, <c>{n,}</c>, <c>{n,m}</c>.</summary>
        private (string Suffix, int Minimum, int Multiplier) ReadQuantifier()
        {
            char first = Peek();
            if (first != '{')
            {
                position++;
                return (first.ToString(), first == '+' ? 1 : 0, 1);
            }

            int open = position;
            int index = position + 1;
            int? minimum = ReadNumber(ref index, open);
            if (minimum is null)
            {
                throw new CustomPatternSyntaxException(open, CustomPatternReasons.InvalidQuantifier);
            }

            int? maximum = minimum;
            bool openEnded = false;
            if (index < pattern.Length && pattern[index] == ',')
            {
                index++;
                if (index < pattern.Length && pattern[index] == '}')
                {
                    openEnded = true;
                    maximum = null;
                }
                else
                {
                    maximum = ReadNumber(ref index, open);
                    if (maximum is null)
                    {
                        throw new CustomPatternSyntaxException(open, CustomPatternReasons.InvalidQuantifier);
                    }
                }
            }

            if (index >= pattern.Length || pattern[index] != '}')
            {
                throw new CustomPatternSyntaxException(open, CustomPatternReasons.InvalidQuantifier);
            }

            if (maximum < minimum)
            {
                throw new CustomPatternSyntaxException(open, CustomPatternReasons.InvalidQuantifier);
            }

            position = index + 1;
            string suffix = openEnded
                ? $"{{{minimum.Value},}}"
                : maximum == minimum
                    ? $"{{{minimum.Value}}}"
                    : $"{{{minimum.Value},{maximum!.Value}}}";
            return (suffix, minimum.Value, Math.Max(Math.Max(minimum.Value, maximum ?? 0), 1));
        }

        /// <summary>Decimal digits; null when none. Values above 1000 are rejected.</summary>
        private int? ReadNumber(ref int index, int open)
        {
            int start = index;
            int value = 0;
            while (index < pattern.Length && char.IsAsciiDigit(pattern[index]))
            {
                value = Math.Min((value * 10) + (pattern[index] - '0'), MaximumRepeat + 1);
                index++;
            }

            if (index == start)
            {
                return null;
            }

            // Only report the bound once the quantifier is otherwise well formed enough to
            // be one: a closing brace or comma follows the digits.
            if (value > MaximumRepeat
                && index < pattern.Length
                && pattern[index] is '}' or ',')
            {
                throw new CustomPatternSyntaxException(open, CustomPatternReasons.QuantifierBound);
            }

            return value;
        }

        private Piece ParseAtom()
        {
            int start = position;
            char current = Peek();
            switch (current)
            {
                case '(':
                    return ParseGroup();
                case '[':
                    return ParseClass();
                case '.':
                    position++;
                    return new Piece("[^\\n]", 1, Nullable: false, Quantifiable: true);
                case '^':
                    position++;
                    return new Piece("\\A", 1, Nullable: true, Quantifiable: false);
                case '$':
                    position++;
                    return new Piece("\\z", 1, Nullable: true, Quantifiable: false);
                case '\\':
                    return ParseEscape();
                case '*' or '+' or '?':
                    throw new CustomPatternSyntaxException(start, CustomPatternReasons.NothingToRepeat);
                case '{':
                    // A well-formed quantifier with nothing before it; otherwise malformed.
                    ReadQuantifier();
                    throw new CustomPatternSyntaxException(start, CustomPatternReasons.NothingToRepeat);
                default:
                    position++;
                    return Literal(CheckLiteral(current, start));
            }
        }

        private Piece ParseGroup()
        {
            int open = position;
            position++;
            if (Has() && Peek() == '?')
            {
                char kind = Peek(1);
                if (kind == ':')
                {
                    position += 2;
                }
                else
                {
                    throw new CustomPatternSyntaxException(open, kind switch
                    {
                        '=' or '!' => CustomPatternReasons.Lookaround,
                        '<' when Peek(2) is '=' or '!' => CustomPatternReasons.Lookaround,
                        '<' or '\'' or 'P' => CustomPatternReasons.NamedGroup,
                        '-' => CustomPatternReasons.InlineFlags,
                        _ when char.IsAsciiLetter(kind) => CustomPatternReasons.InlineFlags,
                        _ => CustomPatternReasons.UnsupportedGroup
                    });
                }
            }

            Piece inner = ParseAlternation();
            if (!Has() || Peek() != ')')
            {
                throw new CustomPatternSyntaxException(open, CustomPatternReasons.UnbalancedParenthesis);
            }

            position++;
            return new Piece($"(?:{inner.Text})", inner.Complexity, inner.Nullable, Quantifiable: true);
        }

        private Piece ParseEscape()
        {
            int start = position;
            if (!Has(1))
            {
                throw new CustomPatternSyntaxException(start, CustomPatternReasons.TrailingBackslash);
            }

            char escaped = Peek(1);
            position += 2;
            switch (escaped)
            {
                case 'd':
                    return Class($"[{Digit}]");
                case 'D':
                    return Class($"[^{Digit}]");
                case 'w':
                    return Class($"[{Word}]");
                case 'W':
                    return Class($"[^{Word}]");
                case 's':
                    return Class($"[{Space}]");
                case 'S':
                    return Class($"[^{Space}]");
                case 't':
                    return Literal('\t');
                case 'n':
                    return Literal('\n');
                case 'r':
                    return Literal('\r');
            }

            return Literal(EscapedLiteral(escaped, start));
        }

        /// <summary>Shared escape rules (outside and inside classes) for non-shorthand escapes.</summary>
        private static char EscapedLiteral(char escaped, int start)
        {
            if (escaped is '<' or '>')
            {
                throw new CustomPatternSyntaxException(start, CustomPatternReasons.WordBoundary);
            }

            if (IsAsciiPunctuationOrSpace(escaped))
            {
                return escaped;
            }

            throw new CustomPatternSyntaxException(start, escaped switch
            {
                >= '1' and <= '9' or 'k' => CustomPatternReasons.BackReference,
                'p' or 'P' => CustomPatternReasons.UnicodeProperty,
                'b' or 'B' => CustomPatternReasons.WordBoundary,
                'A' or 'z' or 'Z' or 'G' => CustomPatternReasons.AnchorEscape,
                _ => CustomPatternReasons.UnsupportedEscape
            });
        }

        /// <summary>Rejects characters that cannot have identical semantics in both engines.</summary>
        private static char CheckLiteral(char value, int start)
        {
            if (char.IsSurrogate(value))
            {
                throw new CustomPatternSyntaxException(start, CustomPatternReasons.SupplementaryCharacter);
            }

            if (value == '\uFFFF')
            {
                throw new CustomPatternSyntaxException(start, CustomPatternReasons.ReservedCharacter);
            }

            return value;
        }

        private static Piece Class(string text) => new(text, 1, Nullable: false, Quantifiable: true);

        private Piece Literal(char value)
        {
            if (ignoreCase && IsAsciiLetter(value))
            {
                return Class($"[{value}{SwapCase(value)}]");
            }

            string text = value switch
            {
                '\t' => "\\t",
                '\n' => "\\n",
                '\r' => "\\r",
                '\\' or '.' or '+' or '*' or '?' or '(' or ')' or '|' or '[' or ']' or '{' or '}' or '^' or '$' =>
                    "\\" + value,
                _ => value.ToString()
            };
            return new Piece(text, 1, Nullable: false, Quantifiable: true);
        }

        private Piece ParseClass()
        {
            int open = position;
            position++;
            StringBuilder text = new("[");
            if (Has() && Peek() == '^')
            {
                text.Append('^');
                position++;
            }

            if (!Has())
            {
                throw new CustomPatternSyntaxException(open, CustomPatternReasons.UnterminatedClass);
            }

            if (Peek() == ']')
            {
                throw new CustomPatternSyntaxException(open, CustomPatternReasons.EmptyClass);
            }

            while (true)
            {
                if (!Has())
                {
                    throw new CustomPatternSyntaxException(open, CustomPatternReasons.UnterminatedClass);
                }

                char current = Peek();
                if (current == ']')
                {
                    position++;
                    break;
                }

                if ((current is '&' or '~' or '-' && Peek(1) == current && Has(1))
                    || (current == '-' && Peek(1) == '[' && Has(1)))
                {
                    throw new CustomPatternSyntaxException(position, CustomPatternReasons.SetOperation);
                }

                if (current == '[')
                {
                    throw new CustomPatternSyntaxException(
                        position,
                        Peek(1) == ':' && Has(1) ? CustomPatternReasons.PosixClass : CustomPatternReasons.NestedClass);
                }

                int itemStart = position;
                (char? low, string? shorthand) = ParseClassAtom();
                if (Has() && Peek() == '-' && Has(1) && Peek(1) != ']')
                {
                    int dash = position;
                    if (Peek(1) is '-' or '[')
                    {
                        throw new CustomPatternSyntaxException(dash, CustomPatternReasons.SetOperation);
                    }

                    position++;
                    (char? high, string? highShorthand) = ParseClassAtom();
                    if (low is null || high is null || highShorthand is not null || shorthand is not null || high < low)
                    {
                        throw new CustomPatternSyntaxException(itemStart, CustomPatternReasons.InvalidRange);
                    }

                    AppendRange(text, low.Value, high.Value);
                    continue;
                }

                if (shorthand is not null)
                {
                    text.Append(shorthand);
                }
                else
                {
                    AppendRange(text, low!.Value, low.Value);
                }
            }

            text.Append(']');
            return Class(text.ToString());
        }

        /// <summary>A single class character or a shorthand expansion (<c>\d \w \s</c>).</summary>
        private (char? Character, string? Shorthand) ParseClassAtom()
        {
            int start = position;
            char current = Peek();
            if (current != '\\')
            {
                position++;
                return (CheckLiteral(current, start), null);
            }

            if (!Has(1))
            {
                throw new CustomPatternSyntaxException(start, CustomPatternReasons.TrailingBackslash);
            }

            char escaped = Peek(1);
            position += 2;
            return escaped switch
            {
                'd' => (null, Digit),
                'w' => (null, Word),
                's' => (null, Space),
                'D' or 'W' or 'S' => throw new CustomPatternSyntaxException(start, CustomPatternReasons.NegatedShorthandInClass),
                't' => ('\t', null),
                'n' => ('\n', null),
                'r' => ('\r', null),
                _ => (EscapedLiteral(escaped, start), null)
            };
        }

        /// <summary>
        /// Appends a range (or single character) without covering UTF-16 surrogates, plus its
        /// swapped-case ASCII letters when ignoring case.
        /// </summary>
        private void AppendRange(StringBuilder text, char low, char high)
        {
            if (low < '\uD800' && high > '\uDFFF')
            {
                AppendPlainRange(text, low, '\uD7FF');
                AppendPlainRange(text, '\uE000', high);
            }
            else
            {
                AppendPlainRange(text, low, high);
            }

            if (!ignoreCase)
            {
                return;
            }

            AppendSwapped(text, low, high, 'A', 'Z');
            AppendSwapped(text, low, high, 'a', 'z');
        }

        private static void AppendSwapped(StringBuilder text, char low, char high, char first, char last)
        {
            char from = low > first ? low : first;
            char to = high < last ? high : last;
            if (from <= to)
            {
                AppendPlainRange(text, SwapCase(from), SwapCase(to));
            }
        }

        private static void AppendPlainRange(StringBuilder text, char low, char high)
        {
            AppendClassCharacter(text, low);
            if (high != low)
            {
                text.Append('-');
                AppendClassCharacter(text, high);
            }
        }

        private static void AppendClassCharacter(StringBuilder text, char value)
        {
            switch (value)
            {
                case '\t':
                    text.Append("\\t");
                    break;
                case '\n':
                    text.Append("\\n");
                    break;
                case '\r':
                    text.Append("\\r");
                    break;
                case '\\' or ']' or '[' or '^' or '-' or '&' or '~':
                    text.Append('\\').Append(value);
                    break;
                default:
                    text.Append(value);
                    break;
            }
        }
    }
}
