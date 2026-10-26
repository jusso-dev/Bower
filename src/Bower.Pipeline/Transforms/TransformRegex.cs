namespace Bower.Pipeline.Transforms;

/// <summary>
/// Bower's own linear-time regular expressions: a small syntax compiled to a Pike VM over
/// Unicode scalar values, with leftmost-first (backtracking-compatible) priorities. Both
/// runtimes implement the same compiler and VM, so matches, captures and step counts are
/// identical. No backtracking, backreferences, lookaround, flags or Unicode classes.
/// </summary>
internal sealed class TransformRegex
{
    private readonly Instruction[] program;
    private readonly int[][] classes;
    private readonly bool[] negated;

    private TransformRegex(Instruction[] program, int[][] classes, bool[] negated, IReadOnlyList<string> groupNames)
    {
        this.program = program;
        this.classes = classes;
        this.negated = negated;
        GroupNames = groupNames;
    }

    public IReadOnlyList<string> GroupNames { get; }

    private enum Op
    {
        Char,
        Any,
        Class,
        Start,
        End,
        Split,
        Jump,
        Save,
        Match
    }

    private record struct Instruction(Op Op, int X = 0, int Y = 0);

    private enum NodeKind
    {
        Empty,
        Char,
        Any,
        Class,
        Start,
        End,
        Group,
        Concat,
        Alternate,
        Repeat
    }

    private sealed record Node(
        NodeKind Kind,
        int Value = 0,
        IReadOnlyList<Node>? Children = null,
        int Minimum = 0,
        int Maximum = 0,
        bool Greedy = true);

    public static TransformRegex? TryCompile(string pattern)
    {
        if (pattern.Length is < 1 or > TransformLimits.MaximumRegexPatternLength || !TransformValue.IsWellFormed(pattern))
        {
            return null;
        }

        PatternParser parser = new([.. pattern.EnumerateRunes().Select(rune => rune.Value)]);
        Node root;
        try
        {
            root = parser.ParseAlternation(0);
            if (parser.Position != parser.Pattern.Length)
            {
                return null;
            }
        }
        catch (FormatException)
        {
            return null;
        }

        if (Size(root) + 3 > TransformLimits.MaximumRegexInstructions)
        {
            return null;
        }

        List<Instruction> program = [new Instruction(Op.Save, 0)];
        Emit(root, program);
        program.Add(new Instruction(Op.Save, 1));
        program.Add(new Instruction(Op.Match));
        return new TransformRegex([.. program], [.. parser.Classes], [.. parser.Negated], parser.Names);
    }

    // Instruction count with saturation, so counted repetition cannot allocate before the limit check.
    private static long Size(Node node)
    {
        const long Cap = TransformLimits.MaximumRegexInstructions + 1L;
        long size = node.Kind switch
        {
            NodeKind.Empty => 0,
            NodeKind.Char or NodeKind.Any or NodeKind.Class or NodeKind.Start or NodeKind.End => 1,
            NodeKind.Group => Size(node.Children![0]) + (node.Value > 0 ? 2 : 0),
            NodeKind.Concat => node.Children!.Sum(Size),
            NodeKind.Alternate => node.Children!.Sum(Size) + (2L * (node.Children!.Count - 1)),
            _ => Repeated(node)
        };
        return Math.Min(size, Cap);

        static long Repeated(Node node)
        {
            long body = Size(node.Children![0]);
            return node.Maximum < 0
                ? (node.Minimum * body) + body + 2
                : (node.Minimum * body) + ((node.Maximum - node.Minimum) * (body + 1));
        }
    }

    private static void Emit(Node node, List<Instruction> program)
    {
        switch (node.Kind)
        {
            case NodeKind.Empty:
                break;
            case NodeKind.Char:
                program.Add(new Instruction(Op.Char, node.Value));
                break;
            case NodeKind.Any:
                program.Add(new Instruction(Op.Any));
                break;
            case NodeKind.Class:
                program.Add(new Instruction(Op.Class, node.Value));
                break;
            case NodeKind.Start:
                program.Add(new Instruction(Op.Start));
                break;
            case NodeKind.End:
                program.Add(new Instruction(Op.End));
                break;
            case NodeKind.Group:
                if (node.Value > 0)
                {
                    program.Add(new Instruction(Op.Save, 2 * node.Value));
                }

                Emit(node.Children![0], program);
                if (node.Value > 0)
                {
                    program.Add(new Instruction(Op.Save, (2 * node.Value) + 1));
                }

                break;
            case NodeKind.Concat:
                foreach (Node child in node.Children!)
                {
                    Emit(child, program);
                }

                break;
            case NodeKind.Alternate:
                {
                    List<int> jumps = [];
                    for (int index = 0; index < node.Children!.Count - 1; index++)
                    {
                        int split = program.Count;
                        program.Add(new Instruction(Op.Split, split + 1));
                        Emit(node.Children[index], program);
                        jumps.Add(program.Count);
                        program.Add(new Instruction(Op.Jump));
                        program[split] = program[split] with { Y = program.Count };
                    }

                    Emit(node.Children[^1], program);
                    foreach (int jump in jumps)
                    {
                        program[jump] = program[jump] with { X = program.Count };
                    }

                    break;
                }
            default:
                {
                    Node body = node.Children![0];
                    for (int index = 0; index < node.Minimum; index++)
                    {
                        Emit(body, program);
                    }

                    if (node.Maximum < 0)
                    {
                        int split = program.Count;
                        program.Add(new Instruction(Op.Split));
                        Emit(body, program);
                        program.Add(new Instruction(Op.Jump, split));
                        program[split] = Branch(split + 1, program.Count, node.Greedy);
                    }
                    else
                    {
                        List<int> splits = [];
                        for (int index = node.Minimum; index < node.Maximum; index++)
                        {
                            splits.Add(program.Count);
                            program.Add(new Instruction(Op.Split));
                            Emit(body, program);
                        }

                        foreach (int split in splits)
                        {
                            program[split] = Branch(split + 1, program.Count, node.Greedy);
                        }
                    }

                    break;
                }
        }

        static Instruction Branch(int body, int skip, bool greedy) =>
            greedy ? new Instruction(Op.Split, body, skip) : new Instruction(Op.Split, skip, body);
    }

    /// <summary>True when the pattern matches anywhere in <paramref name="text"/>; stops at the first match.</summary>
    public bool IsMatch(int[] text, TransformBudget budget) => Run(text, true, budget) is not null;

    /// <summary>Capture slots of the leftmost-first match (-1 when unset), or null.</summary>
    public int[]? Search(int[] text, TransformBudget budget) => Run(text, false, budget);

    private int[]? Run(int[] text, bool earliest, TransformBudget budget)
    {
        int slots = 2 * (GroupNames.Count + 1);
        ThreadList current = new(program.Length);
        ThreadList next = new(program.Length);
        Stack<(int Pc, int Slot, int Old)> stack = new();
        int[]? matched = null;
        for (int position = 0; position <= text.Length; position++)
        {
            if (matched is null)
            {
                int[] empty = new int[slots];
                Array.Fill(empty, -1);
                AddThread(current, 0, position, empty, text.Length, stack, budget);
            }

            for (int index = 0; index < current.Count; index++)
            {
                budget.Step();
                (int pc, int[] captures) = current[index];
                Instruction instruction = program[pc];
                if (instruction.Op == Op.Match)
                {
                    matched = captures;
                    if (earliest)
                    {
                        return matched;
                    }

                    break;
                }

                if (position < text.Length && Consumes(instruction, text[position]))
                {
                    AddThread(next, pc + 1, position + 1, captures, text.Length, stack, budget);
                }
            }

            (current, next) = (next, current);
            next.Clear();
            if (current.Count == 0 && matched is not null)
            {
                break;
            }
        }

        return matched;
    }

    private bool Consumes(Instruction instruction, int character)
    {
        switch (instruction.Op)
        {
            case Op.Char:
                return character == instruction.X;
            case Op.Any:
                return character != '\n';
            case Op.Class:
                int[] ranges = classes[instruction.X];
                bool inside = false;
                for (int index = 0; index < ranges.Length; index += 2)
                {
                    if (character >= ranges[index] && character <= ranges[index + 1])
                    {
                        inside = true;
                        break;
                    }
                }

                return inside != negated[instruction.X];
            default:
                return false;
        }
    }

    // Depth-first closure in priority order with an explicit stack. Slot restores are
    // stack frames (Slot >= 0), so the closure never recurses on the call stack.
    private void AddThread(
        ThreadList list,
        int start,
        int position,
        int[] captures,
        int length,
        Stack<(int Pc, int Slot, int Old)> stack,
        TransformBudget budget)
    {
        int[] working = (int[])captures.Clone();
        stack.Push((start, -1, 0));
        while (stack.Count > 0)
        {
            (int pc, int slot, int old) = stack.Pop();
            if (slot >= 0)
            {
                working[slot] = old;
                continue;
            }

            if (!list.Mark(pc))
            {
                continue;
            }

            budget.Step();
            Instruction instruction = program[pc];
            switch (instruction.Op)
            {
                case Op.Jump:
                    stack.Push((instruction.X, -1, 0));
                    break;
                case Op.Split:
                    stack.Push((instruction.Y, -1, 0));
                    stack.Push((instruction.X, -1, 0));
                    break;
                case Op.Save:
                    stack.Push((0, instruction.X, working[instruction.X]));
                    working[instruction.X] = position;
                    stack.Push((pc + 1, -1, 0));
                    break;
                case Op.Start:
                    if (position == 0)
                    {
                        stack.Push((pc + 1, -1, 0));
                    }

                    break;
                case Op.End:
                    if (position == length)
                    {
                        stack.Push((pc + 1, -1, 0));
                    }

                    break;
                default:
                    list.Add(pc, (int[])working.Clone());
                    break;
            }
        }
    }

    private sealed class ThreadList(int size)
    {
        private readonly bool[] marked = new bool[size];
        private readonly List<int> markedList = [];
        private readonly List<(int Pc, int[] Captures)> threads = [];

        public int Count => threads.Count;

        public (int Pc, int[] Captures) this[int index] => threads[index];

        public bool Mark(int pc)
        {
            if (marked[pc])
            {
                return false;
            }

            marked[pc] = true;
            markedList.Add(pc);
            return true;
        }

        public void Add(int pc, int[] captures) => threads.Add((pc, captures));

        public void Clear()
        {
            foreach (int pc in markedList)
            {
                marked[pc] = false;
            }

            markedList.Clear();
            threads.Clear();
        }
    }

    /// <summary>Pattern parser. Throws <see cref="FormatException"/> for anything outside the subset.</summary>
    private sealed class PatternParser(int[] pattern)
    {
        private const string Escapable = "\\.*+?()[]{}|^$-/";

        public int[] Pattern { get; } = pattern;

        public int Position { get; private set; }

        public List<int[]> Classes { get; } = [];

        public List<bool> Negated { get; } = [];

        public List<string> Names { get; } = [];

        private bool AtEnd => Position >= Pattern.Length;

        private int Peek => Pattern[Position];

        public Node ParseAlternation(int depth)
        {
            if (depth > TransformLimits.MaximumExpressionDepth)
            {
                throw new FormatException();
            }

            List<Node> branches = [ParseConcatenation(depth)];
            while (!AtEnd && Peek == '|')
            {
                Position++;
                branches.Add(ParseConcatenation(depth));
            }

            return branches.Count == 1 ? branches[0] : new Node(NodeKind.Alternate, Children: branches);
        }

        private Node ParseConcatenation(int depth)
        {
            List<Node> items = [];
            while (!AtEnd && Peek != '|' && Peek != ')')
            {
                items.Add(ParseRepeat(depth));
            }

            return items.Count switch
            {
                0 => new Node(NodeKind.Empty),
                1 => items[0],
                _ => new Node(NodeKind.Concat, Children: items)
            };
        }

        private Node ParseRepeat(int depth)
        {
            Node atom = ParseAtom(depth);
            if (AtEnd || Peek is not ('*' or '+' or '?' or '{'))
            {
                return atom;
            }

            if (atom.Kind is NodeKind.Start or NodeKind.End)
            {
                throw new FormatException();
            }

            int minimum;
            int maximum;
            int quantifier = Pattern[Position++];
            switch (quantifier)
            {
                case '*':
                    (minimum, maximum) = (0, -1);
                    break;
                case '+':
                    (minimum, maximum) = (1, -1);
                    break;
                case '?':
                    (minimum, maximum) = (0, 1);
                    break;
                default:
                    minimum = Number();
                    maximum = minimum;
                    if (!AtEnd && Peek == ',')
                    {
                        Position++;
                        maximum = !AtEnd && Peek == '}' ? -1 : Number();
                    }

                    if (AtEnd || Peek != '}' || (maximum >= 0 && maximum < minimum))
                    {
                        throw new FormatException();
                    }

                    Position++;
                    break;
            }

            bool greedy = true;
            if (!AtEnd && Peek == '?')
            {
                greedy = false;
                Position++;
            }

            if (!AtEnd && Peek is '*' or '+' or '?' or '{')
            {
                throw new FormatException();
            }

            return new Node(NodeKind.Repeat, Children: [atom], Minimum: minimum, Maximum: maximum, Greedy: greedy);
        }

        private int Number()
        {
            int start = Position;
            int value = 0;
            while (!AtEnd && Peek is >= '0' and <= '9' && Position - start < 3)
            {
                value = (value * 10) + (Peek - '0');
                Position++;
            }

            if (Position == start || value > TransformLimits.MaximumRegexRepeat)
            {
                throw new FormatException();
            }

            return value;
        }

        private Node ParseAtom(int depth)
        {
            int current = Pattern[Position++];
            switch (current)
            {
                case '(':
                    {
                        if (AtEnd || Peek != '?')
                        {
                            throw new FormatException();
                        }

                        Position++;
                        int group = 0;
                        if (!AtEnd && Peek == ':')
                        {
                            Position++;
                        }
                        else if (!AtEnd && Peek == '<')
                        {
                            Position++;
                            string name = GroupName();
                            if (Names.Contains(name, StringComparer.Ordinal) || Names.Count == TransformLimits.MaximumRegexGroups)
                            {
                                throw new FormatException();
                            }

                            Names.Add(name);
                            group = Names.Count;
                        }
                        else
                        {
                            throw new FormatException();
                        }

                        Node body = ParseAlternation(depth + 1);
                        if (AtEnd || Peek != ')')
                        {
                            throw new FormatException();
                        }

                        Position++;
                        return new Node(NodeKind.Group, group, [body]);
                    }
                case '[':
                    return ParseClass();
                case '.':
                    return new Node(NodeKind.Any);
                case '^':
                    return new Node(NodeKind.Start);
                case '$':
                    return new Node(NodeKind.End);
                case '\\':
                    {
                        if (AtEnd)
                        {
                            throw new FormatException();
                        }

                        int escaped = Pattern[Position++];
                        if (Shorthand(escaped) is { } ranges)
                        {
                            return AddClass(ranges, char.IsAsciiLetterUpper((char)escaped));
                        }

                        return new Node(NodeKind.Char, EscapedCharacter(escaped));
                    }
                case ')' or ']' or '{' or '}' or '*' or '+' or '?' or '|':
                    throw new FormatException();
                default:
                    return new Node(NodeKind.Char, current);
            }
        }

        private string GroupName()
        {
            int start = Position;
            while (!AtEnd && Peek != '>')
            {
                int character = Peek;
                bool valid = character is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or '_'
                    || (Position > start && character is >= '0' and <= '9');
                if (!valid || Position - start >= 32)
                {
                    throw new FormatException();
                }

                Position++;
            }

            if (AtEnd || Position == start)
            {
                throw new FormatException();
            }

            string name = string.Concat(Pattern[start..Position].Select(character => (char)character));
            Position++;
            return name;
        }

        private Node ParseClass()
        {
            bool negate = false;
            if (!AtEnd && Peek == '^')
            {
                negate = true;
                Position++;
            }

            List<int> ranges = [];
            bool first = true;
            while (true)
            {
                if (AtEnd)
                {
                    throw new FormatException();
                }

                int current = Pattern[Position++];
                if (current == ']' && !first)
                {
                    break;
                }

                first = false;
                if (current is ']' or '[')
                {
                    throw new FormatException();
                }

                int low;
                if (current == '\\')
                {
                    if (AtEnd)
                    {
                        throw new FormatException();
                    }

                    int escaped = Pattern[Position++];
                    if (Shorthand(escaped) is { } shorthand && char.IsAsciiLetterLower((char)escaped))
                    {
                        ranges.AddRange(shorthand);
                        if (!AtEnd && Peek == '-' && Position + 1 < Pattern.Length && Pattern[Position + 1] != ']')
                        {
                            throw new FormatException();
                        }

                        continue;
                    }

                    low = EscapedCharacter(escaped);
                }
                else
                {
                    low = current;
                }

                int high = low;
                if (!AtEnd && Peek == '-' && Position + 1 < Pattern.Length && Pattern[Position + 1] != ']')
                {
                    Position++;
                    int upper = Pattern[Position++];
                    if (upper == '\\')
                    {
                        if (AtEnd)
                        {
                            throw new FormatException();
                        }

                        upper = EscapedCharacter(Pattern[Position++]);
                    }
                    else if (upper == '[')
                    {
                        throw new FormatException();
                    }

                    if (upper < low)
                    {
                        throw new FormatException();
                    }

                    high = upper;
                }

                ranges.Add(low);
                ranges.Add(high);
            }

            return AddClass([.. ranges], negate);
        }

        private Node AddClass(int[] ranges, bool negate)
        {
            Classes.Add(ranges);
            Negated.Add(negate);
            return new Node(NodeKind.Class, Classes.Count - 1);
        }

        private static int[]? Shorthand(int escaped) => escaped switch
        {
            'd' or 'D' => ['0', '9'],
            'w' or 'W' => ['0', '9', 'A', 'Z', '_', '_', 'a', 'z'],
            's' or 'S' => ['\t', '\r', ' ', ' '],
            _ => null
        };

        private static int EscapedCharacter(int escaped) => escaped switch
        {
            't' => '\t',
            'n' => '\n',
            'r' => '\r',
            _ when escaped < 128 && Escapable.Contains((char)escaped, StringComparison.Ordinal) => escaped,
            _ => throw new FormatException()
        };
    }
}

/// <summary>Per-record step counter shared by statements, expressions and regex execution.</summary>
internal sealed class TransformBudget
{
    public long Steps { get; private set; }

    public void Step()
    {
        if (++Steps > TransformLimits.StepBudget)
        {
            throw new TransformException(TransformErrorCodes.BudgetExceeded);
        }
    }
}
