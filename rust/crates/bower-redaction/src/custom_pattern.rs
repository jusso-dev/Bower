//! Restricted pattern syntax for custom detectors (`CustomPatternTranslator`).
//!
//! Validates a custom detector pattern and emits the canonical pattern that is
//! actually compiled. The canonical form is identical to the C# translator's output:
//! ASCII-only shorthand classes, `.` as `[^\n]`, anchors as `\A`/`\z`, non-capturing
//! groups, explicit escapes, case-insensitivity expanded into classes, and character
//! ranges never covering UTF-16 surrogates. No engine flag changes its meaning, so
//! .NET (UTF-16 units) and Rust (scalars over a surrogate-preserving haystack, see
//! [`crate::detectors::custom`]) find the same spans.
//!
//! Positions are zero-based character indexes. They equal the C# UTF-16 indexes
//! because characters outside the Basic Multilingual Plane are rejected at the first
//! occurrence.

/// Maximum expansion estimate.
pub const MAXIMUM_COMPLEXITY: u32 = 512;
/// Maximum `{n,m}` bound.
pub const MAXIMUM_REPEAT: u32 = 1000;

const SATURATED: u32 = MAXIMUM_COMPLEXITY + 1;
const DIGIT: &str = "0-9";
const WORD: &str = "0-9A-Z_a-z";
const SPACE: &str = "\\t\\n\\x0B\\f\\r ";

/// Fixed rejection reasons, identical to C# `CustomPatternReasons`.
pub mod reasons {
    pub const LOOKAROUND: &str = "lookaround is not supported";
    pub const BACK_REFERENCE: &str = "back-references are not supported";
    pub const UNICODE_PROPERTY: &str = "unicode properties are not supported";
    pub const INLINE_FLAGS: &str = "inline flags are not supported";
    pub const NAMED_GROUP: &str = "named groups are not supported";
    pub const UNSUPPORTED_GROUP: &str = "unsupported group construct";
    pub const UNBALANCED_PARENTHESIS: &str = "unbalanced parenthesis";
    pub const UNTERMINATED_CLASS: &str = "unterminated character class";
    pub const EMPTY_CLASS: &str = "empty character class";
    pub const NESTED_CLASS: &str = "nested character classes are not supported";
    pub const POSIX_CLASS: &str = "POSIX character classes are not supported";
    pub const SET_OPERATION: &str = "character class set operations are not supported";
    pub const INVALID_RANGE: &str = "invalid character class range";
    pub const NEGATED_SHORTHAND_IN_CLASS: &str =
        "negated shorthand classes are not supported inside character classes";
    pub const INVALID_QUANTIFIER: &str = "invalid quantifier";
    pub const QUANTIFIER_BOUND: &str = "quantifier bound above 1000";
    pub const NOTHING_TO_REPEAT: &str = "nothing to repeat";
    pub const REPEATED_QUANTIFIER: &str = "quantifier follows another quantifier";
    pub const WORD_BOUNDARY: &str = "word boundaries are not supported; use wholeWord";
    pub const ANCHOR_ESCAPE: &str = "anchor escapes are not supported; use ^ and $";
    pub const UNSUPPORTED_ESCAPE: &str = "unsupported escape";
    pub const TRAILING_BACKSLASH: &str = "trailing backslash";
    pub const SUPPLEMENTARY_CHARACTER: &str =
        "characters outside the Basic Multilingual Plane are not supported";
    pub const RESERVED_CHARACTER: &str = "character U+FFFF is not supported";

    /// Every reason, in the C# order.
    pub const ALL: &[&str] = &[
        LOOKAROUND,
        BACK_REFERENCE,
        UNICODE_PROPERTY,
        INLINE_FLAGS,
        NAMED_GROUP,
        UNSUPPORTED_GROUP,
        UNBALANCED_PARENTHESIS,
        UNTERMINATED_CLASS,
        EMPTY_CLASS,
        NESTED_CLASS,
        POSIX_CLASS,
        SET_OPERATION,
        INVALID_RANGE,
        NEGATED_SHORTHAND_IN_CLASS,
        INVALID_QUANTIFIER,
        QUANTIFIER_BOUND,
        NOTHING_TO_REPEAT,
        REPEATED_QUANTIFIER,
        WORD_BOUNDARY,
        ANCHOR_ESCAPE,
        UNSUPPORTED_ESCAPE,
        TRAILING_BACKSLASH,
        SUPPLEMENTARY_CHARACTER,
        RESERVED_CHARACTER,
    ];
}

/// A pattern translated to its canonical, compiled form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Translation {
    pub canonical_pattern: String,
    /// Expansion estimate, saturated just above [`MAXIMUM_COMPLEXITY`].
    pub complexity: u32,
    /// True when the pattern can produce a zero-length match.
    pub matches_empty: bool,
}

/// Unsupported syntax at a zero-based position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    pub position: usize,
    pub reason: &'static str,
}

type Parsed<T> = Result<T, SyntaxError>;

fn error<T>(position: usize, reason: &'static str) -> Parsed<T> {
    Err(SyntaxError { position, reason })
}

/// Validates `pattern` and returns its canonical translation.
pub fn translate(pattern: &str, ignore_case: bool) -> Result<Translation, SyntaxError> {
    let mut parser = Parser {
        pattern: pattern.chars().collect(),
        position: 0,
        ignore_case,
    };
    let piece = parser.parse_alternation()?;
    if parser.has(0) {
        // Only an unmatched ')' stops the top-level alternation early.
        return error(parser.position, reasons::UNBALANCED_PARENTHESIS);
    }

    Ok(Translation {
        canonical_pattern: piece.text,
        complexity: piece.complexity,
        matches_empty: piece.nullable,
    })
}

struct Piece {
    text: String,
    complexity: u32,
    nullable: bool,
    quantifiable: bool,
}

impl Piece {
    fn class(text: String) -> Self {
        Self {
            text,
            complexity: 1,
            nullable: false,
            quantifiable: true,
        }
    }
}

fn add(left: u32, right: u32) -> u32 {
    (left + right).min(SATURATED)
}

fn multiply(left: u32, right: u32) -> u32 {
    (u64::from(left) * u64::from(right)).min(u64::from(SATURATED)) as u32
}

fn swap_case(value: char) -> char {
    char::from(value as u8 ^ 0x20)
}

fn is_ascii_punctuation_or_space(value: char) -> bool {
    (' '..='~').contains(&value) && !value.is_ascii_alphanumeric()
}

/// Shared escape rules (outside and inside classes) for non-shorthand escapes.
fn escaped_literal(escaped: char, start: usize) -> Parsed<char> {
    if matches!(escaped, '<' | '>') {
        return error(start, reasons::WORD_BOUNDARY);
    }

    if is_ascii_punctuation_or_space(escaped) {
        return Ok(escaped);
    }

    error(
        start,
        match escaped {
            '1'..='9' | 'k' => reasons::BACK_REFERENCE,
            'p' | 'P' => reasons::UNICODE_PROPERTY,
            'b' | 'B' => reasons::WORD_BOUNDARY,
            'A' | 'z' | 'Z' | 'G' => reasons::ANCHOR_ESCAPE,
            _ => reasons::UNSUPPORTED_ESCAPE,
        },
    )
}

/// Rejects characters that cannot have identical semantics in both engines.
fn check_literal(value: char, start: usize) -> Parsed<char> {
    if u32::from(value) > 0xFFFF {
        return error(start, reasons::SUPPLEMENTARY_CHARACTER);
    }

    if value == '\u{FFFF}' {
        return error(start, reasons::RESERVED_CHARACTER);
    }

    Ok(value)
}

fn push_class_character(text: &mut String, value: char) {
    match value {
        '\t' => text.push_str("\\t"),
        '\n' => text.push_str("\\n"),
        '\r' => text.push_str("\\r"),
        '\\' | ']' | '[' | '^' | '-' | '&' | '~' => {
            text.push('\\');
            text.push(value);
        }
        other => text.push(other),
    }
}

fn push_plain_range(text: &mut String, low: char, high: char) {
    push_class_character(text, low);
    if high != low {
        text.push('-');
        push_class_character(text, high);
    }
}

fn push_swapped(text: &mut String, low: char, high: char, first: char, last: char) {
    let from = low.max(first);
    let to = high.min(last);
    if from <= to {
        push_plain_range(text, swap_case(from), swap_case(to));
    }
}

enum ClassAtom {
    Character(char),
    Shorthand(&'static str),
}

struct Parser {
    pattern: Vec<char>,
    position: usize,
    ignore_case: bool,
}

impl Parser {
    fn has(&self, offset: usize) -> bool {
        self.position + offset < self.pattern.len()
    }

    fn peek(&self, offset: usize) -> char {
        self.pattern
            .get(self.position + offset)
            .copied()
            .unwrap_or('\0')
    }

    fn parse_alternation(&mut self) -> Parsed<Piece> {
        let first = self.parse_concatenation()?;
        if !self.has(0) || self.peek(0) != '|' {
            return Ok(first);
        }

        let mut text = first.text;
        let mut complexity = first.complexity;
        let mut nullable = first.nullable;
        while self.has(0) && self.peek(0) == '|' {
            self.position += 1;
            let branch = self.parse_concatenation()?;
            text.push('|');
            text.push_str(&branch.text);
            complexity = add(complexity, branch.complexity);
            nullable |= branch.nullable;
        }

        Ok(Piece {
            text,
            complexity,
            nullable,
            quantifiable: false,
        })
    }

    fn parse_concatenation(&mut self) -> Parsed<Piece> {
        let mut text = String::new();
        let mut complexity = 0;
        let mut nullable = true;
        while self.has(0) && !matches!(self.peek(0), '|' | ')') {
            let atom = self.parse_atom()?;
            let atom = self.parse_quantifiers(atom)?;
            text.push_str(&atom.text);
            complexity = add(complexity, atom.complexity);
            nullable &= atom.nullable;
        }

        Ok(Piece {
            text,
            complexity,
            nullable,
            quantifiable: false,
        })
    }

    fn starts_quantifier(&self) -> bool {
        matches!(self.peek(0), '*' | '+' | '?' | '{')
    }

    fn parse_quantifiers(&mut self, atom: Piece) -> Parsed<Piece> {
        if !self.has(0) || !self.starts_quantifier() {
            return Ok(atom);
        }

        let start = self.position;
        if !atom.quantifiable {
            self.read_quantifier()?;
            return error(start, reasons::NOTHING_TO_REPEAT);
        }

        let (mut suffix, minimum, multiplier) = self.read_quantifier()?;
        if self.has(0) && self.peek(0) == '?' {
            self.position += 1;
            suffix.push('?');
        }

        if self.has(0) && self.starts_quantifier() {
            return error(self.position, reasons::REPEATED_QUANTIFIER);
        }

        Ok(Piece {
            text: atom.text + &suffix,
            complexity: multiply(atom.complexity, multiplier),
            nullable: minimum == 0 || atom.nullable,
            quantifiable: false,
        })
    }

    /// Reads `* + ?` or a valid `{n}`, `{n,}`, `{n,m}`: (suffix, minimum, multiplier).
    fn read_quantifier(&mut self) -> Parsed<(String, u32, u32)> {
        let first = self.peek(0);
        if first != '{' {
            self.position += 1;
            return Ok((first.to_string(), u32::from(first == '+'), 1));
        }

        let open = self.position;
        let mut index = self.position + 1;
        let Some(minimum) = self.read_number(&mut index, open)? else {
            return error(open, reasons::INVALID_QUANTIFIER);
        };

        // `None` means open-ended (`{n,}`).
        let mut maximum = Some(minimum);
        if self.pattern.get(index) == Some(&',') {
            index += 1;
            if self.pattern.get(index) == Some(&'}') {
                maximum = None;
            } else {
                let Some(bound) = self.read_number(&mut index, open)? else {
                    return error(open, reasons::INVALID_QUANTIFIER);
                };
                maximum = Some(bound);
            }
        }

        if self.pattern.get(index) != Some(&'}') || maximum.is_some_and(|bound| bound < minimum) {
            return error(open, reasons::INVALID_QUANTIFIER);
        }

        self.position = index + 1;
        let suffix = match maximum {
            None => format!("{{{minimum},}}"),
            Some(bound) if bound == minimum => format!("{{{minimum}}}"),
            Some(bound) => format!("{{{minimum},{bound}}}"),
        };
        Ok((suffix, minimum, minimum.max(maximum.unwrap_or(0)).max(1)))
    }

    /// Decimal digits; `None` when there are none. Values above 1000 are rejected.
    fn read_number(&self, index: &mut usize, open: usize) -> Parsed<Option<u32>> {
        let start = *index;
        let mut value: u32 = 0;
        while let Some(digit) = self.pattern.get(*index).and_then(|c| c.to_digit(10)) {
            value = (value * 10 + digit).min(MAXIMUM_REPEAT + 1);
            *index += 1;
        }

        if *index == start {
            return Ok(None);
        }

        // Only report the bound once a closing brace or comma follows the digits.
        if value > MAXIMUM_REPEAT && matches!(self.pattern.get(*index), Some('}' | ',')) {
            return error(open, reasons::QUANTIFIER_BOUND);
        }

        Ok(Some(value))
    }

    fn parse_atom(&mut self) -> Parsed<Piece> {
        let start = self.position;
        let current = self.peek(0);
        match current {
            '(' => self.parse_group(),
            '[' => self.parse_class(),
            '.' => {
                self.position += 1;
                Ok(Piece::class("[^\\n]".to_owned()))
            }
            '^' | '$' => {
                self.position += 1;
                Ok(Piece {
                    text: if current == '^' { "\\A" } else { "\\z" }.to_owned(),
                    complexity: 1,
                    nullable: true,
                    quantifiable: false,
                })
            }
            '\\' => self.parse_escape(),
            '*' | '+' | '?' => error(start, reasons::NOTHING_TO_REPEAT),
            '{' => {
                // A well-formed quantifier with nothing before it; otherwise malformed.
                self.read_quantifier()?;
                error(start, reasons::NOTHING_TO_REPEAT)
            }
            _ => {
                self.position += 1;
                Ok(self.literal(check_literal(current, start)?))
            }
        }
    }

    fn parse_group(&mut self) -> Parsed<Piece> {
        let open = self.position;
        self.position += 1;
        if self.has(0) && self.peek(0) == '?' {
            let kind = self.peek(1);
            if kind == ':' {
                self.position += 2;
            } else {
                return error(
                    open,
                    match kind {
                        '=' | '!' => reasons::LOOKAROUND,
                        '<' if matches!(self.peek(2), '=' | '!') => reasons::LOOKAROUND,
                        '<' | '\'' | 'P' => reasons::NAMED_GROUP,
                        '-' => reasons::INLINE_FLAGS,
                        _ if kind.is_ascii_alphabetic() => reasons::INLINE_FLAGS,
                        _ => reasons::UNSUPPORTED_GROUP,
                    },
                );
            }
        }

        let inner = self.parse_alternation()?;
        if !self.has(0) || self.peek(0) != ')' {
            return error(open, reasons::UNBALANCED_PARENTHESIS);
        }

        self.position += 1;
        Ok(Piece {
            text: format!("(?:{})", inner.text),
            complexity: inner.complexity,
            nullable: inner.nullable,
            quantifiable: true,
        })
    }

    fn parse_escape(&mut self) -> Parsed<Piece> {
        let start = self.position;
        if !self.has(1) {
            return error(start, reasons::TRAILING_BACKSLASH);
        }

        let escaped = self.peek(1);
        self.position += 2;
        Ok(match escaped {
            'd' => Piece::class(format!("[{DIGIT}]")),
            'D' => Piece::class(format!("[^{DIGIT}]")),
            'w' => Piece::class(format!("[{WORD}]")),
            'W' => Piece::class(format!("[^{WORD}]")),
            's' => Piece::class(format!("[{SPACE}]")),
            'S' => Piece::class(format!("[^{SPACE}]")),
            't' => self.literal('\t'),
            'n' => self.literal('\n'),
            'r' => self.literal('\r'),
            other => self.literal(escaped_literal(other, start)?),
        })
    }

    fn literal(&self, value: char) -> Piece {
        if self.ignore_case && value.is_ascii_alphabetic() {
            return Piece::class(format!("[{value}{}]", swap_case(value)));
        }

        let text = match value {
            '\t' => "\\t".to_owned(),
            '\n' => "\\n".to_owned(),
            '\r' => "\\r".to_owned(),
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' => {
                format!("\\{value}")
            }
            other => other.to_string(),
        };
        Piece {
            text,
            complexity: 1,
            nullable: false,
            quantifiable: true,
        }
    }

    fn parse_class(&mut self) -> Parsed<Piece> {
        let open = self.position;
        self.position += 1;
        let mut text = String::from("[");
        if self.has(0) && self.peek(0) == '^' {
            text.push('^');
            self.position += 1;
        }

        if !self.has(0) {
            return error(open, reasons::UNTERMINATED_CLASS);
        }

        if self.peek(0) == ']' {
            return error(open, reasons::EMPTY_CLASS);
        }

        loop {
            if !self.has(0) {
                return error(open, reasons::UNTERMINATED_CLASS);
            }

            let current = self.peek(0);
            if current == ']' {
                self.position += 1;
                break;
            }

            if (matches!(current, '&' | '~' | '-') && self.peek(1) == current && self.has(1))
                || (current == '-' && self.peek(1) == '[' && self.has(1))
            {
                return error(self.position, reasons::SET_OPERATION);
            }

            if current == '[' {
                return error(
                    self.position,
                    if self.peek(1) == ':' && self.has(1) {
                        reasons::POSIX_CLASS
                    } else {
                        reasons::NESTED_CLASS
                    },
                );
            }

            let item_start = self.position;
            let low = self.parse_class_atom()?;
            if self.has(0) && self.peek(0) == '-' && self.has(1) && self.peek(1) != ']' {
                let dash = self.position;
                if matches!(self.peek(1), '-' | '[') {
                    return error(dash, reasons::SET_OPERATION);
                }

                self.position += 1;
                let high = self.parse_class_atom()?;
                match (low, high) {
                    (ClassAtom::Character(low), ClassAtom::Character(high)) if high >= low => {
                        self.push_range(&mut text, low, high);
                    }
                    _ => return error(item_start, reasons::INVALID_RANGE),
                }
                continue;
            }

            match low {
                ClassAtom::Shorthand(expansion) => text.push_str(expansion),
                ClassAtom::Character(low) => self.push_range(&mut text, low, low),
            }
        }

        text.push(']');
        Ok(Piece::class(text))
    }

    /// A single class character or a shorthand expansion (`\d \w \s`).
    fn parse_class_atom(&mut self) -> Parsed<ClassAtom> {
        let start = self.position;
        let current = self.peek(0);
        if current != '\\' {
            self.position += 1;
            return Ok(ClassAtom::Character(check_literal(current, start)?));
        }

        if !self.has(1) {
            return error(start, reasons::TRAILING_BACKSLASH);
        }

        let escaped = self.peek(1);
        self.position += 2;
        Ok(match escaped {
            'd' => ClassAtom::Shorthand(DIGIT),
            'w' => ClassAtom::Shorthand(WORD),
            's' => ClassAtom::Shorthand(SPACE),
            'D' | 'W' | 'S' => return error(start, reasons::NEGATED_SHORTHAND_IN_CLASS),
            't' => ClassAtom::Character('\t'),
            'n' => ClassAtom::Character('\n'),
            'r' => ClassAtom::Character('\r'),
            other => ClassAtom::Character(escaped_literal(other, start)?),
        })
    }

    /// Pushes a range (or single character) without covering UTF-16 surrogates, plus
    /// its swapped-case ASCII letters when ignoring case.
    fn push_range(&self, text: &mut String, low: char, high: char) {
        if u32::from(low) < 0xD800 && u32::from(high) > 0xDFFF {
            push_plain_range(text, low, '\u{D7FF}');
            push_plain_range(text, '\u{E000}', high);
        } else {
            push_plain_range(text, low, high);
        }

        if self.ignore_case {
            push_swapped(text, low, high, 'A', 'Z');
            push_swapped(text, low, high, 'a', 'z');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(pattern: &str, ignore_case: bool) -> String {
        translate(pattern, ignore_case)
            .unwrap_or_else(|error| panic!("{pattern}: {error:?}"))
            .canonical_pattern
    }

    fn rejected(pattern: &str) -> (usize, &'static str) {
        let error = translate(pattern, false).expect_err(pattern);
        (error.position, error.reason)
    }

    #[test]
    fn translates_shorthands_anchors_and_groups() {
        assert_eq!(canonical(r"EMP-\d{6}", false), "EMP-[0-9]{6}");
        assert_eq!(canonical(r"^\w+$", false), r"\A[0-9A-Z_a-z]+\z");
        assert_eq!(
            canonical(r"\s\S", false),
            r"[\t\n\x0B\f\r ][^\t\n\x0B\f\r ]"
        );
        assert_eq!(canonical(r"(a|b)(?:c)", false), "(?:a|b)(?:c)");
        assert_eq!(canonical(r"a.b", false), r"a[^\n]b");
        assert_eq!(canonical(r"x}]\.\#\ \-", false), r"x\}\]\.# -");
        assert_eq!(canonical(r"[\w.-]+", false), r"[0-9A-Z_a-z.\-]+");
    }

    #[test]
    fn expands_ignore_case_into_classes() {
        assert_eq!(canonical("ab1", true), "[aA][bB]1");
        assert_eq!(canonical("[a-fX]", true), "[a-fA-FXx]");
        assert_eq!(canonical("[Z-b]", true), "[Z-bzA-B]");
        assert_eq!(canonical("é", true), "é");
    }

    #[test]
    fn rejects_unsupported_syntax_with_positions() {
        assert_eq!(rejected("a(?=b)"), (1, reasons::LOOKAROUND));
        assert_eq!(rejected(r"(a)\1"), (3, reasons::BACK_REFERENCE));
        assert_eq!(rejected(r"\p{L}"), (0, reasons::UNICODE_PROPERTY));
        assert_eq!(rejected("(?i)a"), (0, reasons::INLINE_FLAGS));
        assert_eq!(rejected("a{2,1}"), (1, reasons::INVALID_QUANTIFIER));
        assert_eq!(rejected("a{1001}"), (1, reasons::QUANTIFIER_BOUND));
        assert_eq!(rejected("a**"), (2, reasons::REPEATED_QUANTIFIER));
        assert_eq!(rejected("\u{1F600}"), (0, reasons::SUPPLEMENTARY_CHARACTER));
    }
}
