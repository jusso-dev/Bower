//! A block-style YAML writer reproducing YamlDotNet's emitter (a libyaml port) for
//! string scalars: plain when safe, otherwise single-quoted, double-quoted or folded,
//! with YamlDotNet's serializer default of no line folding (`BestWidth = int.MaxValue`).

const BEST_WIDTH: usize = i32::MAX as usize;
const BEST_INDENT: usize = 2;

fn is_break(character: char) -> bool {
    matches!(character, '\r' | '\n' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

fn is_blank(character: char) -> bool {
    matches!(character, ' ' | '\t')
}

fn is_blankz(character: Option<char>) -> bool {
    match character {
        None => true,
        Some(character) => is_blank(character) || is_break(character) || character == '\0',
    }
}

/// YamlDotNet `IsPrintable` (UTF-16 code units; characters outside the BMP are
/// surrogate pairs and therefore not printable).
fn is_printable(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\r' | '\u{20}'..='\u{7E}' | '\u{85}' | '\u{A0}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}')
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Style {
    Plain,
    SingleQuoted,
    DoubleQuoted,
    Folded,
}

struct Analysis {
    multiline: bool,
    block_plain_allowed: bool,
    single_quoted_allowed: bool,
    block_allowed: bool,
}

fn analyze(value: &str) -> Analysis {
    if value.is_empty() {
        return Analysis {
            multiline: false,
            block_plain_allowed: false,
            single_quoted_allowed: true,
            block_allowed: false,
        };
    }
    let chars: Vec<char> = value.chars().collect();
    let mut flow_indicators = false;
    let mut block_indicators = false;
    if value.starts_with("---") || value.starts_with("...") {
        flow_indicators = true;
        block_indicators = true;
    }
    let (mut line_breaks, mut special_characters) = (false, false);
    let (mut leading_space, mut leading_break, mut trailing_space, mut trailing_break) =
        (false, false, false, false);
    let (mut break_space, mut space_break) = (false, false);
    let (mut previous_space, mut previous_break) = (false, false);
    let mut preceded_by_whitespace = true;

    for (index, &character) in chars.iter().enumerate() {
        let first = index == 0;
        let last = index + 1 == chars.len();
        let followed_by_whitespace = is_blankz(chars.get(index + 1).copied());
        if first {
            if matches!(
                character,
                '#' | ','
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '&'
                    | '*'
                    | '!'
                    | '|'
                    | '>'
                    | '\''
                    | '"'
                    | '%'
                    | '@'
                    | '`'
            ) {
                flow_indicators = true;
                block_indicators = true;
            }
            if matches!(character, '?' | ':') {
                flow_indicators = true;
                if followed_by_whitespace {
                    block_indicators = true;
                }
            }
            if character == '-' && followed_by_whitespace {
                flow_indicators = true;
                block_indicators = true;
            }
        } else {
            if matches!(character, ',' | '?' | '[' | ']' | '{' | '}') {
                flow_indicators = true;
            }
            if character == ':' {
                flow_indicators = true;
                if followed_by_whitespace {
                    block_indicators = true;
                }
            }
            if character == '#' && preceded_by_whitespace {
                flow_indicators = true;
                block_indicators = true;
            }
        }

        if !is_printable(character) {
            special_characters = true;
        }
        if is_break(character) {
            line_breaks = true;
        }

        if character == ' ' {
            if first {
                leading_space = true;
            }
            if last {
                trailing_space = true;
            }
            if previous_break {
                break_space = true;
            }
            previous_space = true;
            previous_break = false;
        } else if is_break(character) {
            if first {
                leading_break = true;
            }
            if last {
                trailing_break = true;
            }
            if previous_space {
                space_break = true;
            }
            previous_break = true;
            previous_space = false;
        } else {
            previous_space = false;
            previous_break = false;
        }
        preceded_by_whitespace = is_blankz(Some(character));
    }

    let mut analysis = Analysis {
        multiline: line_breaks,
        block_plain_allowed: true,
        single_quoted_allowed: true,
        block_allowed: true,
    };
    if leading_space || leading_break || trailing_space || trailing_break {
        analysis.block_plain_allowed = false;
    }
    if trailing_space {
        analysis.block_allowed = false;
    }
    if break_space {
        analysis.block_plain_allowed = false;
        analysis.single_quoted_allowed = false;
    }
    if space_break || special_characters {
        analysis.block_plain_allowed = false;
        analysis.single_quoted_allowed = false;
        analysis.block_allowed = false;
    }
    if line_breaks {
        analysis.block_plain_allowed = false;
    }
    if flow_indicators {
        // Flow plain only; block context is unaffected.
    }
    if block_indicators {
        analysis.block_plain_allowed = false;
    }
    analysis
}

fn select_style(value: &str, simple_key: bool) -> Style {
    let analysis = analyze(value);
    let mut style = if analysis.multiline {
        Style::Folded
    } else {
        Style::Plain
    };
    if simple_key && analysis.multiline {
        style = Style::DoubleQuoted;
    }
    if style == Style::Plain {
        if !analysis.block_plain_allowed {
            style = Style::SingleQuoted;
        }
        if value.is_empty() && simple_key {
            style = Style::SingleQuoted;
        }
    }
    if style == Style::SingleQuoted && !analysis.single_quoted_allowed {
        style = Style::DoubleQuoted;
    }
    if style == Style::Folded && (!analysis.block_allowed || simple_key) {
        style = Style::DoubleQuoted;
    }
    style
}

/// Output buffer tracking the libyaml emitter column/whitespace/indention state.
pub(crate) struct Writer {
    output: String,
    column: usize,
    whitespace: bool,
    indention: bool,
    indent: usize,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Self {
            output: String::new(),
            column: 0,
            whitespace: true,
            indention: true,
            indent: 0,
        }
    }

    pub(crate) fn finish(self) -> String {
        self.output
    }

    fn put(&mut self, character: char) {
        self.output.push(character);
        // YamlDotNet counts UTF-16 code units.
        self.column += character.len_utf16();
    }

    fn put_str(&mut self, text: &str) {
        for character in text.chars() {
            self.put(character);
        }
    }

    fn put_break(&mut self) {
        self.output.push('\n');
        self.column = 0;
    }

    fn write_indent(&mut self) {
        if !self.indention
            || self.column > self.indent
            || (self.column == self.indent && !self.whitespace)
        {
            self.put_break();
        }
        while self.column < self.indent {
            self.put(' ');
        }
        self.whitespace = true;
        self.indention = true;
    }

    fn write_indicator(
        &mut self,
        indicator: &str,
        need_whitespace: bool,
        is_whitespace: bool,
        is_indention: bool,
    ) {
        if need_whitespace && !self.whitespace {
            self.put(' ');
        }
        self.put_str(indicator);
        self.whitespace = is_whitespace;
        self.indention = self.indention && is_indention;
    }

    fn write_break(&mut self) {
        self.put_break();
    }

    /// Starts a block mapping entry key at `indent`.
    pub(crate) fn mapping_key(&mut self, indent: usize, key: &str) {
        self.indent = indent;
        self.write_indent();
        self.scalar(key, true);
        self.write_indicator(":", false, false, false);
    }

    /// Starts a block sequence entry (`- `) at `indent`.
    pub(crate) fn sequence_entry(&mut self, indent: usize) {
        self.indent = indent;
        self.write_indent();
        self.write_indicator("-", true, false, true);
    }

    /// Writes an inline flow token (`[]`, `{}`).
    pub(crate) fn flow_token(&mut self, token: &str) {
        self.write_indicator(token, true, false, false);
    }

    /// Writes a string scalar value whose parent node is at `parent_indent`.
    pub(crate) fn value(&mut self, parent_indent: usize, value: &str) {
        self.indent = parent_indent + BEST_INDENT;
        self.scalar(value, false);
    }

    /// Ends the document (`\n` after the last node).
    pub(crate) fn end(&mut self) {
        if !self.output.is_empty() && !self.output.ends_with('\n') {
            self.put_break();
        }
    }

    fn scalar(&mut self, value: &str, simple_key: bool) {
        let allow_breaks = !simple_key;
        match select_style(value, simple_key) {
            Style::Plain => self.write_plain(value, allow_breaks),
            Style::SingleQuoted => self.write_single_quoted(value, allow_breaks),
            Style::DoubleQuoted => self.write_double_quoted(value, allow_breaks),
            Style::Folded => self.write_folded(value),
        }
    }

    fn write_plain(&mut self, value: &str, allow_breaks: bool) {
        let chars: Vec<char> = value.chars().collect();
        if !self.whitespace && !chars.is_empty() {
            self.put(' ');
        }
        let mut spaces = false;
        let mut breaks = false;
        for (index, &character) in chars.iter().enumerate() {
            if character == ' ' {
                if allow_breaks
                    && !spaces
                    && self.column > BEST_WIDTH
                    && chars.get(index + 1) != Some(&' ')
                {
                    self.write_indent();
                } else {
                    self.put(character);
                }
                spaces = true;
            } else if is_break(character) {
                if !breaks && character == '\n' {
                    self.put_break();
                }
                self.write_break();
                self.indention = true;
                breaks = true;
            } else {
                if breaks {
                    self.write_indent();
                }
                self.put(character);
                self.indention = false;
                spaces = false;
                breaks = false;
            }
        }
        self.whitespace = false;
        self.indention = false;
    }

    fn write_single_quoted(&mut self, value: &str, allow_breaks: bool) {
        self.write_indicator("'", true, false, false);
        let chars: Vec<char> = value.chars().collect();
        let mut spaces = false;
        let mut breaks = false;
        for (index, &character) in chars.iter().enumerate() {
            if character == ' ' {
                if allow_breaks
                    && !spaces
                    && self.column > BEST_WIDTH
                    && index != 0
                    && index + 1 != chars.len()
                    && chars.get(index + 1) != Some(&' ')
                {
                    self.write_indent();
                } else {
                    self.put(character);
                }
                spaces = true;
            } else if is_break(character) {
                if !breaks && character == '\n' {
                    self.put_break();
                }
                self.write_break();
                self.indention = true;
                breaks = true;
            } else {
                if breaks {
                    self.write_indent();
                }
                if character == '\'' {
                    self.put('\'');
                }
                self.put(character);
                self.indention = false;
                spaces = false;
                breaks = false;
            }
        }
        if breaks {
            self.write_indent();
        }
        self.write_indicator("'", false, false, false);
    }

    fn write_double_quoted(&mut self, value: &str, allow_breaks: bool) {
        self.write_indicator("\"", true, false, false);
        let chars: Vec<char> = value.chars().collect();
        let mut spaces = false;
        for (index, &character) in chars.iter().enumerate() {
            if !is_printable(character)
                || character == '\u{FEFF}'
                || is_break(character)
                || character == '"'
                || character == '\\'
            {
                self.put('\\');
                match character {
                    '\0' => self.put('0'),
                    '\u{7}' => self.put('a'),
                    '\u{8}' => self.put('b'),
                    '\t' => self.put('t'),
                    '\n' => self.put('n'),
                    '\u{B}' => self.put('v'),
                    '\u{C}' => self.put('f'),
                    '\r' => self.put('r'),
                    '\u{1B}' => self.put('e'),
                    '"' => self.put('"'),
                    '\\' => self.put('\\'),
                    '\u{85}' => self.put('N'),
                    '\u{A0}' => self.put('_'),
                    '\u{2028}' => self.put('L'),
                    '\u{2029}' => self.put('P'),
                    other => {
                        let code = u32::from(other);
                        if code <= 0xFF {
                            self.put_str(&format!("x{code:02X}"));
                        } else if code <= 0xFFFF {
                            self.put_str(&format!("u{code:04X}"));
                        } else {
                            self.put_str(&format!("U{code:08X}"));
                        }
                    }
                }
                spaces = false;
            } else if character == ' ' {
                if allow_breaks
                    && !spaces
                    && self.column > BEST_WIDTH
                    && index != 0
                    && index + 1 != chars.len()
                {
                    self.write_indent();
                    if chars.get(index + 1) == Some(&' ') {
                        self.put('\\');
                    }
                } else {
                    self.put(character);
                }
                spaces = true;
            } else {
                self.put(character);
                spaces = false;
            }
        }
        self.write_indicator("\"", false, false, false);
    }

    fn write_folded(&mut self, value: &str) {
        let chars: Vec<char> = value.chars().collect();
        self.write_indicator(">", true, false, false);
        // Block scalar hints.
        let first = chars[0];
        if first == ' ' || is_break(first) {
            self.put_str(&BEST_INDENT.to_string());
        }
        let last = chars[chars.len() - 1];
        let chomp = if !is_break(last) {
            Some("-")
        } else if chars.len() == 1 || is_break(chars[chars.len() - 2]) {
            Some("+")
        } else {
            None
        };
        if let Some(chomp) = chomp {
            self.put_str(chomp);
        }
        self.put_break();
        self.indention = true;
        self.whitespace = true;

        let mut breaks = true;
        let mut leading_spaces = true;
        for (index, &character) in chars.iter().enumerate() {
            if is_break(character) {
                if !breaks && !leading_spaces && character == '\n' {
                    let mut next = index;
                    while next < chars.len() && is_break(chars[next]) {
                        next += 1;
                    }
                    if !is_blankz(chars.get(next).copied()) {
                        self.put_break();
                    }
                }
                self.write_break();
                self.indention = true;
                breaks = true;
            } else {
                if breaks {
                    self.write_indent();
                    leading_spaces = is_blank(character);
                }
                if !breaks
                    && character == ' '
                    && chars.get(index + 1) != Some(&' ')
                    && self.column > BEST_WIDTH
                {
                    self.write_indent();
                } else {
                    self.put(character);
                }
                self.indention = false;
                breaks = false;
            }
        }
    }
}
