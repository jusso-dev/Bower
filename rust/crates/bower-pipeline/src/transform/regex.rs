//! Bower's own linear-time regular expressions (`TransformRegex.cs`): the same syntax
//! subset, compiler and Pike VM as C#, over Unicode scalar values with leftmost-first
//! priorities, so matches, captures and step counts are identical.

use super::{Budget, TransformError, limits};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Char,
    Any,
    Class,
    Start,
    End,
    Split,
    Jump,
    Save,
    Match,
}

#[derive(Clone, Copy, Debug)]
struct Instruction {
    op: Op,
    x: usize,
    y: usize,
}

impl Instruction {
    fn new(op: Op, x: usize) -> Self {
        Self { op, x, y: 0 }
    }
}

#[derive(Debug)]
enum Node {
    Empty,
    Char(u32),
    Any,
    Class(usize),
    Start,
    End,
    /// Capture index (0 for a non-capturing group) and body.
    Group(usize, Box<Node>),
    Concat(Vec<Node>),
    Alternate(Vec<Node>),
    Repeat {
        body: Box<Node>,
        minimum: usize,
        /// `None` is unbounded.
        maximum: Option<usize>,
        greedy: bool,
    },
}

#[derive(Debug)]
pub(crate) struct TransformRegex {
    program: Vec<Instruction>,
    classes: Vec<Vec<u32>>,
    negated: Vec<bool>,
    pub group_names: Vec<String>,
}

const CAP: usize = limits::MAXIMUM_REGEX_INSTRUCTIONS + 1;

fn size(node: &Node) -> usize {
    let size = match node {
        Node::Empty => 0,
        Node::Char(_) | Node::Any | Node::Class(_) | Node::Start | Node::End => 1,
        Node::Group(capture, body) => size(body) + if *capture > 0 { 2 } else { 0 },
        Node::Concat(children) => children.iter().map(size).sum(),
        Node::Alternate(children) => {
            children.iter().map(size).sum::<usize>() + 2 * (children.len() - 1)
        }
        Node::Repeat {
            body,
            minimum,
            maximum,
            ..
        } => {
            let body = size(body);
            match maximum {
                None => minimum * body + body + 2,
                Some(maximum) => minimum * body + (maximum - minimum) * (body + 1),
            }
        }
    };
    size.min(CAP)
}

fn branch(body: usize, skip: usize, greedy: bool) -> Instruction {
    if greedy {
        Instruction {
            op: Op::Split,
            x: body,
            y: skip,
        }
    } else {
        Instruction {
            op: Op::Split,
            x: skip,
            y: body,
        }
    }
}

fn emit(node: &Node, program: &mut Vec<Instruction>) {
    match node {
        Node::Empty => {}
        Node::Char(character) => program.push(Instruction::new(Op::Char, *character as usize)),
        Node::Any => program.push(Instruction::new(Op::Any, 0)),
        Node::Class(index) => program.push(Instruction::new(Op::Class, *index)),
        Node::Start => program.push(Instruction::new(Op::Start, 0)),
        Node::End => program.push(Instruction::new(Op::End, 0)),
        Node::Group(capture, body) => {
            if *capture > 0 {
                program.push(Instruction::new(Op::Save, 2 * capture));
            }
            emit(body, program);
            if *capture > 0 {
                program.push(Instruction::new(Op::Save, 2 * capture + 1));
            }
        }
        Node::Concat(children) => children.iter().for_each(|child| emit(child, program)),
        Node::Alternate(children) => {
            let mut jumps = Vec::new();
            for child in &children[..children.len() - 1] {
                let split = program.len();
                program.push(Instruction::new(Op::Split, split + 1));
                emit(child, program);
                jumps.push(program.len());
                program.push(Instruction::new(Op::Jump, 0));
                program[split].y = program.len();
            }
            emit(&children[children.len() - 1], program);
            let end = program.len();
            for jump in jumps {
                program[jump].x = end;
            }
        }
        Node::Repeat {
            body,
            minimum,
            maximum,
            greedy,
        } => {
            for _ in 0..*minimum {
                emit(body, program);
            }
            match maximum {
                None => {
                    let split = program.len();
                    program.push(Instruction::new(Op::Split, 0));
                    emit(body, program);
                    program.push(Instruction::new(Op::Jump, split));
                    program[split] = branch(split + 1, program.len(), *greedy);
                }
                Some(maximum) => {
                    let mut splits = Vec::new();
                    for _ in *minimum..*maximum {
                        splits.push(program.len());
                        program.push(Instruction::new(Op::Split, 0));
                        emit(body, program);
                    }
                    let end = program.len();
                    for split in splits {
                        program[split] = branch(split + 1, end, *greedy);
                    }
                }
            }
        }
    }
}

struct ThreadList {
    marked: Vec<bool>,
    marked_list: Vec<usize>,
    threads: Vec<(usize, Vec<i64>)>,
}

impl ThreadList {
    fn new(size: usize) -> Self {
        Self {
            marked: vec![false; size],
            marked_list: Vec::new(),
            threads: Vec::new(),
        }
    }

    fn mark(&mut self, pc: usize) -> bool {
        if self.marked[pc] {
            return false;
        }
        self.marked[pc] = true;
        self.marked_list.push(pc);
        true
    }

    fn clear(&mut self) {
        for pc in self.marked_list.drain(..) {
            self.marked[pc] = false;
        }
        self.threads.clear();
    }
}

enum Frame {
    Explore(usize),
    Restore(usize, i64),
}

impl TransformRegex {
    /// `None` for anything outside the supported subset or over the size limits.
    pub fn compile(pattern: &str) -> Option<Self> {
        let length: usize = pattern.chars().map(char::len_utf16).sum();
        if !(1..=limits::MAXIMUM_REGEX_PATTERN_LENGTH).contains(&length) {
            return None;
        }
        let mut parser = PatternParser {
            pattern: pattern.chars().map(u32::from).collect(),
            position: 0,
            classes: Vec::new(),
            negated: Vec::new(),
            names: Vec::new(),
        };
        let root = parser.alternation(0).ok()?;
        if parser.position != parser.pattern.len()
            || size(&root) + 3 > limits::MAXIMUM_REGEX_INSTRUCTIONS
        {
            return None;
        }
        let mut program = vec![Instruction::new(Op::Save, 0)];
        emit(&root, &mut program);
        program.push(Instruction::new(Op::Save, 1));
        program.push(Instruction::new(Op::Match, 0));
        Some(Self {
            program,
            classes: parser.classes,
            negated: parser.negated,
            group_names: parser.names,
        })
    }

    /// True when the pattern matches anywhere; stops at the first match.
    pub fn is_match(&self, text: &[char], budget: &mut Budget) -> Result<bool, TransformError> {
        Ok(self.run(text, true, budget)?.is_some())
    }

    /// Capture slots of the leftmost-first match (-1 when unset).
    pub fn search(
        &self,
        text: &[char],
        budget: &mut Budget,
    ) -> Result<Option<Vec<i64>>, TransformError> {
        self.run(text, false, budget)
    }

    fn run(
        &self,
        text: &[char],
        earliest: bool,
        budget: &mut Budget,
    ) -> Result<Option<Vec<i64>>, TransformError> {
        let slots = 2 * (self.group_names.len() + 1);
        let mut current = ThreadList::new(self.program.len());
        let mut next = ThreadList::new(self.program.len());
        let mut stack = Vec::new();
        let mut matched: Option<Vec<i64>> = None;
        for position in 0..=text.len() {
            if matched.is_none() {
                self.add_thread(
                    &mut current,
                    0,
                    position,
                    &vec![-1; slots],
                    text.len(),
                    &mut stack,
                    budget,
                )?;
            }
            let mut index = 0;
            while index < current.threads.len() {
                budget.step()?;
                let pc = current.threads[index].0;
                let instruction = self.program[pc];
                if instruction.op == Op::Match {
                    let captures = std::mem::take(&mut current.threads[index].1);
                    if earliest {
                        return Ok(Some(captures));
                    }
                    matched = Some(captures);
                    break;
                }
                if position < text.len() && self.consumes(instruction, text[position]) {
                    let captures = current.threads[index].1.clone();
                    self.add_thread(
                        &mut next,
                        pc + 1,
                        position + 1,
                        &captures,
                        text.len(),
                        &mut stack,
                        budget,
                    )?;
                }
                index += 1;
            }
            std::mem::swap(&mut current, &mut next);
            next.clear();
            if current.threads.is_empty() && matched.is_some() {
                break;
            }
        }
        Ok(matched)
    }

    fn consumes(&self, instruction: Instruction, character: char) -> bool {
        let character = u32::from(character);
        match instruction.op {
            Op::Char => character as usize == instruction.x,
            Op::Any => character != u32::from('\n'),
            Op::Class => {
                let ranges = &self.classes[instruction.x];
                let inside = ranges
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .any(|[low, high]| (*low..=*high).contains(&character));
                inside != self.negated[instruction.x]
            }
            _ => false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_thread(
        &self,
        list: &mut ThreadList,
        start: usize,
        position: usize,
        captures: &[i64],
        length: usize,
        stack: &mut Vec<Frame>,
        budget: &mut Budget,
    ) -> Result<(), TransformError> {
        let mut working = captures.to_vec();
        stack.push(Frame::Explore(start));
        while let Some(frame) = stack.pop() {
            let pc = match frame {
                Frame::Restore(slot, old) => {
                    working[slot] = old;
                    continue;
                }
                Frame::Explore(pc) => pc,
            };
            if !list.mark(pc) {
                continue;
            }
            budget.step()?;
            let instruction = self.program[pc];
            match instruction.op {
                Op::Jump => stack.push(Frame::Explore(instruction.x)),
                Op::Split => {
                    stack.push(Frame::Explore(instruction.y));
                    stack.push(Frame::Explore(instruction.x));
                }
                Op::Save => {
                    stack.push(Frame::Restore(instruction.x, working[instruction.x]));
                    working[instruction.x] = position as i64;
                    stack.push(Frame::Explore(pc + 1));
                }
                Op::Start => {
                    if position == 0 {
                        stack.push(Frame::Explore(pc + 1));
                    }
                }
                Op::End => {
                    if position == length {
                        stack.push(Frame::Explore(pc + 1));
                    }
                }
                _ => list.threads.push((pc, working.clone())),
            }
        }
        Ok(())
    }
}

struct PatternParser {
    pattern: Vec<u32>,
    position: usize,
    classes: Vec<Vec<u32>>,
    negated: Vec<bool>,
    names: Vec<String>,
}

/// Anything outside the supported subset.
struct Unsupported;

const ESCAPABLE: &str = "\\.*+?()[]{}|^$-/";

fn is(value: u32, character: char) -> bool {
    value == u32::from(character)
}

fn shorthand(escaped: u32) -> Option<Vec<u32>> {
    let ranges: &[char] = match char::from_u32(escaped)? {
        'd' | 'D' => &['0', '9'],
        'w' | 'W' => &['0', '9', 'A', 'Z', '_', '_', 'a', 'z'],
        's' | 'S' => &['\t', '\r', ' ', ' '],
        _ => return None,
    };
    Some(
        ranges
            .iter()
            .map(|character| u32::from(*character))
            .collect(),
    )
}

fn escaped_character(escaped: u32) -> Result<u32, Unsupported> {
    match char::from_u32(escaped) {
        Some('t') => Ok(u32::from('\t')),
        Some('n') => Ok(u32::from('\n')),
        Some('r') => Ok(u32::from('\r')),
        Some(character) if ESCAPABLE.contains(character) => Ok(escaped),
        _ => Err(Unsupported),
    }
}

impl PatternParser {
    fn at_end(&self) -> bool {
        self.position >= self.pattern.len()
    }

    fn peek_is(&self, character: char) -> bool {
        !self.at_end() && is(self.pattern[self.position], character)
    }

    fn peek_any(&self, characters: &str) -> bool {
        !self.at_end()
            && char::from_u32(self.pattern[self.position])
                .is_some_and(|current| characters.contains(current))
    }

    fn take(&mut self) -> u32 {
        let value = self.pattern[self.position];
        self.position += 1;
        value
    }

    fn alternation(&mut self, depth: usize) -> Result<Node, Unsupported> {
        if depth > limits::MAXIMUM_EXPRESSION_DEPTH {
            return Err(Unsupported);
        }
        let mut branches = vec![self.concatenation(depth)?];
        while self.peek_is('|') {
            self.position += 1;
            branches.push(self.concatenation(depth)?);
        }
        Ok(if branches.len() == 1 {
            branches.pop().unwrap_or(Node::Empty)
        } else {
            Node::Alternate(branches)
        })
    }

    fn concatenation(&mut self, depth: usize) -> Result<Node, Unsupported> {
        let mut items = Vec::new();
        while !self.at_end() && !self.peek_is('|') && !self.peek_is(')') {
            items.push(self.repeat(depth)?);
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.pop().unwrap_or(Node::Empty),
            _ => Node::Concat(items),
        })
    }

    fn repeat(&mut self, depth: usize) -> Result<Node, Unsupported> {
        let atom = self.atom(depth)?;
        if !self.peek_any("*+?{") {
            return Ok(atom);
        }
        if matches!(atom, Node::Start | Node::End) {
            return Err(Unsupported);
        }
        let quantifier = self.take();
        let (minimum, maximum) = if is(quantifier, '*') {
            (0, None)
        } else if is(quantifier, '+') {
            (1, None)
        } else if is(quantifier, '?') {
            (0, Some(1))
        } else {
            let minimum = self.number()?;
            let mut maximum = Some(minimum);
            if self.peek_is(',') {
                self.position += 1;
                maximum = if self.peek_is('}') {
                    None
                } else {
                    Some(self.number()?)
                };
            }
            if !self.peek_is('}') || maximum.is_some_and(|maximum| maximum < minimum) {
                return Err(Unsupported);
            }
            self.position += 1;
            (minimum, maximum)
        };
        let mut greedy = true;
        if self.peek_is('?') {
            greedy = false;
            self.position += 1;
        }
        if self.peek_any("*+?{") {
            return Err(Unsupported);
        }
        Ok(Node::Repeat {
            body: Box::new(atom),
            minimum,
            maximum,
            greedy,
        })
    }

    fn number(&mut self) -> Result<usize, Unsupported> {
        let start = self.position;
        let mut value = 0usize;
        while !self.at_end() && self.position - start < 3 {
            let Some(digit) = char::from_u32(self.pattern[self.position])
                .filter(char::is_ascii_digit)
                .and_then(|character| character.to_digit(10))
            else {
                break;
            };
            value = value * 10 + digit as usize;
            self.position += 1;
        }
        if self.position == start || value > limits::MAXIMUM_REGEX_REPEAT {
            return Err(Unsupported);
        }
        Ok(value)
    }

    fn atom(&mut self, depth: usize) -> Result<Node, Unsupported> {
        let current = self.take();
        let Some(character) = char::from_u32(current) else {
            return Err(Unsupported);
        };
        match character {
            '(' => {
                if !self.peek_is('?') {
                    return Err(Unsupported);
                }
                self.position += 1;
                let mut group = 0;
                if self.peek_is(':') {
                    self.position += 1;
                } else if self.peek_is('<') {
                    self.position += 1;
                    let name = self.group_name()?;
                    if self.names.contains(&name)
                        || self.names.len() == limits::MAXIMUM_REGEX_GROUPS
                    {
                        return Err(Unsupported);
                    }
                    self.names.push(name);
                    group = self.names.len();
                } else {
                    return Err(Unsupported);
                }
                let body = self.alternation(depth + 1)?;
                if !self.peek_is(')') {
                    return Err(Unsupported);
                }
                self.position += 1;
                Ok(Node::Group(group, Box::new(body)))
            }
            '[' => self.class(),
            '.' => Ok(Node::Any),
            '^' => Ok(Node::Start),
            '$' => Ok(Node::End),
            '\\' => {
                if self.at_end() {
                    return Err(Unsupported);
                }
                let escaped = self.take();
                if let Some(ranges) = shorthand(escaped) {
                    let negate = char::from_u32(escaped).is_some_and(|c| c.is_ascii_uppercase());
                    return Ok(self.add_class(ranges, negate));
                }
                Ok(Node::Char(escaped_character(escaped)?))
            }
            ')' | ']' | '{' | '}' | '*' | '+' | '?' | '|' => Err(Unsupported),
            _ => Ok(Node::Char(current)),
        }
    }

    fn group_name(&mut self) -> Result<String, Unsupported> {
        let start = self.position;
        while !self.at_end() && !self.peek_is('>') {
            let character = char::from_u32(self.pattern[self.position]).unwrap_or('\0');
            let valid = character.is_ascii_alphabetic()
                || character == '_'
                || (self.position > start && character.is_ascii_digit());
            if !valid || self.position - start >= 32 {
                return Err(Unsupported);
            }
            self.position += 1;
        }
        if self.at_end() || self.position == start {
            return Err(Unsupported);
        }
        let name = self.pattern[start..self.position]
            .iter()
            .filter_map(|value| char::from_u32(*value))
            .collect();
        self.position += 1;
        Ok(name)
    }

    fn range_follows(&self) -> bool {
        self.peek_is('-')
            && self.position + 1 < self.pattern.len()
            && !is(self.pattern[self.position + 1], ']')
    }

    fn class(&mut self) -> Result<Node, Unsupported> {
        let mut negate = false;
        if self.peek_is('^') {
            negate = true;
            self.position += 1;
        }
        let mut ranges = Vec::new();
        let mut first = true;
        loop {
            if self.at_end() {
                return Err(Unsupported);
            }
            let current = self.take();
            if is(current, ']') && !first {
                break;
            }
            first = false;
            if is(current, ']') || is(current, '[') {
                return Err(Unsupported);
            }
            let low = if is(current, '\\') {
                if self.at_end() {
                    return Err(Unsupported);
                }
                let escaped = self.take();
                if let Some(shorthand) = shorthand(escaped)
                    && char::from_u32(escaped).is_some_and(|c| c.is_ascii_lowercase())
                {
                    ranges.extend(shorthand);
                    if self.range_follows() {
                        return Err(Unsupported);
                    }
                    continue;
                }
                escaped_character(escaped)?
            } else {
                current
            };
            let mut high = low;
            if self.range_follows() {
                self.position += 1;
                let mut upper = self.take();
                if is(upper, '\\') {
                    if self.at_end() {
                        return Err(Unsupported);
                    }
                    let escaped = self.take();
                    upper = escaped_character(escaped)?;
                } else if is(upper, '[') {
                    return Err(Unsupported);
                }
                if upper < low {
                    return Err(Unsupported);
                }
                high = upper;
            }
            ranges.push(low);
            ranges.push(high);
        }
        Ok(self.add_class(ranges, negate))
    }

    fn add_class(&mut self, ranges: Vec<u32>, negate: bool) -> Node {
        self.classes.push(ranges);
        self.negated.push(negate);
        Node::Class(self.classes.len() - 1)
    }
}
