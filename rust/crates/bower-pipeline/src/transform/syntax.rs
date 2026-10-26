//! Lexer, abstract syntax and recursive-descent parser for one statement
//! (`TransformSyntax.cs`). Positions are 0-based UTF-16 offsets, as in C#.

use std::sync::Arc;

use indexmap::IndexMap;

use super::regex::TransformRegex;
use super::value::Value;
use super::{codes, limits};

/// Resolved at compile time: regex, table or timestamp format.
#[derive(Clone, Debug)]
pub(crate) enum Bound {
    None,
    Regex(Arc<TransformRegex>),
    Table(Arc<IndexMap<String, String>>),
    Format(&'static str),
}

#[derive(Clone, Debug)]
pub(crate) enum Expr {
    Literal(usize, Value),
    Path(usize, Vec<String>),
    Not(usize, Box<Expr>),
    Binary(usize, &'static str, Box<Expr>, Box<Expr>),
    Call(usize, Call),
}

#[derive(Clone, Debug)]
pub(crate) struct Call {
    pub name: String,
    pub arguments: Vec<Expr>,
    pub bound: Bound,
}

impl Expr {
    pub fn position(&self) -> usize {
        match self {
            Self::Literal(position, _)
            | Self::Path(position, _)
            | Self::Not(position, _)
            | Self::Binary(position, ..)
            | Self::Call(position, _) => *position,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Stmt {
    Assign {
        position: usize,
        target: String,
        value: Expr,
    },
    Delete {
        position: usize,
        target: String,
    },
    Rename {
        position: usize,
        from: String,
        to: String,
        to_position: usize,
    },
    If {
        condition: Expr,
        then: Vec<Stmt>,
        otherwise: Option<Vec<Stmt>>,
    },
}

/// A static failure at a UTF-16 position with a stable code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SyntaxError {
    pub position: usize,
    pub code: &'static str,
}

pub(crate) fn fail<T>(position: usize, code: &'static str) -> Result<T, SyntaxError> {
    Err(SyntaxError { position, code })
}

#[derive(Clone, Debug, PartialEq)]
enum Kind {
    Path(Vec<String>),
    Str(String),
    Int(i64),
    Identifier(String),
    Operator(&'static str),
    End,
}

#[derive(Clone, Debug)]
struct Token {
    kind: Kind,
    position: usize,
}

const OPERATORS: [&str; 16] = [
    "==", "!=", "<=", ">=", "&&", "||", "<", ">", "!", "=", "(", ")", "{", "}", ",", ";",
];

struct Lexer {
    chars: Vec<char>,
    /// UTF-16 offset of each char, plus the total length at the end.
    offsets: Vec<usize>,
    index: usize,
}

impl Lexer {
    fn new(text: &str) -> Self {
        let chars: Vec<char> = text.chars().collect();
        let mut offsets = Vec::with_capacity(chars.len() + 1);
        let mut offset = 0;
        for character in &chars {
            offsets.push(offset);
            offset += character.len_utf16();
        }
        offsets.push(offset);
        Self {
            chars,
            offsets,
            index: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.index).copied()
    }

    fn at(&self, index: usize) -> usize {
        self.offsets[index]
    }

    fn segment_character(character: char) -> bool {
        character.is_ascii_alphanumeric() || matches!(character, '_' | '@' | '-')
    }

    fn lex(mut self) -> Result<Vec<Token>, SyntaxError> {
        let mut tokens = Vec::new();
        while let Some(current) = self.peek() {
            if matches!(current, ' ' | '\t' | '\r' | '\n') {
                self.index += 1;
                continue;
            }
            let start = self.index;
            let position = self.at(start);
            let kind = if current == '.' {
                let mut segments = Vec::new();
                while self.peek() == Some('.') {
                    self.index += 1;
                    if self.peek() == Some('"') {
                        let quote = self.at(self.index);
                        let segment = self.quoted()?;
                        if segment.is_empty() {
                            return fail(quote, codes::SYNTAX);
                        }
                        segments.push(segment);
                    } else {
                        let segment_start = self.index;
                        while self.peek().is_some_and(Self::segment_character) {
                            self.index += 1;
                        }
                        if self.index == segment_start {
                            return fail(self.at(segment_start - 1), codes::SYNTAX);
                        }
                        segments.push(self.chars[segment_start..self.index].iter().collect());
                    }
                }
                Kind::Path(segments)
            } else if current == '"' {
                Kind::Str(self.quoted()?)
            } else if current == '\'' {
                let content = self.index + 1;
                let Some(length) = self.chars[content..].iter().position(|next| *next == '\'')
                else {
                    return fail(position, codes::SYNTAX);
                };
                let end = content + length;
                if let Some(control) = (content..end).find(|scan| self.chars[*scan] < ' ') {
                    return fail(self.at(control), codes::SYNTAX);
                }
                self.index = end + 1;
                Kind::Str(self.chars[content..end].iter().collect())
            } else if current.is_ascii_digit() || current == '-' {
                self.index += 1;
                if current == '-' && !self.peek().is_some_and(|next| next.is_ascii_digit()) {
                    return fail(position, codes::SYNTAX);
                }
                let digits = if current == '-' { self.index } else { start };
                while self.peek().is_some_and(|next| next.is_ascii_digit()) {
                    self.index += 1;
                }
                let number: String = self.chars[start..self.index].iter().collect();
                let leading_zero = self.chars[digits] == '0' && self.index - digits > 1;
                match number.parse::<i64>() {
                    Ok(value) if !leading_zero => Kind::Int(value),
                    _ => return fail(position, codes::SYNTAX),
                }
            } else if current.is_ascii_alphabetic() || current == '_' {
                while self
                    .peek()
                    .is_some_and(|next| next.is_ascii_alphanumeric() || next == '_')
                {
                    self.index += 1;
                }
                Kind::Identifier(self.chars[start..self.index].iter().collect())
            } else {
                let rest: String = self.chars[start..(start + 2).min(self.chars.len())]
                    .iter()
                    .collect();
                match OPERATORS
                    .iter()
                    .find(|operator| rest.starts_with(**operator))
                {
                    Some(operator) => {
                        self.index += operator.len();
                        Kind::Operator(operator)
                    }
                    None => return fail(position, codes::SYNTAX),
                }
            };
            tokens.push(Token { kind, position });
        }
        tokens.push(Token {
            kind: Kind::End,
            position: self.at(self.chars.len()),
        });
        Ok(tokens)
    }

    /// Double-quoted text with `\" \\ \n \r \t` escapes; no raw control characters.
    fn quoted(&mut self) -> Result<String, SyntaxError> {
        let start = self.at(self.index);
        self.index += 1;
        let mut value = String::new();
        loop {
            let Some(current) = self.peek() else {
                return fail(start, codes::SYNTAX);
            };
            match current {
                '"' => {
                    self.index += 1;
                    return Ok(value);
                }
                control if control < ' ' => return fail(self.at(self.index), codes::SYNTAX),
                '\\' => {
                    let escaped = match self.chars.get(self.index + 1) {
                        Some('"') => '"',
                        Some('\\') => '\\',
                        Some('n') => '\n',
                        Some('r') => '\r',
                        Some('t') => '\t',
                        _ => return fail(self.at(self.index), codes::SYNTAX),
                    };
                    value.push(escaped);
                    self.index += 2;
                }
                other => {
                    value.push(other);
                    self.index += 1;
                }
            }
        }
    }
}

pub(crate) struct Parser {
    tokens: Vec<Token>,
    index: usize,
    depth: usize,
    block_depth: usize,
    nodes: usize,
}

impl Parser {
    pub fn parse(text: &str) -> Result<Stmt, SyntaxError> {
        let mut parser = Self {
            tokens: Lexer::new(text).lex()?,
            index: 0,
            depth: 0,
            block_depth: 0,
            nodes: 0,
        };
        let statement = parser.statement()?;
        if parser.current().kind != Kind::End {
            return fail(parser.current().position, codes::SYNTAX);
        }
        Ok(statement)
    }

    fn current(&self) -> &Token {
        &self.tokens[self.index]
    }

    fn is_operator(&self, text: &str) -> bool {
        matches!(&self.current().kind, Kind::Operator(operator) if *operator == text)
    }

    fn is_keyword(&self, text: &str) -> bool {
        matches!(&self.current().kind, Kind::Identifier(name) if name == text)
    }

    fn expect(&mut self, text: &str) -> Result<(), SyntaxError> {
        if !self.is_operator(text) {
            return fail(self.current().position, codes::SYNTAX);
        }
        self.index += 1;
        Ok(())
    }

    fn count_node(&mut self, position: usize) -> Result<(), SyntaxError> {
        self.nodes += 1;
        if self.nodes > limits::MAXIMUM_NODES_PER_STATEMENT {
            return fail(position, codes::LIMIT_EXCEEDED);
        }
        Ok(())
    }

    fn enter(&mut self, position: usize) -> Result<(), SyntaxError> {
        self.depth += 1;
        if self.depth > limits::MAXIMUM_EXPRESSION_DEPTH {
            return fail(position, codes::LIMIT_EXCEEDED);
        }
        Ok(())
    }

    fn target(&mut self) -> Result<(String, usize), SyntaxError> {
        let token = self.current().clone();
        let Kind::Path(segments) = token.kind else {
            return fail(token.position, codes::SYNTAX);
        };
        self.index += 1;
        if segments.len() != 1 {
            return fail(token.position, codes::INVALID_TARGET);
        }
        Ok((
            segments.into_iter().next().unwrap_or_default(),
            token.position,
        ))
    }

    fn statement(&mut self) -> Result<Stmt, SyntaxError> {
        let start = self.current().clone();
        self.count_node(start.position)?;
        if self.is_keyword("if") {
            self.index += 1;
            return self.conditional(start.position);
        }
        if self.is_keyword("del") {
            self.index += 1;
            self.expect("(")?;
            let (target, _) = self.target()?;
            self.expect(")")?;
            return Ok(Stmt::Delete {
                position: start.position,
                target,
            });
        }
        if self.is_keyword("rename") {
            self.index += 1;
            self.expect("(")?;
            let (from, _) = self.target()?;
            self.expect(",")?;
            let (to, to_position) = self.target()?;
            self.expect(")")?;
            return Ok(Stmt::Rename {
                position: start.position,
                from,
                to,
                to_position,
            });
        }
        if matches!(start.kind, Kind::Path(_)) {
            let (target, _) = self.target()?;
            self.expect("=")?;
            let value = self.expression()?;
            return Ok(Stmt::Assign {
                position: start.position,
                target,
                value,
            });
        }
        fail(start.position, codes::SYNTAX)
    }

    fn conditional(&mut self, position: usize) -> Result<Stmt, SyntaxError> {
        self.block_depth += 1;
        if self.block_depth > limits::MAXIMUM_BLOCK_DEPTH {
            return fail(position, codes::LIMIT_EXCEEDED);
        }
        let condition = self.expression()?;
        let then = self.block()?;
        let mut otherwise = None;
        if self.is_keyword("else") {
            self.index += 1;
            if self.is_keyword("if") {
                let nested = self.current().position;
                self.count_node(nested)?;
                self.index += 1;
                otherwise = Some(vec![self.conditional(nested)?]);
            } else {
                otherwise = Some(self.block()?);
            }
        }
        self.block_depth -= 1;
        Ok(Stmt::If {
            condition,
            then,
            otherwise,
        })
    }

    fn block(&mut self) -> Result<Vec<Stmt>, SyntaxError> {
        self.expect("{")?;
        let mut statements = vec![self.statement()?];
        while self.is_operator(";") {
            self.index += 1;
            if self.is_operator("}") {
                break;
            }
            statements.push(self.statement()?);
        }
        self.expect("}")?;
        Ok(statements)
    }

    fn binary_operator(&self, choices: &[&'static str]) -> Option<&'static str> {
        match &self.current().kind {
            Kind::Operator(operator) => choices.iter().copied().find(|choice| choice == operator),
            _ => None,
        }
    }

    fn expression(&mut self) -> Result<Expr, SyntaxError> {
        let mut left = self.and()?;
        while let Some(operator) = self.binary_operator(&["||"]) {
            let position = self.current().position;
            self.index += 1;
            self.count_node(position)?;
            let right = self.and()?;
            left = Expr::Binary(position, operator, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, SyntaxError> {
        let mut left = self.unary()?;
        while let Some(operator) = self.binary_operator(&["&&"]) {
            let position = self.current().position;
            self.index += 1;
            self.count_node(position)?;
            let right = self.unary()?;
            left = Expr::Binary(position, operator, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, SyntaxError> {
        if self.is_operator("!") {
            let position = self.current().position;
            self.index += 1;
            self.count_node(position)?;
            self.enter(position)?;
            let operand = self.unary()?;
            self.depth -= 1;
            return Ok(Expr::Not(position, Box::new(operand)));
        }
        let left = self.primary()?;
        if let Some(operator) = self.binary_operator(&["==", "!=", "<", "<=", ">", ">="]) {
            let position = self.current().position;
            self.index += 1;
            self.count_node(position)?;
            let right = self.primary()?;
            return Ok(Expr::Binary(
                position,
                operator,
                Box::new(left),
                Box::new(right),
            ));
        }
        Ok(left)
    }

    fn primary(&mut self) -> Result<Expr, SyntaxError> {
        let token = self.current().clone();
        self.count_node(token.position)?;
        match token.kind {
            Kind::Str(text) => {
                self.index += 1;
                Ok(Expr::Literal(token.position, Value::Str(text)))
            }
            Kind::Int(value) => {
                self.index += 1;
                Ok(Expr::Literal(token.position, Value::Int(value)))
            }
            Kind::Path(segments) => {
                self.index += 1;
                Ok(Expr::Path(token.position, segments))
            }
            Kind::Identifier(name) => {
                self.index += 1;
                match name.as_str() {
                    "true" => return Ok(Expr::Literal(token.position, Value::Bool(true))),
                    "false" => return Ok(Expr::Literal(token.position, Value::Bool(false))),
                    "null" => return Ok(Expr::Literal(token.position, Value::Null)),
                    _ => {}
                }
                self.expect("(")?;
                self.enter(token.position)?;
                let mut arguments = Vec::new();
                if !self.is_operator(")") {
                    arguments.push(self.expression()?);
                    while self.is_operator(",") {
                        self.index += 1;
                        if arguments.len() == limits::MAXIMUM_ARGUMENTS {
                            return fail(token.position, codes::ARITY);
                        }
                        arguments.push(self.expression()?);
                    }
                }
                self.expect(")")?;
                self.depth -= 1;
                Ok(Expr::Call(
                    token.position,
                    Call {
                        name,
                        arguments,
                        bound: Bound::None,
                    },
                ))
            }
            _ if self.is_operator("(") => {
                self.index += 1;
                self.enter(token.position)?;
                let inner = self.expression()?;
                self.expect(")")?;
                self.depth -= 1;
                Ok(inner)
            }
            _ => fail(token.position, codes::SYNTAX),
        }
    }
}
