//! Strict, bounded condition and field matching shared by loader and engine.
use crate::{DetectionError, model::DetectionFields, ordinal::{eq_ignore_case, contains_ignore_case, ends_with_ignore_case}};

pub(crate) fn invalid() -> DetectionError {
    DetectionError::InvalidData("Unsupported or over-limit detection syntax.".to_owned())
}

pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64
        && value.as_bytes().first().is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
        && value.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

pub(crate) fn validate_clauses(clauses: &[Vec<String>]) -> Result<(), DetectionError> {
    if clauses.is_empty() || clauses.len() > 64 { return Err(invalid()); }
    let mut seen: Vec<String> = Vec::new();
    for clause in clauses {
        if clause.len() < 3 || clause.len() > 66 { return Err(invalid()); }
        let key = format!("{}|{}", clause[0], clause[1]);
        if clause[0].is_empty() || clause[0].len() > 128
            || !clause[0].bytes().all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            || seen.iter().any(|v| eq_ignore_case(v, &key))
            || !["equals", "contains", "startswith", "endswith"].contains(&clause[1].as_str())
            || clause[2..].iter().any(|v| v.is_empty() || v.encode_utf16().count() > 4096 || v.contains(['*', '?']))
        { return Err(invalid()); }
        seen.push(key);
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct Semantics {
    selections: Vec<(String, Vec<Vec<String>>)>,
    program: Vec<String>,
}

impl Semantics {
    pub(crate) fn new(fields: &DetectionFields, condition: &str) -> Result<Self, DetectionError> {
        if fields.is_empty() || fields.len() > 64 { return Err(invalid()); }
        let mut selections = Vec::new();
        for (name, encoded) in fields.iter() {
            if !identifier(name) || ["and", "or", "not"].iter().any(|v| eq_ignore_case(v, name))
                || encoded.encode_utf16().count() > 256 * 1024 { return Err(invalid()); }
            let clauses: Vec<Vec<String>> = bower_contracts::json::from_str(encoded).map_err(|_| invalid())?;
            validate_clauses(&clauses)?;
            selections.push((name.to_owned(), clauses));
        }
        let program = Parser::parse(condition, fields)?;
        Ok(Self { selections, program })
    }

    pub(crate) fn matches(&self, get: impl Fn(&str) -> Option<String>) -> Option<Vec<String>> {
        let mut results = Vec::new();
        for (name, clauses) in &self.selections {
            let mut fields = Vec::new();
            let mut matched = true;
            for clause in clauses {
                let value = get(&clause[0]);
                let ok = value.as_ref().is_some_and(|v| v.encode_utf16().count() <= 65536 && clause[2..].iter().any(|p| match clause[1].as_str() {
                    "equals" => eq_ignore_case(v, p),
                    "contains" => contains_ignore_case(v, p),
                    "startswith" => eq_ignore_case(&v.chars().take(p.chars().count()).collect::<String>(), p),
                    "endswith" => ends_with_ignore_case(v, p),
                    _ => false,
                }));
                if !ok { matched = false; break; }
                fields.push(clause[0].clone());
            }
            results.push((name, matched, if matched { fields } else { Vec::new() }));
        }
        let mut stack: Vec<(bool, Vec<String>)> = Vec::new();
        for token in &self.program {
            match token.as_str() {
                "not" => { let (matched, _) = stack.pop()?; stack.push((!matched, Vec::new())); }
                "and" | "or" => {
                    let (right, right_fields) = stack.pop()?;
                    let (left, mut left_fields) = stack.pop()?;
                    let matched = if token == "and" { left && right } else { left || right };
                    left_fields.extend(right_fields);
                    stack.push((matched, if matched { left_fields } else { Vec::new() }));
                }
                _ => {
                    let (_, matched, fields) = results.iter().find(|(name, _, _)| eq_ignore_case(name, token))?;
                    stack.push((*matched, fields.clone()));
                }
            }
        }
        let (matched, fields) = stack.pop()?;
        let mut distinct: Vec<String> = Vec::new();
        for field in fields {
            if !distinct.iter().any(|v| eq_ignore_case(v, &field)) { distinct.push(field); }
        }
        matched.then_some(distinct)
    }
}

struct Parser<'a> {
    tokens: Vec<&'a str>,
    position: usize,
    output: Vec<String>,
    fields: &'a DetectionFields,
}

impl<'a> Parser<'a> {
    fn parse(condition: &'a str, fields: &'a DetectionFields) -> Result<Vec<String>, DetectionError> {
        if condition.is_empty() || condition.len() > 4096 { return Err(invalid()); }
        let bytes = condition.as_bytes();
        let mut tokens = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            if b" \t\r\n".contains(&c) { i += 1; continue; }
            let start = i;
            i += 1;
            if c.is_ascii_alphabetic() || c == b'_' {
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') { i += 1; }
            } else if !b"()".contains(&c) { return Err(invalid()); }
            tokens.push(&condition[start..i]);
            if tokens.len() > 256 { return Err(invalid()); }
        }
        let mut parser = Self { tokens, position: 0, output: Vec::new(), fields };
        parser.or(0)?;
        if parser.position != parser.tokens.len() { return Err(invalid()); }
        Ok(parser.output)
    }

    fn take(&mut self, token: &str) -> bool {
        if self.tokens.get(self.position).is_some_and(|v| eq_ignore_case(v, token)) {
            self.position += 1; true
        } else { false }
    }

    fn or(&mut self, depth: usize) -> Result<(), DetectionError> {
        self.and(depth)?;
        while self.take("or") { self.and(depth)?; self.output.push("or".to_owned()); }
        Ok(())
    }

    fn and(&mut self, depth: usize) -> Result<(), DetectionError> {
        self.unary(depth)?;
        while self.take("and") { self.unary(depth)?; self.output.push("and".to_owned()); }
        Ok(())
    }

    fn unary(&mut self, depth: usize) -> Result<(), DetectionError> {
        if depth > 32 { return Err(invalid()); }
        if self.take("not") { self.unary(depth + 1)?; self.output.push("not".to_owned()); }
        else if self.take("(") { self.or(depth + 1)?; if !self.take(")") { return Err(invalid()); } }
        else if let Some(token) = self.tokens.get(self.position).filter(|v| self.fields.get(v).is_some()) {
            self.output.push((*token).to_owned()); self.position += 1;
        } else { return Err(invalid()); }
        Ok(())
    }
}
