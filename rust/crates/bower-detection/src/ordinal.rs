//! `StringComparison.OrdinalIgnoreCase` helpers: per-character simple upper-case
//! mapping (`char.ToUpperInvariant`), no culture rules.

fn upper(character: char) -> char {
    let mut mapped = character.to_uppercase();
    match (mapped.next(), mapped.next()) {
        (Some(single), None) => single,
        _ => character,
    }
}

fn folded(text: &str) -> Vec<char> {
    text.chars().map(upper).collect()
}

pub fn eq_ignore_case(left: &str, right: &str) -> bool {
    left.chars().map(upper).eq(right.chars().map(upper))
}

pub fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let haystack = folded(haystack);
    let needle = folded(needle);
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_slice())
}

pub fn ends_with_ignore_case(text: &str, suffix: &str) -> bool {
    let text = folded(text);
    let suffix = folded(suffix);
    text.ends_with(&suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_non_ascii_like_dotnet() {
        assert!(contains_ignore_case("ÉVÉNEMENT failure", "événement"));
        assert!(eq_ignore_case("Straße", "STRAßE"));
        assert!(!eq_ignore_case("Straße", "STRASSE"));
        assert!(ends_with_ignore_case("aws.identityType", "IDENTITYTYPE"));
    }
}
