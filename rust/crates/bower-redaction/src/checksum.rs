//! Deterministic checksum validators (`ChecksumAlgorithms`). Pure functions.
//!
//! Every C# validator rejects any character outside `'0'..='9'`, so non-ASCII
//! input is rejected up front and lengths are measured in ASCII bytes.

const TFN_WEIGHTS: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];
const ABN_WEIGHTS: [i32; 11] = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
const MEDICARE_WEIGHTS: [u32; 8] = [1, 3, 7, 9, 1, 3, 7, 9];

fn digit(byte: u8) -> Option<u32> {
    byte.is_ascii_digit().then(|| u32::from(byte - b'0'))
}

/// Luhn (mod 10) check over ASCII digits.
pub fn luhn(digits: &str) -> bool {
    if digits.is_empty() {
        return false;
    }

    let mut sum = 0u32;
    let mut alternate = false;
    for &byte in digits.as_bytes().iter().rev() {
        let Some(mut value) = digit(byte) else {
            return false;
        };
        if alternate {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }

        sum += value;
        alternate = !alternate;
    }

    sum.is_multiple_of(10)
}

/// ATO TFN algorithm. Accepts 8 or 9 digits (8-digit treated as leading zero).
pub fn is_valid_tfn(digits: &str) -> bool {
    let bytes = digits.as_bytes();
    let mut padded = [b'0'; 9];
    match bytes.len() {
        8 => padded[1..].copy_from_slice(bytes),
        9 => padded.copy_from_slice(bytes),
        _ => return false,
    }

    let mut sum = 0u32;
    for (index, &byte) in padded.iter().enumerate() {
        let Some(value) = digit(byte) else {
            return false;
        };
        sum += value * TFN_WEIGHTS[index];
    }

    sum.is_multiple_of(11)
}

/// Australian Business Number (11 digits).
pub fn is_valid_abn(digits: &str) -> bool {
    let bytes = digits.as_bytes();
    if bytes.len() != 11 || !digits.is_ascii() {
        return false;
    }

    let Some(first) = digit(bytes[0]) else {
        return false;
    };
    let mut sum = (first as i32 - 1) * ABN_WEIGHTS[0];
    for index in 1..11 {
        let Some(value) = digit(bytes[index]) else {
            return false;
        };
        sum += value as i32 * ABN_WEIGHTS[index];
    }

    sum % 89 == 0
}

/// Australian Company Number (9 digits).
pub fn is_valid_acn(digits: &str) -> bool {
    let bytes = digits.as_bytes();
    if bytes.len() != 9 || !digits.is_ascii() {
        return false;
    }

    let mut sum = 0u32;
    for (index, &byte) in bytes[..8].iter().enumerate() {
        let Some(value) = digit(byte) else {
            return false;
        };
        sum += value * (8 - index as u32);
    }

    let Some(check) = digit(bytes[8]) else {
        return false;
    };
    check == (10 - (sum % 10)) % 10
}

/// Medicare card number: 10 digits (8 body + check + issue), first digit 2–6.
pub fn is_valid_medicare(digits: &str) -> bool {
    let bytes = digits.as_bytes();
    if bytes.len() != 10 || !digits.is_ascii() {
        return false;
    }

    if !(b'2'..=b'6').contains(&bytes[0]) {
        return false;
    }

    let mut sum = 0u32;
    for (index, &byte) in bytes[..8].iter().enumerate() {
        let Some(value) = digit(byte) else {
            return false;
        };
        sum += value * MEDICARE_WEIGHTS[index];
    }

    let (Some(check), true) = (digit(bytes[8]), (b'1'..=b'9').contains(&bytes[9])) else {
        return false;
    };
    sum % 10 == check
}

/// Individual Healthcare Identifier: 16 digits starting with 800360, Luhn check.
pub fn is_valid_ihi(digits: &str) -> bool {
    digits.len() == 16 && digits.is_ascii() && digits.starts_with("800360") && luhn(digits)
}

/// ASCII digits only (`ChecksumAlgorithms.DigitsOnly`).
pub fn digits_only(value: &str) -> String {
    value.chars().filter(char::is_ascii_digit).collect()
}

/// Count of ASCII digits (`ChecksumAlgorithms.CountDigits`).
pub fn count_digits(value: &str) -> usize {
    value.bytes().filter(u8::is_ascii_digit).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csharp_checksum_cases() {
        assert!(is_valid_tfn("100000001"));
        assert!(!is_valid_tfn("123456789"));
        assert!(is_valid_abn("51824753556"));
        assert!(!is_valid_abn("51824753557"));
        assert!(is_valid_acn("000000019"));
        assert!(!is_valid_acn("000000018"));
        assert!(is_valid_medicare("2123456701"));
        assert!(!is_valid_medicare("2123456711"));
        assert!(is_valid_ihi("8003600000000007"));
        assert!(!is_valid_ihi("8003600000000008"));
        assert!(luhn("4111111111111111"));
        assert!(!luhn("4111111111111112"));
        assert_eq!(count_digits("a1b2"), 2);
        assert_eq!(digits_only("4111-1111 \u{661}"), "41111111");
    }

    #[test]
    fn tfn_accepts_eight_digits_when_padded_value_is_valid() {
        let eight = (0..1_000_000)
            .map(|n| format!("{n:08}"))
            .find(|eight| is_valid_tfn(&format!("0{eight}")))
            .expect("a valid 8-digit TFN exists");
        assert!(is_valid_tfn(&eight));
    }
}
