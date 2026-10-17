//! `bower token generate [--id PRODUCER]` (C# `TokenCommands.Generate`).
//!
//! The token is the command's product, so it goes to stdout exactly once; the
//! tokens-file line carries only the SHA-256 digest.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::cli::TokenGenerateArgs;
use crate::support::{CliError, CliResult};

/// 32 CSPRNG bytes, base64url without padding (43 characters).
pub fn new_token() -> CliResult<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|_| CliError::new("Secure random number generator unavailable."))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// `{producer} sha256:{lowercase hex}` line for `BOWER_INGEST_TOKENS_FILE`.
pub fn tokens_file_line(producer: &str, token: &str) -> String {
    format!(
        "{producer} sha256:{}",
        hex::encode(Sha256::digest(token.as_bytes()))
    )
}

pub fn generate(args: &TokenGenerateArgs) -> CliResult {
    let token = new_token()?;
    match &args.id {
        Some(producer) => {
            eprintln!("Give this token to producer '{producer}' (shown once):");
            println!("{token}");
            eprintln!(
                "Add this line to the collector's BOWER_INGEST_TOKENS_FILE (remove it to revoke):"
            );
            eprintln!("{}", tokens_file_line(producer, &token));
        }
        None => println!("{token}"),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_base64url_32_bytes() {
        let token = new_token().unwrap();
        assert_eq!(token.len(), 43);
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
        assert_ne!(token, new_token().unwrap());
    }

    #[test]
    fn tokens_file_line_is_sha256_hex() {
        assert_eq!(
            tokens_file_line("app", "abc"),
            "app sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
