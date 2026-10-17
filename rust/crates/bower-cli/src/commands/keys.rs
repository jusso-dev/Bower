//! `bower keys generate --out-dir DIR [--name NAME]` (C# `KeyCommands.Generate`).

use std::io::Write;
use std::path::Path;

use crate::cli::KeysGenerateArgs;
use crate::support::{CliError, CliResult, required, write_text};

pub fn generate(args: &KeysGenerateArgs) -> CliResult {
    let directory = required(args.out_dir.as_deref(), "--out-dir")?;
    let name = args.name.as_deref().unwrap_or("bower-signing");
    std::fs::create_dir_all(directory).map_err(CliError::from_display)?;
    let pair = bower_integrity::generate_key_pair();
    let private_path = Path::new(directory).join(format!("{name}.key.pem"));
    let public_path = Path::new(directory).join(format!("{name}.pub.pem"));
    let private_shown = private_path.to_string_lossy().into_owned();
    let public_shown = public_path.to_string_lossy().into_owned();
    if private_path.exists() {
        return Err(CliError(format!(
            "{private_shown} already exists; refusing to overwrite a signing key."
        )));
    }

    write_private(&private_path, &pair.private_key_pem).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            CliError(format!(
                "{private_shown} already exists; refusing to overwrite a signing key."
            ))
        } else {
            CliError(format!("Could not write {private_shown}: {}", error.kind()))
        }
    })?;
    write_text(&public_shown, &pair.public_key_pem)?;
    println!("Key id:      {}", pair.key_id);
    println!("Private key: {private_shown} (keep secret; store in a vault or HSM)");
    println!("Public key:  {public_shown} (distribute to collectors and verifiers)");
    Ok(0)
}

/// Creates the private key file owner read/write only (C# sets `UserRead | UserWrite`
/// after writing; creating with the mode avoids a window where it is wider).
fn write_private(path: &Path, pem: &str) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(pem.as_bytes())?;
    file.sync_all()
}
