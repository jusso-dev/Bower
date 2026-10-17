//! Start-up failures. `kind` mirrors the .NET exception type name the C# host prints
//! (`Bower collector failed: {Type}: {Message}`). Messages are Bower-authored
//! configuration or storage errors and never contain secrets.

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostError {
    pub kind: &'static str,
    pub message: String,
}

impl HostError {
    pub fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// File errors carry the path (never file contents), like .NET IO exceptions.
    pub fn io(path: impl AsRef<std::path::Path>, error: &std::io::Error) -> Self {
        let path = path.as_ref().display();
        match error.kind() {
            std::io::ErrorKind::NotFound => Self::new(
                "FileNotFoundException",
                format!("Could not find file '{path}'."),
            ),
            std::io::ErrorKind::PermissionDenied => Self::new(
                "UnauthorizedAccessException",
                format!("Access to the path '{path}' is denied."),
            ),
            _ => Self::new(
                "IOException",
                format!("Could not read '{path}': {}", error.kind()),
            ),
        }
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for HostError {}
