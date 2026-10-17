//! Configuration errors. Messages never contain secret values.

/// Mirrors the .NET exception types the C# implementation throws.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PrivacyError {
    /// `ArgumentException`: invalid argument (for example a short HMAC key).
    #[error("{0}")]
    Argument(String),
    /// `InvalidOperationException`: the policy cannot run safely (for example Hmac
    /// without a key).
    #[error("{0}")]
    InvalidOperation(String),
    /// `InvalidDataException`: invalid privacy profile or key file.
    #[error("{0}")]
    InvalidData(String),
    /// I/O failure reading a key file.
    #[error("{0}")]
    Io(String),
}

impl PrivacyError {
    /// Name of the equivalent .NET exception type.
    pub fn dotnet_type(&self) -> &'static str {
        match self {
            Self::Argument(_) => "ArgumentException",
            Self::InvalidOperation(_) => "InvalidOperationException",
            Self::InvalidData(_) => "InvalidDataException",
            Self::Io(_) => "IOException",
        }
    }
}
