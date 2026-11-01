//! RELP framing, offers and responses (C# `SyslogRelp.cs`, the specification).
//!
//! A frame is `TXNR SP COMMAND SP DATALEN [SP DATA] LF`, parsed as librelp does: TXNR and
//! DATALEN are 1–9 ASCII digits, the command 1–32 ASCII letters, and a zero DATALEN is
//! followed directly by the LF trailer. Memory is one fixed buffer of the data limit plus
//! header room. A `syslog` frame that exceeds the limit is read past without buffering (at
//! most 999,999,999 bytes, within the caller's frame timeout) so the session can answer it as
//! a final drop instead of making the sender resend it forever; any other oversized or
//! malformed frame fails, and the caller closes the session. Every field separator must be
//! exactly one space.

use tokio::io::{AsyncRead, AsyncReadExt};

/// Stable RELP failure codes (C# `RelpFailures`). A failure ends the session; it is never
/// answered with an error code.
pub mod failures {
    pub const FRAME_INVALID: &str = "relp-frame-invalid";
    pub const FRAME_TRUNCATED: &str = "relp-frame-truncated";
    pub const DATA_TOO_LARGE: &str = "relp-data-too-large";
    pub const OFFERS_INVALID: &str = "relp-offers-invalid";
}

pub const MAXIMUM_DIGITS: usize = 9;
pub const MAXIMUM_COMMAND_LENGTH: usize = 32;
/// The only RELP protocol version (librelp's current version).
pub const VERSION: u32 = 0;
/// Largest `open` offer data Bower reads; librelp sends about 100 bytes.
pub const MAXIMUM_OFFER_BYTES: usize = 4_096;
pub const MAXIMUM_OFFER_NAME_LENGTH: usize = 32;
pub const MAXIMUM_OFFER_VALUE_LENGTH: usize = 255;
pub const MAXIMUM_OFFERS: usize = 16;
pub const MAXIMUM_OFFER_VALUES: usize = 16;
/// librelp wraps transaction numbers after 999,999,999 back to 1.
pub const MAXIMUM_TRANSACTION: u64 = 999_999_999;

// TXNR SP COMMAND SP DATALEN SP: 9 + 1 + 32 + 1 + 9 + 1, plus the trailer.
const HEADROOM: usize = 64;

/// The RELP commands Bower understands (C# `RelpCommand`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Unknown,
    Open,
    Syslog,
    Close,
    Response,
    ServerClose,
}

impl Command {
    fn from_name(name: &[u8]) -> Self {
        match name {
            b"syslog" => Self::Syslog,
            b"open" => Self::Open,
            b"close" => Self::Close,
            b"rsp" => Self::Response,
            b"serverclose" => Self::ServerClose,
            _ => Self::Unknown,
        }
    }
}

/// One read (C# `RelpFrameResult`). Data is valid until the next read.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    End,
    Failed(&'static str),
    Frame {
        transaction: u64,
        command: Command,
        data: &'a [u8],
        /// A `syslog` frame whose data exceeded the limit and was skipped.
        oversized: bool,
    },
}

pub struct RelpReader<R> {
    stream: R,
    maximum: usize,
    buffer: Vec<u8>,
    start: usize,
    end: usize,
}

impl<R: AsyncRead + Unpin> RelpReader<R> {
    pub fn new(stream: R, maximum_data_bytes: usize) -> Self {
        Self {
            stream,
            maximum: maximum_data_bytes,
            buffer: vec![0; maximum_data_bytes + HEADROOM],
            start: 0,
            end: 0,
        }
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.stream
    }

    /// Waits until the first byte of the next frame is buffered. `false` at the end of the
    /// stream. Cancel-safe: buffered bytes stay buffered.
    pub async fn wait_for_frame(&mut self) -> std::io::Result<bool> {
        while self.start == self.end {
            if !self.fill().await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub async fn read_frame(&mut self) -> std::io::Result<Frame<'_>> {
        if self.start == self.end && !self.fill().await? {
            return Ok(Frame::End);
        }
        let (transaction, digits) = match self.number(0).await? {
            Ok(number) => number,
            Err(failure) => return Ok(Frame::Failed(failure)),
        };
        match self.byte_at(digits).await? {
            None => return Ok(Frame::Failed(failures::FRAME_TRUNCATED)),
            Some(b' ') => {}
            Some(_) => return Ok(Frame::Failed(failures::FRAME_INVALID)),
        }
        let mut offset = digits + 1;
        let mut letters = 0;
        loop {
            let Some(value) = self.byte_at(offset + letters).await? else {
                return Ok(Frame::Failed(failures::FRAME_TRUNCATED));
            };
            if value == b' ' && letters > 0 {
                break;
            }
            letters += 1;
            if !value.is_ascii_alphabetic() || letters > MAXIMUM_COMMAND_LENGTH {
                return Ok(Frame::Failed(failures::FRAME_INVALID));
            }
        }
        let command =
            Command::from_name(&self.buffer[self.start + offset..self.start + offset + letters]);
        offset += letters + 1;
        let (length, digits) = match self.number(offset).await? {
            Ok(number) => number,
            Err(failure) => return Ok(Frame::Failed(failure)),
        };
        offset += digits;
        let Some(separator) = self.byte_at(offset).await? else {
            return Ok(Frame::Failed(failures::FRAME_TRUNCATED));
        };
        if length == 0 {
            if separator != b'\n' {
                return Ok(Frame::Failed(failures::FRAME_INVALID));
            }
            self.start += offset + 1;
            return Ok(Frame::Frame {
                transaction,
                command,
                data: &[],
                oversized: false,
            });
        }
        if separator != b' ' {
            return Ok(Frame::Failed(failures::FRAME_INVALID));
        }
        offset += 1;
        let length = usize::try_from(length).unwrap_or(usize::MAX);
        if length > self.maximum {
            return if command == Command::Syslog {
                self.skip(transaction, offset, length).await
            } else {
                Ok(Frame::Failed(failures::DATA_TOO_LARGE))
            };
        }
        match self.byte_at(offset + length).await? {
            None => return Ok(Frame::Failed(failures::FRAME_TRUNCATED)),
            Some(b'\n') => {}
            Some(_) => return Ok(Frame::Failed(failures::FRAME_INVALID)),
        }
        let from = self.start + offset;
        self.start += offset + length + 1;
        Ok(Frame::Frame {
            transaction,
            command,
            data: &self.buffer[from..from + length],
            oversized: false,
        })
    }

    /// 1–9 digits followed by a non-digit (left unread), as librelp accepts them.
    async fn number(
        &mut self,
        offset: usize,
    ) -> std::io::Result<Result<(u64, usize), &'static str>> {
        let mut value = 0u64;
        let mut digits = 0;
        loop {
            let Some(next) = self.byte_at(offset + digits).await? else {
                return Ok(Err(failures::FRAME_TRUNCATED));
            };
            if !next.is_ascii_digit() {
                break;
            }
            digits += 1;
            if digits > MAXIMUM_DIGITS {
                return Ok(Err(failures::FRAME_INVALID));
            }
            value = value * 10 + u64::from(next - b'0');
        }
        Ok(if digits == 0 {
            Err(failures::FRAME_INVALID)
        } else {
            Ok((value, digits))
        })
    }

    /// Reads past `length` data bytes and checks the trailer.
    async fn skip(
        &mut self,
        transaction: u64,
        offset: usize,
        length: usize,
    ) -> std::io::Result<Frame<'_>> {
        self.start += offset;
        let mut remaining = length;
        while remaining > 0 {
            if self.start == self.end && !self.fill().await? {
                return Ok(Frame::Failed(failures::FRAME_TRUNCATED));
            }
            let take = remaining.min(self.end - self.start);
            self.start += take;
            remaining -= take;
        }
        match self.byte_at(0).await? {
            None => return Ok(Frame::Failed(failures::FRAME_TRUNCATED)),
            Some(b'\n') => {}
            Some(_) => return Ok(Frame::Failed(failures::FRAME_INVALID)),
        }
        self.start += 1;
        Ok(Frame::Frame {
            transaction,
            command: Command::Syslog,
            data: &[],
            oversized: true,
        })
    }

    /// The byte `offset` past the frame start, reading more as needed; `None` at the end of
    /// the stream.
    async fn byte_at(&mut self, offset: usize) -> std::io::Result<Option<u8>> {
        while self.end - self.start <= offset {
            if !self.fill().await? {
                return Ok(None);
            }
        }
        Ok(Some(self.buffer[self.start + offset]))
    }

    /// Reads more bytes, compacting first. False at end of stream.
    async fn fill(&mut self) -> std::io::Result<bool> {
        if self.start > 0 && (self.end == self.buffer.len() || self.start == self.end) {
            self.buffer.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        if self.end == self.buffer.len() {
            // Callers check their bound before asking for more, so a full buffer is a bug.
            return Err(std::io::Error::other("RELP frame buffer is full"));
        }
        let read = self.stream.read(&mut self.buffer[self.end..]).await?;
        self.end += read;
        Ok(read > 0)
    }
}

/// The transaction number a client must use after `current`.
pub fn next(current: u64) -> u64 {
    if current >= MAXIMUM_TRANSACTION {
        1
    } else {
        current + 1
    }
}

/// Checks a client's `open` offers (C# `RelpProtocol.TryAcceptOffers`): `relp_version` must
/// be a non-negative integer and `commands` must include `syslog`. Unknown offers are
/// ignored, as librelp does. Names, values and counts are bounded.
pub fn accept_offers(data: &[u8]) -> Result<(), &'static str> {
    if data.len() > MAXIMUM_OFFER_BYTES {
        return Err(failures::OFFERS_INVALID);
    }
    let (mut version, mut syslog, mut offers) = (false, false, 0);
    for line in data.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        offers += 1;
        if offers > MAXIMUM_OFFERS {
            return Err(failures::OFFERS_INVALID);
        }
        let equals = line.iter().position(|byte| *byte == b'=');
        let name = equals.map_or(line, |index| &line[..index]);
        if name.is_empty() || name.len() > MAXIMUM_OFFER_NAME_LENGTH || !printable(name) {
            return Err(failures::OFFERS_INVALID);
        }
        let mut values: Vec<&[u8]> = Vec::new();
        if let Some(index) = equals {
            for value in line[index + 1..].split(|byte| *byte == b',') {
                if value.is_empty() {
                    continue;
                }
                if value.len() > MAXIMUM_OFFER_VALUE_LENGTH
                    || !printable(value)
                    || values.len() == MAXIMUM_OFFER_VALUES
                {
                    return Err(failures::OFFERS_INVALID);
                }
                values.push(value);
            }
        }
        match name {
            b"relp_version" => {
                if values.is_empty()
                    || !values
                        .iter()
                        .all(|value| value.len() <= 9 && value.iter().all(u8::is_ascii_digit))
                {
                    return Err(failures::OFFERS_INVALID);
                }
                version = true;
            }
            b"commands" => syslog |= values.iter().any(|value| *value == b"syslog"),
            _ => {}
        }
    }
    if version && syslog {
        Ok(())
    } else {
        Err(failures::OFFERS_INVALID)
    }
}

/// `TXNR rsp LEN 200 OK LF relp_version=0 LF relp_software=bower LF commands=syslog LF`.
pub fn open_accepted(transaction: u64) -> Vec<u8> {
    frame(
        transaction,
        "rsp",
        b"200 OK\nrelp_version=0\nrelp_software=bower\ncommands=syslog",
    )
}

/// The acknowledgement for a `syslog` transaction, sent only after a final durable decision.
pub fn acknowledge(transaction: u64) -> Vec<u8> {
    frame(transaction, "rsp", b"200 OK")
}

/// Refuses an `open`; the session closes after it. Never used for a `syslog` transaction.
pub fn open_refused(transaction: u64) -> Vec<u8> {
    frame(
        transaction,
        "rsp",
        b"500 required command not supported by client",
    )
}

/// The empty response to a client's `close`.
pub fn close_accepted(transaction: u64) -> Vec<u8> {
    frame(transaction, "rsp", b"")
}

/// The server's hint that it is closing (transaction 0, no response expected).
pub fn server_close() -> Vec<u8> {
    frame(0, "serverclose", b"")
}

fn frame(transaction: u64, command: &str, data: &[u8]) -> Vec<u8> {
    let mut frame = if data.is_empty() {
        format!("{transaction} {command} 0").into_bytes()
    } else {
        format!("{transaction} {command} {} ", data.len()).into_bytes()
    };
    frame.extend_from_slice(data);
    frame.push(b'\n');
    frame
}

fn printable(value: &[u8]) -> bool {
    value.iter().all(|byte| (b' '..=b'~').contains(byte))
}

/// Removes one trailing LF or CR LF (rsyslog templates end with LF), as LF framing does.
pub fn trim_line_ending(data: &[u8]) -> &[u8] {
    let mut length = data.len();
    if length > 0 && data[length - 1] == b'\n' {
        length -= 1;
        if length > 0 && data[length - 1] == b'\r' {
            length -= 1;
        }
    }
    &data[..length]
}
