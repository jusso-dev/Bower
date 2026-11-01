//! RFC 6587 framing over a byte stream (C# `SyslogFrameReader`): octet counting when a
//! frame starts with a digit, LF framing when it starts with `<`. One fixed buffer of the
//! maximum message size bounds memory; framing errors close the connection.

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::parser::failures::{
    FRAME_TOO_LARGE, FRAME_TRUNCATED, FRAMING_INVALID, OCTET_COUNT_INVALID,
};

/// MSG-LEN digits and the separating SP fit in this headroom for any allowed maximum.
const HEADROOM: usize = 8;

pub struct FrameReader<R> {
    stream: R,
    maximum: usize,
    buffer: Vec<u8>,
    start: usize,
    end: usize,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(stream: R, maximum_message_bytes: usize) -> Self {
        Self {
            stream,
            maximum: maximum_message_bytes,
            buffer: vec![0; maximum_message_bytes + HEADROOM],
            start: 0,
            end: 0,
        }
    }

    pub fn into_inner(self) -> R {
        self.stream
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.stream
    }

    /// Waits until the first byte of the next frame is buffered, skipping blank lines, so a
    /// caller can time an idle connection separately from a frame in progress. `false` at
    /// the end of the stream. Cancel-safe: buffered bytes stay buffered.
    pub async fn wait_for_frame(&mut self) -> std::io::Result<bool> {
        loop {
            while self.start < self.end && matches!(self.buffer[self.start], b'\n' | b'\r') {
                self.start += 1;
            }
            if self.start < self.end {
                return Ok(true);
            }
            if !self.fill().await? {
                return Ok(false);
            }
        }
    }

    /// `Ok(None)` at the end of the stream; `Err(code)` on a framing failure. The frame is
    /// valid until the next read.
    pub async fn read_frame(&mut self) -> std::io::Result<Result<Option<&[u8]>, &'static str>> {
        // Blank lines between frames (trailing CR LF from some senders) are not frames.
        loop {
            if self.start == self.end && !self.fill().await? {
                return Ok(Ok(None));
            }
            if !matches!(self.buffer[self.start], b'\n' | b'\r') {
                break;
            }
            self.start += 1;
        }
        match self.buffer[self.start] {
            b'1'..=b'9' => self.read_octet_counted().await,
            b'<' => self.read_delimited().await,
            _ => Ok(Err(FRAMING_INVALID)),
        }
    }

    async fn read_octet_counted(&mut self) -> std::io::Result<Result<Option<&[u8]>, &'static str>> {
        let mut digits = 0;
        let mut length = 0usize;
        loop {
            if self.start + digits == self.end && !self.fill().await? {
                return Ok(Err(FRAME_TRUNCATED));
            }
            let value = self.buffer[self.start + digits];
            if value == b' ' {
                break;
            }
            if !value.is_ascii_digit() {
                return Ok(Err(OCTET_COUNT_INVALID));
            }
            digits += 1;
            length = length * 10 + usize::from(value - b'0');
            if length > self.maximum {
                return Ok(Err(FRAME_TOO_LARGE));
            }
        }
        let total = digits + 1 + length;
        while self.end - self.start < total {
            if !self.fill().await? {
                return Ok(Err(FRAME_TRUNCATED));
            }
        }
        let from = self.start + digits + 1;
        self.start += total;
        Ok(Ok(Some(&self.buffer[from..from + length])))
    }

    async fn read_delimited(&mut self) -> std::io::Result<Result<Option<&[u8]>, &'static str>> {
        let mut scanned = self.start;
        loop {
            if let Some(index) = self.buffer[scanned..self.end]
                .iter()
                .position(|byte| *byte == b'\n')
            {
                let newline = scanned + index;
                let mut length = newline - self.start;
                if length > 0 && self.buffer[newline - 1] == b'\r' {
                    length -= 1;
                }
                if length > self.maximum {
                    return Ok(Err(FRAME_TOO_LARGE));
                }
                let from = self.start;
                self.start = newline + 1;
                return Ok(Ok(Some(&self.buffer[from..from + length])));
            }
            // Allow one byte past the maximum for a CR before the LF.
            if self.end - self.start > self.maximum + 1 {
                return Ok(Err(FRAME_TOO_LARGE));
            }
            let buffered = self.end - self.start;
            if !self.fill().await? {
                return Ok(Err(FRAME_TRUNCATED));
            }
            scanned = self.start + buffered;
        }
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
            return Err(std::io::Error::other("syslog frame buffer is full"));
        }
        let read = self.stream.read(&mut self.buffer[self.end..]).await?;
        self.end += read;
        Ok(read > 0)
    }
}
