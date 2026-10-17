//! Minimal, bounded ZIP reader and writer for `.bowerpack` archives.
//!
//! Only what `System.IO.Compression.ZipArchive` produces for packs is supported:
//! stored or deflated entries, no encryption, no ZIP64, single disk. Sizes come from
//! the central directory; inflation is capped and checked against the declared size
//! and CRC-32, so a lying header cannot expand past the per-file limit.

use std::io::{Read, Write};

use flate2::Crc;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;

const LOCAL_HEADER: u32 = 0x0403_4b50;
const CENTRAL_HEADER: u32 = 0x0201_4b50;
const END_OF_CENTRAL_DIRECTORY: u32 = 0x0605_4b50;
const EOCD_LENGTH: usize = 22;
const MAXIMUM_COMMENT: usize = u16::MAX as usize;
const STORED: u16 = 0;
const DEFLATED: u16 = 8;
const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_UTF8: u16 = 0x0800;
/// MS-DOS date for 2020-01-01 (the fixed timestamp the C# builder writes).
const FIXED_DOS_DATE: u16 = ((2020 - 1980) << 9) | (1 << 5) | 1;

/// One central-directory entry, not yet read.
#[derive(Clone, Debug)]
pub(crate) struct ZipEntry {
    pub name: String,
    flags: u16,
    method: u16,
    crc32: u32,
    compressed_size: u64,
    /// Declared uncompressed size (C# `ZipArchiveEntry.Length`).
    pub length: u64,
    local_header_offset: u64,
}

/// Structural failure with the `System.IO.Compression` message for the same
/// problem. Never echoes archive bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipError(pub &'static str);

impl std::fmt::Display for ZipError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

const NO_EOCD: ZipError = ZipError("End of Central Directory record could not be found.");
const CORRUPT_DIRECTORY: ZipError = ZipError("Central Directory corrupt.");
const CORRUPT_LOCAL_HEADER: ZipError = ZipError("A local file header is corrupt.");
const UNSUPPORTED_METHOD: ZipError =
    ZipError("The archive entry was compressed using an unsupported compression method.");
const CORRUPT_ENTRY: ZipError = ZipError("The archive entry is corrupt.");

/// Every file entry (directories skipped) with its content, each capped at `limit`
/// bytes. For tools and tests; [`crate::load`] applies the full pack rules.
pub fn read_all(archive: &[u8], limit: u64) -> Result<Vec<(String, Vec<u8>)>, ZipError> {
    entries(archive)?
        .iter()
        .filter(|entry| !entry.name.ends_with('/'))
        .map(|entry| Ok((entry.name.clone(), read(archive, entry, limit)?)))
        .collect()
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, ZipError> {
    bytes
        .get(offset..offset + 2)
        .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
        .ok_or(CORRUPT_DIRECTORY)
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, ZipError> {
    bytes
        .get(offset..offset + 4)
        .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
        .ok_or(CORRUPT_DIRECTORY)
}

/// The central directory (`ZipArchive.Entries`) in archive order.
pub(crate) fn entries(archive: &[u8]) -> Result<Vec<ZipEntry>, ZipError> {
    let search_start = archive.len().saturating_sub(EOCD_LENGTH + MAXIMUM_COMMENT);
    let eocd = (search_start..=archive.len().saturating_sub(EOCD_LENGTH))
        .rev()
        .find(|&offset| u32_at(archive, offset) == Ok(END_OF_CENTRAL_DIRECTORY))
        .ok_or(NO_EOCD)?;
    let disk = u16_at(archive, eocd + 4)?;
    let directory_disk = u16_at(archive, eocd + 6)?;
    let count_on_disk = u16_at(archive, eocd + 8)?;
    let count = u16_at(archive, eocd + 10)?;
    let directory_size = u32_at(archive, eocd + 12)?;
    let directory_offset = u32_at(archive, eocd + 16)?;
    if disk != 0
        || directory_disk != 0
        || count_on_disk != count
        || count == u16::MAX
        || directory_size == u32::MAX
        || directory_offset == u32::MAX
    {
        // Multi-disk or ZIP64: never produced for packs.
        return Err(CORRUPT_DIRECTORY);
    }

    let mut offset = directory_offset as usize;
    let end = offset
        .checked_add(directory_size as usize)
        .ok_or(CORRUPT_DIRECTORY)?;
    if end > eocd {
        return Err(CORRUPT_DIRECTORY);
    }
    let mut entries = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        if u32_at(archive, offset)? != CENTRAL_HEADER {
            return Err(CORRUPT_DIRECTORY);
        }
        let flags = u16_at(archive, offset + 8)?;
        let method = u16_at(archive, offset + 10)?;
        let crc32 = u32_at(archive, offset + 16)?;
        let compressed_size = u32_at(archive, offset + 20)?;
        let length = u32_at(archive, offset + 24)?;
        let name_length = usize::from(u16_at(archive, offset + 28)?);
        let extra_length = usize::from(u16_at(archive, offset + 30)?);
        let comment_length = usize::from(u16_at(archive, offset + 32)?);
        let local_header_offset = u32_at(archive, offset + 42)?;
        if compressed_size == u32::MAX || length == u32::MAX || local_header_offset == u32::MAX {
            return Err(CORRUPT_DIRECTORY);
        }
        let name_start = offset + 46;
        let name = archive
            .get(name_start..name_start + name_length)
            .ok_or(CORRUPT_DIRECTORY)?;
        entries.push(ZipEntry {
            // Non-UTF-8 (CP437) names never pass the pack entry-name allow-list, so
            // lossy decoding cannot let an unsafe name through.
            name: String::from_utf8_lossy(name).into_owned(),
            flags,
            method,
            crc32,
            compressed_size: u64::from(compressed_size),
            length: u64::from(length),
            local_header_offset: u64::from(local_header_offset),
        });
        offset = name_start + name_length + extra_length + comment_length;
        if offset > end {
            return Err(CORRUPT_DIRECTORY);
        }
    }
    Ok(entries)
}

/// Reads one entry's content; fails when it is encrypted, uses another method,
/// inflates past `limit`, or does not match its declared size and CRC-32.
pub(crate) fn read(archive: &[u8], entry: &ZipEntry, limit: u64) -> Result<Vec<u8>, ZipError> {
    if entry.length > limit {
        return Err(CORRUPT_ENTRY);
    }
    if entry.flags & FLAG_ENCRYPTED != 0 {
        return Err(UNSUPPORTED_METHOD);
    }
    let header = usize::try_from(entry.local_header_offset).map_err(|_| CORRUPT_LOCAL_HEADER)?;
    if u32_at(archive, header).map_err(|_| CORRUPT_LOCAL_HEADER)? != LOCAL_HEADER {
        return Err(CORRUPT_LOCAL_HEADER);
    }
    let name_length = usize::from(u16_at(archive, header + 26).map_err(|_| CORRUPT_LOCAL_HEADER)?);
    let extra_length = usize::from(u16_at(archive, header + 28).map_err(|_| CORRUPT_LOCAL_HEADER)?);
    let start = header + 30 + name_length + extra_length;
    let compressed_end = start
        .checked_add(usize::try_from(entry.compressed_size).map_err(|_| CORRUPT_LOCAL_HEADER)?)
        .ok_or(CORRUPT_LOCAL_HEADER)?;
    let compressed = archive
        .get(start..compressed_end)
        .ok_or(CORRUPT_LOCAL_HEADER)?;

    let content = match entry.method {
        STORED => compressed.to_vec(),
        DEFLATED => {
            let mut content = Vec::new();
            DeflateDecoder::new(compressed)
                .take(entry.length + 1)
                .read_to_end(&mut content)
                .map_err(|_| CORRUPT_ENTRY)?;
            content
        }
        _ => return Err(UNSUPPORTED_METHOD),
    };
    let mut crc = Crc::new();
    crc.update(&content);
    if content.len() as u64 != entry.length || crc.sum() != entry.crc32 {
        return Err(CORRUPT_ENTRY);
    }
    Ok(content)
}

/// Writes a deflated archive with the fixed 2020-01-01 timestamp, so identical
/// content gives identical archives.
pub fn write(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut archive = Vec::new();
    let mut directory = Vec::new();
    for (name, content) in files {
        let mut encoder = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(content)
            .expect("in-memory deflate cannot fail");
        let compressed = encoder.finish().expect("in-memory deflate cannot fail");
        let mut crc = Crc::new();
        crc.update(content);
        let flags = if name.is_ascii() { 0 } else { FLAG_UTF8 };
        let offset =
            u32::try_from(archive.len()).expect("pack archives are bounded far below 4 GiB");
        let compressed_size = u32::try_from(compressed.len()).expect("pack files are bounded");
        let length = u32::try_from(content.len()).expect("pack files are bounded");
        let name_length = u16::try_from(name.len()).expect("pack paths are short");

        // Shared fields of the local and central headers, from "version needed".
        let mut common = Vec::with_capacity(26);
        common.extend_from_slice(&20u16.to_le_bytes());
        common.extend_from_slice(&flags.to_le_bytes());
        common.extend_from_slice(&DEFLATED.to_le_bytes());
        common.extend_from_slice(&0u16.to_le_bytes());
        common.extend_from_slice(&FIXED_DOS_DATE.to_le_bytes());
        common.extend_from_slice(&crc.sum().to_le_bytes());
        common.extend_from_slice(&compressed_size.to_le_bytes());
        common.extend_from_slice(&length.to_le_bytes());
        common.extend_from_slice(&name_length.to_le_bytes());
        common.extend_from_slice(&0u16.to_le_bytes());

        archive.extend_from_slice(&LOCAL_HEADER.to_le_bytes());
        archive.extend_from_slice(&common);
        archive.extend_from_slice(name.as_bytes());
        archive.extend_from_slice(&compressed);

        directory.extend_from_slice(&CENTRAL_HEADER.to_le_bytes());
        directory.extend_from_slice(&20u16.to_le_bytes());
        directory.extend_from_slice(&common);
        directory.extend_from_slice(&[0; 10]); // comment length, disk, internal and external attributes
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
    }
    let directory_offset = u32::try_from(archive.len()).expect("pack archives are bounded");
    let directory_size = u32::try_from(directory.len()).expect("pack archives are bounded");
    let count = u16::try_from(files.len()).expect("pack entry count is bounded");
    archive.extend_from_slice(&directory);
    archive.extend_from_slice(&END_OF_CENTRAL_DIRECTORY.to_le_bytes());
    archive.extend_from_slice(&[0; 4]);
    archive.extend_from_slice(&count.to_le_bytes());
    archive.extend_from_slice(&count.to_le_bytes());
    archive.extend_from_slice(&directory_size.to_le_bytes());
    archive.extend_from_slice(&directory_offset.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_corruption() {
        let files = vec![
            ("a.txt".to_owned(), b"hello hello hello".to_vec()),
            ("b/c".to_owned(), Vec::new()),
        ];
        let archive = write(&files);
        let listed = entries(&archive).unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["a.txt", "b/c"]
        );
        assert_eq!(
            read(&archive, &listed[0], 100).unwrap(),
            b"hello hello hello"
        );
        assert_eq!(read(&archive, &listed[1], 100).unwrap(), b"");
        // Over the limit.
        assert_eq!(read(&archive, &listed[0], 4), Err(CORRUPT_ENTRY));
        // Lying declared size: inflation is capped and the size check fails.
        let mut lying = listed[0].clone();
        lying.length = 3;
        assert_eq!(read(&archive, &lying, 100), Err(CORRUPT_ENTRY));
        // Bad CRC.
        let mut bad_crc = listed[0].clone();
        bad_crc.crc32 ^= 1;
        assert_eq!(read(&archive, &bad_crc, 100), Err(CORRUPT_ENTRY));
        // Truncated archive.
        assert!(entries(&archive[..archive.len() - 1]).is_err());
        assert_eq!(entries(b"not a zip").unwrap_err(), NO_EOCD);
    }
}
