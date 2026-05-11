//! ADB sync protocol service (file transfer).
//!
//! The sync protocol runs as a sub-protocol inside an ADB stream opened
//! with destination `sync:`. Sync messages are carried in WRTE payloads
//! and consist of an 8-byte header (id + length, both `u32` LE)
//! optionally followed by `length` bytes of data.
//!
//! ```text
//! adb pull:
//!   LSTAT_V1(path)        -> STAT(mode, size, mtime)
//!   RECV_V1(path)         -> DATA(chunk)* DONE
//!   QUIT                  -> (stream closed)
//!
//! adb push:
//!   SEND_V1(path,mode)    -> (wait for data)
//!   DATA(chunk)*          -> (written to file)
//!   DONE(mtime)           -> OKAY
//! ```
//!
//! Errors at any point are reported as FAIL messages containing a
//! human-readable error string.

use alloc::fmt;
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::Read as _,
    os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _},
    path::Path,
};

use log::debug;
use thiserror::Error;
use winnow::{
    Parser as _, Result as WResult,
    binary::{le_u32, length_take},
};

const PAYLOAD_SIZE_MAX_BYTES: usize = 64 * 1024;

const ID_LSTAT_V1: u32 = u32::from_le_bytes(*b"STAT");
const ID_DATA: u32 = u32::from_le_bytes(*b"DATA");
const ID_DONE: u32 = u32::from_le_bytes(*b"DONE");
const ID_FAIL: u32 = u32::from_le_bytes(*b"FAIL");
const ID_RECV_V1: u32 = u32::from_le_bytes(*b"RECV");
const ID_QUIT: u32 = u32::from_le_bytes(*b"QUIT");

/// Error returned when parsing an unknown sync command value.
#[derive(Debug, Error)]
#[error("Unknown Sync Command: {0:#010x}")]
pub(crate) struct SyncCommandParsingError(u32);

/// Sync protocol command identifiers.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncPacketId {
    /// Stat a file path.
    LstatV1 = ID_LSTAT_V1,
    /// Receive (pull) a file from the device.
    RecvV1 = ID_RECV_V1,
    /// End the sync session.
    Quit = ID_QUIT,
}

impl TryFrom<u32> for SyncPacketId {
    type Error = SyncCommandParsingError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            ID_LSTAT_V1 => Ok(Self::LstatV1),
            ID_RECV_V1 => Ok(Self::RecvV1),
            ID_QUIT => Ok(Self::Quit),
            other => Err(SyncCommandParsingError(other)),
        }
    }
}

impl fmt::Display for SyncPacketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LstatV1 => write!(f, "STAT"),
            Self::RecvV1 => write!(f, "RECV"),
            Self::Quit => write!(f, "QUIT"),
        }
    }
}

fn parse_sync_packet_id(input: &mut &[u8]) -> WResult<SyncPacketId> {
    le_u32
        .verify_map(|v| SyncPacketId::try_from(v).ok())
        .parse_next(input)
}

/// A parsed sync request from the host.
pub(crate) enum SyncPacket<'a> {
    /// Stat request with the target path.
    LStatV1(&'a Path),
    /// File receive request with the target path.
    RecvV1(&'a Path),
    /// End the sync session.
    Quit,
}

fn parse_sync_packet<'a>(input: &mut &'a [u8]) -> WResult<SyncPacket<'a>> {
    match parse_sync_packet_id(input)? {
        SyncPacketId::LstatV1 => {
            let path = length_take(le_u32)
                .map(|b| OsStr::from_bytes(b).as_ref())
                .parse_next(input)?;

            Ok(SyncPacket::LStatV1(path))
        }
        SyncPacketId::RecvV1 => {
            let path = length_take(le_u32)
                .map(|b| OsStr::from_bytes(b).as_ref())
                .parse_next(input)?;

            Ok(SyncPacket::RecvV1(path))
        }
        SyncPacketId::Quit => Ok(SyncPacket::Quit),
    }
}

#[repr(u32)]
enum SyncFrameResponseId {
    Data = ID_DATA,
    Done = ID_DONE,
    Fail = ID_FAIL,
}

impl TryFrom<u32> for SyncFrameResponseId {
    type Error = SyncCommandParsingError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            ID_DATA => Ok(Self::Data),
            ID_DONE => Ok(Self::Done),
            other => Err(SyncCommandParsingError(other)),
        }
    }
}

impl fmt::Display for SyncFrameResponseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data => write!(f, "DATA"),
            Self::Done => write!(f, "DONE"),
            Self::Fail => write!(f, "FAIL"),
        }
    }
}

/// 8-byte header for DATA/DONE/OKAY/FAIL sync response frames.
#[repr(C)]
pub(crate) struct SyncFrameResponseHeader {
    id: SyncFrameResponseId,
    payload_len: u32,
}

/// `LSTAT_V1` response: fixed 16-byte struct sent as a single write.
#[repr(C)]
pub(crate) struct SyncStat {
    /// Sync command ID (always `LSTAT_V1`).
    pub id: u32,
    /// File mode bits.
    pub mode: u32,
    /// File size in bytes.
    pub size: u32,
    /// Last modification time as a Unix timestamp.
    pub mtime: u32,
}

type SyncResponse = (SyncFrameResponseHeader, Vec<u8>);

/// Result of processing a single sync request from the host.
pub(crate) enum SyncResult {
    /// `LSTAT_V1` response: fixed 16-byte stat result.
    Stat(SyncStat),
    /// A DATA/DONE/FAIL response: fixed header + variable payload.
    Data(SyncFrameResponseHeader, Vec<u8>),
    /// No response needed yet; more data expected.
    Continue,
    /// The host sent QUIT; the stream should be closed.
    Quit,
}

/// Streams a file back to the host as framed sync DATA messages.
pub(crate) struct FileSender {
    file: File,
    done: bool,
}

impl FileSender {
    /// Returns the next DATA chunk, a DONE message at EOF, or `None`
    /// once the transfer is complete.
    pub(crate) fn next_frame(&mut self) -> Option<SyncResponse> {
        if self.done {
            return None;
        }

        let mut buf = vec![0u8; PAYLOAD_SIZE_MAX_BYTES];
        let n = match self.file.read(&mut buf) {
            Ok(0) => {
                self.done = true;
                return Some(done_response());
            }
            Ok(n) => n,
            Err(e) => {
                self.done = true;
                return Some(fail_response(&format!("read error: {e}")));
            }
        };

        Some(data_response(&buf[..n]))
    }
}

/// Current state of a sync service session.
pub(crate) enum SyncState {
    /// Waiting for a command from the host.
    Idle,
    /// Streaming file data back to the host.
    Sending(FileSender),
}

/// Handles sync protocol requests within an ADB stream.
pub(crate) struct SyncService {
    /// Current session state.
    pub state: SyncState,
}

impl SyncService {
    /// Creates a new sync service in the idle state.
    pub(crate) fn new() -> Self {
        SyncService {
            state: SyncState::Idle,
        }
    }

    /// Parses a sync request from a WRTE payload and dispatches it.
    pub(crate) fn handle(&mut self, mut data: &[u8]) -> SyncResult {
        let Ok(packet) = parse_sync_packet(&mut data) else {
            let (hdr, data) = fail_response("invalid sync request");
            return SyncResult::Data(hdr, data);
        };

        match packet {
            SyncPacket::LStatV1(p) => self.handle_lstat_v1(p),
            SyncPacket::RecvV1(p) => self.handle_recv_v1(p),
            SyncPacket::Quit => SyncResult::Quit,
        }
    }

    #[expect(
        clippy::unused_self,
        reason = "Keeps consistent signature with the other handlers"
    )]
    fn handle_lstat_v1(&self, path: &Path) -> SyncResult {
        debug!("LSTAT {}", path.display());

        let (mode, size, mtime) = match fs::symlink_metadata(path) {
            Ok(meta) => (
                meta.mode(),
                meta.size().try_into().expect("File too large for 32-bits"),
                meta.mtime()
                    .try_into()
                    .expect("File modified in 2038 or after"),
            ),
            Err(_) => (0, 0, 0),
        };

        SyncResult::Stat(SyncStat {
            id: ID_LSTAT_V1,
            mode,
            size,
            mtime,
        })
    }

    fn handle_recv_v1(&mut self, path: &Path) -> SyncResult {
        debug!("RECV {}", path.display());

        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                let (hdr, data) = fail_response(&format!("cannot open {}: {e}", path.display()));
                return SyncResult::Data(hdr, data);
            }
        };

        self.state = SyncState::Sending(FileSender { file, done: false });
        SyncResult::Continue
    }
}

fn data_response(data: &[u8]) -> (SyncFrameResponseHeader, Vec<u8>) {
    (
        SyncFrameResponseHeader {
            id: SyncFrameResponseId::Data,
            payload_len: data
                .len()
                .try_into()
                .expect("DATA responses can fit at most 64kB, well below 2^32"),
        },
        data.to_vec(),
    )
}

fn done_response() -> (SyncFrameResponseHeader, Vec<u8>) {
    (
        SyncFrameResponseHeader {
            id: SyncFrameResponseId::Done,
            payload_len: 0,
        },
        Vec::new(),
    )
}

fn fail_response(msg: &str) -> (SyncFrameResponseHeader, Vec<u8>) {
    let bytes = msg.as_bytes();
    (
        SyncFrameResponseHeader {
            id: SyncFrameResponseId::Fail,
            payload_len: bytes
                .len()
                .try_into()
                .expect("Our maximum data buffer size is 1MB, well below 2^32."),
        },
        bytes.to_vec(),
    )
}
