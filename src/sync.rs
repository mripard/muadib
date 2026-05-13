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
use core::time::Duration;
use std::{
    ffi::OsStr,
    fs::{self, File, Permissions},
    io::{Read as _, Write as _},
    os::unix::{
        ffi::OsStrExt as _,
        fs::{MetadataExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
    time::SystemTime,
};

use log::{debug, warn};
use thiserror::Error;
use winnow::{
    Parser as _, Result as WResult,
    ascii::digit1,
    binary::{le_u32, length_take},
    combinator::{separated_pair, seq},
    token::take_until,
};

const PAYLOAD_SIZE_MAX_BYTES: usize = 64 * 1024;

const ID_LSTAT_V1: u32 = u32::from_le_bytes(*b"STAT");
const ID_DATA: u32 = u32::from_le_bytes(*b"DATA");
const ID_DONE: u32 = u32::from_le_bytes(*b"DONE");
const ID_FAIL: u32 = u32::from_le_bytes(*b"FAIL");
const ID_OKAY: u32 = u32::from_le_bytes(*b"OKAY");
const ID_RECV_V1: u32 = u32::from_le_bytes(*b"RECV");
const ID_SEND_V1: u32 = u32::from_le_bytes(*b"SEND");
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
    /// Send (push) a file to the device.
    SendV1 = ID_SEND_V1,
    /// End the sync session.
    Quit = ID_QUIT,
}

impl TryFrom<u32> for SyncPacketId {
    type Error = SyncCommandParsingError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            ID_LSTAT_V1 => Ok(Self::LstatV1),
            ID_RECV_V1 => Ok(Self::RecvV1),
            ID_SEND_V1 => Ok(Self::SendV1),
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
            Self::SendV1 => write!(f, "SEND"),
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
    /// File send request with the target path and mode.
    SendV1(&'a Path, u32),
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
        SyncPacketId::SendV1 => {
            let mut path_mode_bytes = length_take(le_u32).parse_next(input)?;
            let (path, mode) = separated_pair(
                take_until(1.., ",").map(|b| OsStr::from_bytes(b).as_ref()),
                ",",
                digit1.verify_map(|b| {
                    OsStr::from_bytes(b)
                        .to_str()
                        .and_then(|s| s.parse::<u32>().ok())
                }),
            )
            .parse_next(&mut path_mode_bytes)?;

            Ok(SyncPacket::SendV1(path, mode))
        }
        SyncPacketId::Quit => Ok(SyncPacket::Quit),
    }
}

/// Sync frame command IDs in host-to-device DATA/DONE frames.
#[repr(u32)]
pub(crate) enum SyncFrameRequestId {
    /// File data chunk.
    Data = ID_DATA,
    /// End of file transfer (`payload_len` carries the mtime).
    Done = ID_DONE,
}

impl TryFrom<u32> for SyncFrameRequestId {
    type Error = SyncCommandParsingError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            ID_DATA => Ok(Self::Data),
            ID_DONE => Ok(Self::Done),
            other => Err(SyncCommandParsingError(other)),
        }
    }
}

fn parse_sync_frame_id(input: &mut &[u8]) -> WResult<SyncFrameRequestId> {
    le_u32
        .verify_map(|v| SyncFrameRequestId::try_from(v).ok())
        .parse_next(input)
}

impl fmt::Display for SyncFrameRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data => write!(f, "DATA"),
            Self::Done => write!(f, "DONE"),
        }
    }
}

/// Parsed 8-byte header for host-to-device sync frames.
#[repr(C)]
struct SyncFrameRequestHeader {
    id: SyncFrameRequestId,
    payload_len: u32,
}

fn parse_sync_frame_header(input: &mut &[u8]) -> WResult<SyncFrameRequestHeader> {
    seq!(parse_sync_frame_id, le_u32)
        .map(|(i, l)| SyncFrameRequestHeader {
            id: i,
            payload_len: l,
        })
        .parse_next(input)
}

#[repr(u32)]
enum SyncFrameResponseId {
    Data = ID_DATA,
    Done = ID_DONE,
    Okay = ID_OKAY,
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
            Self::Okay => write!(f, "OKAY"),
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

/// Parsing state for an in-progress file receive.
#[derive(Debug, PartialEq)]
enum RecvState {
    Header,
    PartialHeader([u8; 8], usize),
    Data { remaining: usize },
}

/// Receives a file from the host during an `adb push` session.
pub(crate) struct FileReceiver {
    file: File,
    path: PathBuf,
    mode: Permissions,
    state: RecvState,
}

/// Outcome of feeding a WRTE payload into a `FileReceiver`.
pub(crate) enum FileReceiverResult<T> {
    /// Transfer complete — contains the sync response to send back.
    Done(T),
    /// More data expected — keep feeding WRTE payloads.
    Continue,
}

impl FileReceiver {
    /// Feeds a WRTE payload containing sync DATA or DONE frames.
    ///
    /// Returns `Continue` while data chunks are still expected, or
    /// `Done` with an OKAY/FAIL response when the transfer finishes.
    pub(crate) fn receive(&mut self, data: &[u8]) -> FileReceiverResult<SyncResponse> {
        let mut pos = 0;

        while pos < data.len() {
            match self.state {
                RecvState::Header => {
                    let Some(mut header_slice) =
                        data.get(pos..(pos + size_of::<SyncFrameRequestHeader>()))
                    else {
                        let rem = &data[pos..];
                        let mut buf = [0u8; size_of::<SyncFrameRequestHeader>()];
                        buf[..rem.len()].copy_from_slice(rem);

                        self.state = RecvState::PartialHeader(buf, rem.len());
                        return FileReceiverResult::Continue;
                    };

                    let Ok(header) = parse_sync_frame_header(&mut header_slice) else {
                        self.abort();
                        return FileReceiverResult::Done(fail_response(
                            "invalid sync frame during send",
                        ));
                    };

                    pos += size_of::<SyncFrameRequestHeader>();

                    match header.id {
                        SyncFrameRequestId::Data => {
                            self.state = RecvState::Data {
                                remaining: usize::try_from(header.payload_len)
                                    .expect("sync frame payload length fits in usize"),
                            };
                        }
                        SyncFrameRequestId::Done => return self.finalize(header.payload_len),
                    }
                }
                RecvState::PartialHeader(mut leftovers, mut leftovers_len) => {
                    let need = size_of::<SyncFrameRequestHeader>() - leftovers_len;

                    let Some(rem) = data.get(pos..(pos + need)) else {
                        let next = usize::min(need, data.len() - pos);

                        leftovers[leftovers_len..leftovers_len + next]
                            .copy_from_slice(&data[pos..pos + next]);
                        leftovers_len += next;

                        self.state = RecvState::PartialHeader(leftovers, leftovers_len);
                        return FileReceiverResult::Continue;
                    };

                    leftovers[leftovers_len..].copy_from_slice(rem);
                    pos += rem.len();

                    let Ok(header) = parse_sync_frame_header(&mut leftovers.as_ref()) else {
                        self.abort();
                        return FileReceiverResult::Done(fail_response(
                            "invalid sync frame during send",
                        ));
                    };

                    match header.id {
                        SyncFrameRequestId::Data => {
                            self.state = RecvState::Data {
                                remaining: usize::try_from(header.payload_len)
                                    .expect("sync frame payload length fits in usize"),
                            };
                        }
                        SyncFrameRequestId::Done => return self.finalize(header.payload_len),
                    }
                }
                RecvState::Data { mut remaining } => {
                    let to_write = usize::min(remaining, data.len() - pos);

                    if let Err(e) = self.file.write_all(&data[pos..pos + to_write]) {
                        self.abort();
                        return FileReceiverResult::Done(fail_response(&format!(
                            "write error for {}: {e}",
                            self.path.display()
                        )));
                    }

                    pos += to_write;
                    remaining -= to_write;

                    if remaining > 0 {
                        self.state = RecvState::Data { remaining };
                    } else {
                        self.state = RecvState::Header;
                    }
                }
            }
        }

        FileReceiverResult::Continue
    }

    fn finalize(&mut self, mtime: u32) -> FileReceiverResult<SyncResponse> {
        if let Err(e) = self.file.set_permissions(self.mode.clone()) {
            self.abort();
            return FileReceiverResult::Done(fail_response(&format!(
                "cannot set permissions on {}: {e}",
                self.path.display()
            )));
        }

        let mtime_system = SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(mtime));
        let times = fs::FileTimes::new().set_modified(mtime_system);
        if let Err(e) = self.file.set_times(times) {
            warn!("cannot set mtime on {}: {e}", self.path.display());
        }

        debug!(
            "SEND complete: {} mode={:#o} mtime={mtime}",
            self.path.display(),
            self.mode.mode()
        );

        FileReceiverResult::Done(okay_response())
    }

    fn abort(&self) {
        if let Err(e) = fs::remove_file(&self.path) {
            warn!("cannot remove {}: {e}", self.path.display());
        }
    }
}

/// Current state of a sync service session.
pub(crate) enum SyncState {
    /// Waiting for a command from the host.
    Idle,
    /// Streaming file data back to the host.
    Sending(FileSender),
    /// Receiving file data from the host.
    Receiving(FileReceiver),
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
        if let SyncState::Receiving(ref mut receiver) = self.state {
            match receiver.receive(data) {
                FileReceiverResult::Continue => return SyncResult::Continue,
                FileReceiverResult::Done((hdr, payload)) => {
                    self.state = SyncState::Idle;
                    return SyncResult::Data(hdr, payload);
                }
            }
        }

        let Ok(packet) = parse_sync_packet(&mut data) else {
            let (hdr, data) = fail_response("invalid sync request");
            return SyncResult::Data(hdr, data);
        };

        match packet {
            SyncPacket::LStatV1(p) => self.handle_lstat_v1(p),
            SyncPacket::RecvV1(p) => self.handle_recv_v1(p),
            SyncPacket::SendV1(p, m) => self.handle_send_v1(p, m, data),
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

    // The host packs DATA frames right after the SEND header in the
    // same WRTE payload, so `leftover` carries those first frames.
    fn handle_send_v1(&mut self, path: &Path, mode: u32, leftover: &[u8]) -> SyncResult {
        debug!("SEND {} mode={mode:#o}", path.display());

        let file = match File::create(path) {
            Ok(f) => f,
            Err(e) => {
                let (hdr, data) = fail_response(&format!("cannot create {}: {e}", path.display()));
                return SyncResult::Data(hdr, data);
            }
        };

        let mut receiver = FileReceiver {
            file,
            path: path.to_owned(),
            mode: Permissions::from_mode(mode),
            state: RecvState::Header,
        };

        if !leftover.is_empty() {
            match receiver.receive(leftover) {
                FileReceiverResult::Continue => {}
                FileReceiverResult::Done(response) => {
                    return SyncResult::Data(response.0, response.1);
                }
            }
        }

        self.state = SyncState::Receiving(receiver);
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

fn okay_response() -> (SyncFrameResponseHeader, Vec<u8>) {
    (
        SyncFrameResponseHeader {
            id: SyncFrameResponseId::Okay,
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
