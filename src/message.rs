//! ADB protocol message parsing and construction.

use core::fmt;

use thiserror::Error;
use winnow::{Parser as _, Result as WResult, binary::le_u32, combinator::seq};

const A_CNXN: u32 = 0x4e58_4e43;
const A_AUTH: u32 = 0x4854_5541;
const A_OPEN: u32 = 0x4e45_504f;
const A_OKAY: u32 = 0x5941_4b4f;
const A_CLSE: u32 = 0x4553_4c43;
const A_WRTE: u32 = 0x4554_5257;
const A_STLS: u32 = 0x534c_5453;

/// Error returned when parsing an unknown ADB command value.
#[derive(Debug, Error)]
#[error("Unknown Command: {0:#010x}")]
pub(crate) struct CommandParsingError(u32);

/// ADB protocol command identifiers.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    /// Connection handshake: `arg0`=version, `arg1`=`max_payload`, payload=system identity.
    Cnxn = A_CNXN,
    /// Authentication challenge/response.
    Auth = A_AUTH,
    /// Open a new stream: `arg0`=`local_id`, payload=destination.
    Open = A_OPEN,
    /// Stream ready for data: `arg0`=`local_id`, `arg1`=`remote_id`.
    Okay = A_OKAY,
    /// Close a stream: `arg0`=`local_id`, `arg1`=`remote_id`.
    Clse = A_CLSE,
    /// Write data to a stream: `arg0`=`local_id`, `arg1`=`remote_id`.
    Wrte = A_WRTE,
    /// Start TLS handshake.
    Stls = A_STLS,
}

impl TryFrom<u32> for Command {
    type Error = CommandParsingError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            A_CNXN => Ok(Self::Cnxn),
            A_AUTH => Ok(Self::Auth),
            A_OPEN => Ok(Self::Open),
            A_OKAY => Ok(Self::Okay),
            A_CLSE => Ok(Self::Clse),
            A_WRTE => Ok(Self::Wrte),
            A_STLS => Ok(Self::Stls),
            other => Err(CommandParsingError(other)),
        }
    }
}

impl From<Command> for u32 {
    fn from(value: Command) -> Self {
        value as u32
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cnxn => write!(f, "CNXN"),
            Self::Auth => write!(f, "AUTH"),
            Self::Open => write!(f, "OPEN"),
            Self::Okay => write!(f, "OKAY"),
            Self::Clse => write!(f, "CLSE"),
            Self::Wrte => write!(f, "WRTE"),
            Self::Stls => write!(f, "STLS"),
        }
    }
}

/// Parsed ADB message header (24 bytes on the wire).
#[repr(C)]
#[derive(Debug)]
pub(crate) struct AdbHeader {
    /// The command identifier.
    pub command: Command,
    /// First argument (meaning depends on command).
    pub arg0: u32,
    /// Second argument (meaning depends on command).
    pub arg1: u32,
    /// Length of the payload that follows, in bytes.
    pub data_length: u32,
    /// Checksum of the payload (sum of all bytes as `u32`).
    pub data_check: u32,
    /// Bitwise inverse of the command word.
    pub magic: u32,
}

/// Computes the ADB payload checksum (sum of all bytes).
pub(crate) fn checksum(data: &[u8]) -> u32 {
    data.iter().map(|&b| u32::from(b)).sum()
}

fn parse_command(input: &mut &[u8]) -> WResult<Command> {
    le_u32
        .verify_map(|v| Command::try_from(v).ok())
        .parse_next(input)
}

/// Parses a 24-byte ADB header from a byte slice.
///
/// # Errors
///
/// Returns an error if the slice is too short, contains an unknown command,
/// or fails the magic check.
pub(crate) fn parse_header(input: &mut &[u8]) -> WResult<AdbHeader> {
    seq!(parse_command, le_u32, le_u32, le_u32, le_u32, le_u32)
        .verify_map(|(command, arg0, arg1, data_length, data_check, magic)| {
            if magic != u32::from(command) ^ 0xffff_ffff {
                return None;
            }

            Some(AdbHeader {
                command,
                arg0,
                arg1,
                data_length,
                data_check,
                magic,
            })
        })
        .parse_next(input)
}
