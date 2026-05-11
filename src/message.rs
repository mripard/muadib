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

const A_VERSION_V0: u32 = 0x0100_0000;
const A_VERSION_V1: u32 = 0x0100_0001;

/// Error returned when parsing an unknown ADB protocol version.
#[derive(Debug, Error)]
#[error("Unknown Protocol version: {0:#010x}")]
pub(crate) struct ProtocolVersionError(u32);

/// ADB protocol version negotiated during the CNXN handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum ProtocolVersion {
    /// ADB protocol v0: requires payload checksums, max payload 4096 bytes.
    V0 = A_VERSION_V0,

    /// ADB protocol v1: skips payload checksums, max payload up to 1MB.
    V1 = A_VERSION_V1,
}

impl From<ProtocolVersion> for u32 {
    fn from(v: ProtocolVersion) -> Self {
        v as u32
    }
}

impl TryFrom<u32> for ProtocolVersion {
    type Error = ProtocolVersionError;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            A_VERSION_V0 => Ok(Self::V0),
            A_VERSION_V1 => Ok(Self::V1),
            other => Err(ProtocolVersionError(other)),
        }
    }
}

impl ProtocolVersion {
    /// Maximum payload size in bytes for this protocol version.
    pub(crate) const fn max_payload(self) -> u32 {
        match self {
            Self::V0 => 4096,
            Self::V1 => 1024 * 1024,
        }
    }

    /// Whether this version requires payload checksums.
    pub(crate) fn requires_checksum(self) -> bool {
        self == Self::V0
    }
}

/// The protocol version this daemon advertises during CNXN.
pub(crate) const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V1;

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

/// Builds an [`AdbHeader`] for a given command and payload.
pub(crate) fn header_from_payload(
    host_version: ProtocolVersion,
    command: Command,
    arg0: u32,
    arg1: u32,
    payload: &[u8],
) -> AdbHeader {
    let checksum = if host_version.requires_checksum() {
        checksum(payload)
    } else {
        0
    };

    AdbHeader {
        command,
        arg0,
        arg1,
        data_length: payload.len().try_into().expect(
            "The maximum payload that can be negotiated is 2^20 (1MB), way lower than u32::MAX",
        ),
        data_check: checksum,
        magic: u32::from(command) ^ 0xffff_ffff,
    }
}

/// Builds a CNXN header advertising our protocol version and max payload.
pub(crate) fn cnxn_header(host_version: ProtocolVersion, payload: &[u8]) -> AdbHeader {
    header_from_payload(
        host_version,
        Command::Cnxn,
        PROTOCOL_VERSION.into(),
        PROTOCOL_VERSION.max_payload(),
        payload,
    )
}

/// Builds an OKAY header: `arg0`=`local_id`, `arg1`=`remote_id`.
pub(crate) fn okay_header(peer: ProtocolVersion, local_id: u32, remote_id: u32) -> AdbHeader {
    header_from_payload(peer, Command::Okay, local_id, remote_id, &[])
}

/// Builds a WRTE header: `arg0`=`local_id`, `arg1`=`remote_id`.
pub(crate) fn wrte_header(
    peer: ProtocolVersion,
    local_id: u32,
    remote_id: u32,
    payload: &[u8],
) -> AdbHeader {
    header_from_payload(peer, Command::Wrte, local_id, remote_id, payload)
}

/// Builds a CLSE header: `arg0`=`local_id`, `arg1`=`remote_id`.
pub(crate) fn clse_header(peer: ProtocolVersion, local_id: u32, remote_id: u32) -> AdbHeader {
    header_from_payload(peer, Command::Clse, local_id, remote_id, &[])
}

/// Builds a complete CNXN response (header + system identity payload).
pub(crate) fn cnxn_response(
    peer: ProtocolVersion,
    info: &crate::device_info::DeviceInfo,
) -> (AdbHeader, Vec<u8>) {
    let payload = format!(
        "device::ro.product.name={};ro.product.model={};ro.product.device={};\0",
        info.name, info.model, info.device,
    )
    .into_bytes();

    (cnxn_header(peer, &payload), payload)
}
