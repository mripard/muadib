#![doc = include_str!("../README.md")]

use core::num::NonZeroU32;
use std::{
    env, io,
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd},
};

use clap::{Parser, Subcommand};
use io_uring::{IoUring, SubmissionQueue, opcode, types::Fd};
use log::{debug, error, info, warn};
use thiserror::Error;

mod buffers;
mod device_info;
mod ffs;
mod message;
mod usb;

use crate::{
    buffers::BufferManager,
    ffs::{UsbFunctionFsEventType, bind_udc, read_next_ffs_event_type, setup_gadget, unbind_udc},
    message::ProtocolVersion,
    usb::AsLittleEndianBytes as _,
};

#[derive(Debug, Error)]
#[error("Unknown IO Uring User Op Type {0}")]
struct UserDataOpTypeError(u32);

/// Our IO Uring operation enum
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
enum UserDataOpType {
    /// We queue an epoll on ep0
    Ep0Poll = 1,

    /// We queue a Header Read on `bulk_out`
    BulkOutReadHeader,

    /// We queue a Payload Read on `bulk_out`
    BulkOutReadPayload,

    /// We queue a write on `bulk_in`
    BulkInWrite,
}

impl TryFrom<u32> for UserDataOpType {
    type Error = UserDataOpTypeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ep0Poll),
            2 => Ok(Self::BulkOutReadHeader),
            3 => Ok(Self::BulkOutReadPayload),
            4 => Ok(Self::BulkInWrite),
            other => Err(UserDataOpTypeError(other)),
        }
    }
}

impl From<UserDataOpType> for u32 {
    fn from(value: UserDataOpType) -> Self {
        value as u32
    }
}

/// Our `io_uring` user data type
struct UserData {
    op_type: UserDataOpType,
    data: Option<NonZeroU32>,
}

impl UserData {
    fn new(op_type: UserDataOpType, data: Option<NonZeroU32>) -> Self {
        Self { op_type, data }
    }

    fn op_type(&self) -> UserDataOpType {
        self.op_type
    }

    fn data(&self) -> Option<NonZeroU32> {
        self.data
    }
}

impl From<UserData> for u64 {
    fn from(value: UserData) -> Self {
        let op = u32::from(value.op_type);

        (u64::from(op) << 32) | u64::from(value.data.map_or(0, NonZeroU32::get))
    }
}

#[derive(Debug, Error)]
enum UserDataError {
    #[error("Unknown Operation Type")]
    UnknownOperationType(#[from] UserDataOpTypeError),
}

impl TryFrom<u64> for UserData {
    type Error = UserDataError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let op_u64 = (value & 0xffff_ffff_0000_0000) >> 32;

        #[expect(
            clippy::unwrap_in_result,
            reason = "This isn't something we can recover from, and it would be a very bad sign."
        )]
        let op_u32 = u32::try_from(op_u64)
            .expect("We just made sure that the value wasn't larger than 32 bits.");
        let op = UserDataOpType::try_from(op_u32)?;

        let data_u64 = value & 0x0000_0000_ffff_ffff;

        #[expect(
            clippy::unwrap_in_result,
            reason = "This isn't something we can recover from, and it would be a very bad sign."
        )]
        let data = u32::try_from(data_u64)
            .expect("We just made sure that the value wasn't larger than 32 bits.");

        Ok(Self {
            op_type: op,
            data: NonZeroU32::new(data),
        })
    }
}

/// State for a single ADB session over USB.
struct AdbConnection<'a> {
    ep0: BorrowedFd<'a>,
    bulk_in: BorrowedFd<'a>,
    bulk_out: BorrowedFd<'a>,
    info: &'a device_info::DeviceInfo,
    buffers: BufferManager,
    version: ProtocolVersion,
}

impl<'a> AdbConnection<'a> {
    /// Creates a new ADB connection
    fn new(
        ep0: BorrowedFd<'a>,
        bulk_out: BorrowedFd<'a>,
        bulk_in: BorrowedFd<'a>,
        info: &'a device_info::DeviceInfo,
    ) -> Self {
        Self {
            ep0,
            bulk_in,
            bulk_out,
            info,
            buffers: BufferManager::new(),
            version: ProtocolVersion::V0,
        }
    }

    /// Handles CNXN: negotiates protocol version and sends the connection response.
    fn handle_command_cnxn(
        &mut self,
        sq: &mut SubmissionQueue<'_>,
        header: &message::AdbHeader,
        _payload: &[u8],
    ) {
        let recv_version = if let Ok(v) = ProtocolVersion::try_from(header.arg0) {
            info!("host connected with ADB protocol {v:?}");
            v
        } else {
            warn!("host sent unknown protocol version, assuming V0");
            ProtocolVersion::V0
        };
        self.version = recv_version;

        let (response_header, response_payload) = message::cnxn_response(recv_version, self.info);
        self.submit_message(sq, &response_header, Some(&response_payload));
    }

    /// Dispatches a fully parsed ADB command.
    fn handle_command(
        &mut self,
        sq: &mut SubmissionQueue<'_>,
        header: &message::AdbHeader,
        payload: Option<&[u8]>,
    ) {
        if let Some(payload) = payload {
            debug!(
                "received {} (arg0={:#x}, arg1={:#x}, payload={} bytes)",
                header.command,
                header.arg0,
                header.arg1,
                payload.len(),
            );
        } else {
            debug!(
                "received {} (arg0={:#x}, arg1={:#x}, no payload)",
                header.command, header.arg0, header.arg1,
            );
        }

        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "More commands will be added"
        )]
        match header.command {
            message::Command::Cnxn => {
                self.handle_command_cnxn(sq, header, payload.expect("CNXN requires a payload"));
            }
            cmd => {
                warn!("unhandled message: {cmd}");
            }
        }
    }

    /// Handles the ep0 events
    ///
    /// # Returns
    ///
    /// A boolean indicating whether or not we should stop all operations (true) or continue (false)
    fn handle_ep0_event(&self) -> bool {
        match read_next_ffs_event_type(self.ep0) {
            Ok(UsbFunctionFsEventType::Disable) => {
                info!("USB interface disabled");
                true
            }
            Ok(UsbFunctionFsEventType::Unbind) => {
                info!("USB function unbound");
                true
            }
            Ok(other) => {
                debug!("USB event: {other}");
                false
            }
            Err(e) => {
                error!("ep0 event error: {e}");
                true
            }
        }
    }

    /// Runs the `io_uring` event loop, processing ADB commands until the USB
    /// interface is disabled or an error occurs.
    ///
    /// # Errors
    ///
    /// Returns an error on `io_uring` submission failures or unrecoverable
    /// endpoint I/O errors.
    #[expect(clippy::too_many_lines, reason = "Event loop with inline CQE dispatch")]
    fn run(&mut self) -> io::Result<()> {
        let mut pending_header: Option<message::AdbHeader> = None;
        let mut bulk_out_buf = vec![0u8; message::PROTOCOL_VERSION.max_payload() as usize];
        let mut ring = IoUring::new(32)?;

        let mut sq = ring.submission();
        self.submit_ep0_poll(&mut sq);

        // SAFETY: bulk_out_buf has been allocated before the ring, and will be dropped after it.
        // Dropping the ring will cancel all pending submissions, so we know once it's done we don't
        // have a possible access to our buffer anymore.
        unsafe {
            self.submit_bulk_out_read(
                &mut sq,
                &mut bulk_out_buf,
                UserData::new(UserDataOpType::BulkOutReadHeader, None),
            );
        };
        sq.sync();
        drop(sq);

        loop {
            let _entries = ring.submit_and_wait(1)?;

            let (_, mut sq, cq) = ring.split();

            for cqe in cq {
                let Ok(user_data) = UserData::try_from(cqe.user_data()) else {
                    warn!("unknown completion op: {:#x}", cqe.user_data());
                    continue;
                };

                match (user_data.op_type(), user_data.data(), cqe.result()) {
                    // A failed outbound write is not fatal — the USB endpoint
                    // is still usable, so just free the buffer and carry on.
                    (UserDataOpType::BulkInWrite, Some(slot), res) if res < 0 => {
                        let err = io::Error::from_raw_os_error(-res);
                        warn!("BulkInWrite error: {err}");
                        self.buffers.free(slot.get());
                    }
                    (op_type, _, res) if res < 0 => {
                        let err = io::Error::from_raw_os_error(-res);
                        return Err(io::Error::other(format!("{op_type:?} error: {err}")));
                    }
                    (UserDataOpType::Ep0Poll, _, _) => {
                        if self.handle_ep0_event() {
                            return Ok(());
                        }
                        self.submit_ep0_poll(&mut sq);
                    }
                    (UserDataOpType::BulkOutReadHeader, _, len) => {
                        #[expect(
                            clippy::unwrap_in_result,
                            reason = "A positive i32 always fits in a usize"
                        )]
                        let len = usize::try_from(len)
                            .expect("A positive i32 will always fit in a usize");

                        let header = {
                            let mut data = &bulk_out_buf[..len];
                            message::parse_header(&mut data)
                        };

                        match header {
                            Ok(header) if header.data_length > 0 => {
                                pending_header = Some(header);

                                // SAFETY: bulk_out_buf has been allocated before the ring, and will
                                // be dropped after it. Dropping the ring will cancel all pending
                                // submissions, so we know once it's done we don't have a possible
                                // access to our buffer anymore.
                                unsafe {
                                    self.submit_bulk_out_read(
                                        &mut sq,
                                        &mut bulk_out_buf,
                                        UserData::new(UserDataOpType::BulkOutReadPayload, None),
                                    );
                                }
                            }
                            Ok(header) => {
                                self.handle_command(&mut sq, &header, None);

                                // SAFETY: bulk_out_buf has been allocated before the ring, and will
                                // be dropped after it. Dropping the ring will cancel all pending
                                // submissions, so we know once it's done we don't have a possible
                                // access to our buffer anymore.
                                unsafe {
                                    self.submit_bulk_out_read(
                                        &mut sq,
                                        &mut bulk_out_buf,
                                        UserData::new(UserDataOpType::BulkOutReadHeader, None),
                                    );
                                }
                            }
                            Err(e) => {
                                warn!("invalid header: {e}");

                                // SAFETY: bulk_out_buf has been allocated before the ring, and will
                                // be dropped after it. Dropping the ring will cancel all pending
                                // submissions, so we know once it's done we don't have a possible
                                // access to our buffer anymore.
                                unsafe {
                                    self.submit_bulk_out_read(
                                        &mut sq,
                                        &mut bulk_out_buf,
                                        UserData::new(UserDataOpType::BulkOutReadHeader, None),
                                    );
                                }
                            }
                        }
                    }
                    (UserDataOpType::BulkOutReadPayload, _, len) => {
                        #[expect(
                            clippy::unwrap_in_result,
                            reason = "A positive i32 always fits in a usize"
                        )]
                        let len = usize::try_from(len)
                            .expect("A positive i32 will always fit in a usize");

                        if let Some(header) = pending_header.take() {
                            let data = &bulk_out_buf[..len];

                            if self.version.requires_checksum()
                                && message::checksum(data) != header.data_check
                            {
                                warn!("checksum mismatch, dropping message");
                            } else {
                                self.handle_command(&mut sq, &header, Some(data));
                            }
                        } else {
                            warn!("payload without pending header");
                        }

                        // SAFETY: bulk_out_buf has been allocated before the ring, and will be
                        // dropped after it. Dropping the ring will cancel all pending submissions,
                        // so we know once it's done we don't have a possible access to our buffer
                        // anymore.
                        unsafe {
                            self.submit_bulk_out_read(
                                &mut sq,
                                &mut bulk_out_buf,
                                UserData::new(UserDataOpType::BulkOutReadHeader, None),
                            );
                        }
                    }
                    (UserDataOpType::BulkInWrite, Some(slot), _) => {
                        self.buffers.free(slot.get());
                    }
                    (UserDataOpType::BulkInWrite, None, _) => {
                        unreachable!()
                    }
                }
            }

            sq.sync();
        }
    }

    /// Submits a read on the `bulk_out` fd.
    ///
    /// # Safety
    ///
    /// `bulk_out_buf` must outlive the sq's ring.
    unsafe fn submit_bulk_out_read(
        &self,
        sq: &mut SubmissionQueue<'_>,
        bulk_out_buf: &mut [u8],
        user_data: UserData,
    ) {
        let read_op = opcode::Read::new(
            Fd(self.bulk_out.as_raw_fd()),
            bulk_out_buf.as_mut_ptr(),
            bulk_out_buf
                .len()
                .try_into()
                .expect("The buffer is at most 1MB and will fit in a u32"),
        )
        .build()
        .user_data(user_data.into());

        // SAFETY: The caller guarantees that bulk_out_buf outlives the ring,
        // so the pointer in read_op remains valid through completion.
        unsafe {
            sq.push(&read_op).expect("SQ full");
        }
    }

    /// Submit a poll on ep0
    fn submit_ep0_poll(&self, sq: &mut SubmissionQueue<'_>) {
        let poll_op = opcode::PollAdd::new(Fd(self.ep0.as_raw_fd()), 0x0001)
            .build()
            .user_data(UserData::new(UserDataOpType::Ep0Poll, None).into());

        // SAFETY: All our parameters are copied. We don't have any potential lifetime issue here.
        unsafe {
            sq.push(&poll_op).expect("SQ full");
        }
    }

    /// Submits an ADB message (header + optional payload) to `bulk_in` via `io_uring`.
    fn submit_message(
        &mut self,
        sq: &mut SubmissionQueue<'_>,
        header: &message::AdbHeader,
        payload: Option<&[u8]>,
    ) {
        let payload = payload.filter(|p| !p.is_empty());

        let (hdr_slot, hdr_buf) = self.buffers.alloc(size_of_val(header));
        hdr_buf.extend_from_slice(header.as_le_bytes());

        let mut hdr_sqe = opcode::Write::new(
            Fd(self.bulk_in.as_raw_fd()),
            hdr_buf.as_ptr(),
            u32::try_from(hdr_buf.len()).expect("buffer length fits in u32"),
        )
        .build()
        .user_data(
            UserData::new(
                UserDataOpType::BulkInWrite,
                Some(NonZeroU32::new(hdr_slot).expect("Buffer slot 0 cannot exist")),
            )
            .into(),
        );

        if payload.is_some() {
            hdr_sqe = hdr_sqe.flags(io_uring::squeue::Flags::IO_LINK);
        }

        // SAFETY: hdr_buf is owned by BufferManager and stays alive until the
        // BulkInWrite completion frees the slot.
        unsafe {
            sq.push(&hdr_sqe).expect("SQ full");
        };

        if let Some(payload) = payload {
            let (pay_slot, pay_buf) = self.buffers.alloc(payload.len());
            pay_buf.extend_from_slice(payload);

            let pay_sqe = opcode::Write::new(
                Fd(self.bulk_in.as_raw_fd()),
                pay_buf.as_ptr(),
                u32::try_from(pay_buf.len()).expect("buffer length fits in u32"),
            )
            .build()
            .user_data(
                UserData::new(
                    UserDataOpType::BulkInWrite,
                    Some(NonZeroU32::new(pay_slot).expect("Buffer slot 0 cannot exist")),
                )
                .into(),
            );

            // SAFETY: pay_buf is owned by BufferManager and stays alive until the
            // BulkInWrite completion frees the slot.
            unsafe {
                sq.push(&pay_sqe).expect("SQ full");
            }
        }
    }
}

/// Waits for the host connection to be enabled.
///
/// # Errors
///
/// Returns an error if reading an ep0 event fails.
fn wait_for_enable(ep0: BorrowedFd<'_>) -> io::Result<()> {
    loop {
        match read_next_ffs_event_type(ep0) {
            Ok(UsbFunctionFsEventType::Bind) => info!("USB function bound to gadget"),
            Ok(UsbFunctionFsEventType::Enable) => {
                info!("USB interface enabled by host");
                return Ok(());
            }
            Ok(other) => debug!("USB event: {other}"),
            Err(e) => return Err(e),
        }
    }
}

/// Starts handling a new connection to a host.
///
/// # Errors
///
/// Returns an error if waiting for the USB Enable event fails, or if the
/// connection event loop encounters an unrecoverable I/O error.
fn run_daemon(
    ep0: BorrowedFd<'_>,
    bulk_out: BorrowedFd<'_>,
    bulk_in: BorrowedFd<'_>,
) -> io::Result<()> {
    let device_info = device_info::DeviceInfo::from_system();
    info!(
        "device identity: serial={}, name={}, model={}, device={}",
        device_info.serial, device_info.name, device_info.model, device_info.device
    );

    info!("waiting for host connection...");
    wait_for_enable(ep0)?;

    info!("ready for ADB communication");

    let mut conn = AdbConnection::new(ep0, bulk_out, bulk_in, &device_info);
    conn.run()
}

const SD_LISTEN_FDS_START: i32 = 3;

/// Returns the FDs passed by systemd via socket activation.
///
/// # Returns
///
/// A tuple of three [`OwnedFd`], in the (`ep0`, `bulk_out`, `bulk_in`) order.
///
/// # Errors
///
/// Returns an error if `LISTEN_FDS` is missing, not parseable, or does not
/// contain exactly 3 file descriptors.
fn receive_usb_fds() -> io::Result<(OwnedFd, OwnedFd, OwnedFd)> {
    let n: i32 = env::var("LISTEN_FDS")
        .map_err(io::Error::other)?
        .parse()
        .map_err(io::Error::other)?;

    if n != 3 {
        return Err(io::Error::other(format!(
            "expected 3 fds (ep0 + 2 data endpoints), got {n}"
        )));
    }

    // fd 3 = ep0 (control, already used by systemd to write descriptors)
    // fd 4 = ep1 (bulk OUT)
    // fd 5 = ep2 (bulk IN)
    let (ep0, ep_out, ep_in) = (
        // SAFETY: systemd transfer ownership of the fd to us. We know it's valid, and that we only
        // have to close it when done.
        unsafe { OwnedFd::from_raw_fd(SD_LISTEN_FDS_START) },
        // SAFETY: systemd transfer ownership of the fd to us. We know it's valid, and that we only
        // have to close it when done.
        unsafe { OwnedFd::from_raw_fd(SD_LISTEN_FDS_START + 1) },
        // SAFETY: systemd transfer ownership of the fd to us. We know it's valid, and that we only
        // have to close it when done.
        unsafe { OwnedFd::from_raw_fd(SD_LISTEN_FDS_START + 2) },
    );

    Ok((ep0, ep_out, ep_in))
}

#[derive(Subcommand)]
enum CliCommand {
    /// Create the USB gadget in configfs
    SetupGadget,

    /// Bind the USB gadget to a UDC
    BindUdc,
}

#[derive(Parser)]
#[command(about = "Android Debug Bridge (ADB) device daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    match cli.command {
        Some(CliCommand::SetupGadget) => setup_gadget(),
        Some(CliCommand::BindUdc) => {
            unbind_udc()?;
            bind_udc()
        }
        None => {
            let (ep0, bulk_out, bulk_in) = receive_usb_fds()?;

            run_daemon(ep0.as_fd(), bulk_out.as_fd(), bulk_in.as_fd())
        }
    }
}
