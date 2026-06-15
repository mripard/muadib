//! Socket-backed forwarding service for `adb forward`.
//!
//! When the host runs `adb forward tcp:HOST_PORT tcp:DEVICE_PORT`, the host
//! ADB daemon listens on `HOST_PORT` and, for each incoming connection, sends
//! an OPEN to the device with the service string `tcp:DEVICE_PORT`. This
//! module connects a local socket to the requested destination and relays data
//! bidirectionally over the ADB stream.
//!
//! Supported destination types:
//! - `tcp:PORT` — TCP connection to `127.0.0.1:PORT`.
//! - `localabstract:NAME` — abstract Unix domain socket.
//! - `localfilesystem:PATH` — pathname-bound Unix domain socket.

use std::{
    io,
    net::TcpStream,
    os::{
        fd::{AsRawFd, OwnedFd, RawFd},
        linux::net::SocketAddrExt as _,
        unix::net::UnixStream,
    },
};

use log::debug;

const SOCKET_READ_BUF_SIZE: usize = 4096;

/// Manages a socket connection for a single ADB forwarding stream.
#[derive(Debug)]
pub(crate) struct ForwardService {
    socket: OwnedFd,
    read_buf: Vec<u8>,
}

impl ForwardService {
    /// Connects to the given destination and returns a new forwarding service.
    ///
    /// The `destination` string is the service name from the OPEN payload,
    /// already stripped of any trailing NUL. Supported formats:
    /// - `tcp:PORT`
    /// - `localabstract:NAME`
    /// - `localfilesystem:PATH`
    ///
    /// # Errors
    ///
    /// Returns an error if the destination format is invalid or the connection
    /// fails.
    pub(crate) fn connect(destination: &str) -> io::Result<Self> {
        debug!("forward: connecting to {destination}");

        let socket: OwnedFd = if let Some(port_str) = destination.strip_prefix("tcp:") {
            let port: u16 = port_str
                .parse()
                .map_err(|e| io::Error::other(format!("invalid port: {e}")))?;
            TcpStream::connect(("127.0.0.1", port))?.into()
        } else if let Some(name) = destination.strip_prefix("localabstract:") {
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
            UnixStream::connect_addr(&addr)?.into()
        } else if let Some(path) = destination.strip_prefix("localfilesystem:") {
            UnixStream::connect(path)?.into()
        } else {
            return Err(io::Error::other(format!(
                "unsupported forward destination: {destination}"
            )));
        };

        Ok(Self {
            socket,
            read_buf: Vec::with_capacity(SOCKET_READ_BUF_SIZE),
        })
    }

    /// Returns a pointer to the read buffer for `io_uring` submissions.
    pub(crate) fn read_buf_ptr(&mut self) -> *mut u8 {
        self.read_buf.as_mut_ptr()
    }

    /// Returns the read buffer capacity as a `u32` for `io_uring` submissions.
    pub(crate) fn read_buf_capacity(&self) -> u32 {
        self.read_buf
            .capacity()
            .try_into()
            .expect("socket read buffer fits in u32")
    }

    /// Returns a slice of `len` bytes from the read buffer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `io_uring` has written at least `len` bytes
    /// into the buffer before calling this method.
    pub(crate) unsafe fn read_buf_data(&self, len: usize) -> &[u8] {
        // SAFETY: Guaranteed by the caller.
        unsafe { core::slice::from_raw_parts(self.read_buf.as_ptr(), len) }
    }

    /// Shuts down the write side of the socket so the destination sees EOF.
    ///
    /// # Errors
    ///
    /// Returns an error if the shutdown fails.
    pub(crate) fn shutdown_write(&self) -> io::Result<()> {
        rustix::net::shutdown(&self.socket, rustix::net::Shutdown::Write)?;
        Ok(())
    }

    /// Writes data to the connected socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    pub(crate) fn write_input(&self, data: &[u8]) -> io::Result<()> {
        let mut written = 0;
        while written < data.len() {
            written += rustix::io::write(&self.socket, &data[written..])?;
        }
        Ok(())
    }
}

impl AsRawFd for ForwardService {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}
