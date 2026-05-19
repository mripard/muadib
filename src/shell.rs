//! PTY-backed shell service for `adb shell`.

use std::{
    fs::File,
    io::{self, Write as _},
    os::{
        fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, IntoRawFd as _, RawFd},
        unix::process::CommandExt as _,
    },
    process::{Child, Command, Stdio},
};

use rustix::pty::{OpenptFlags, grantpt, ioctl_tiocgptpeer, openpt, unlockpt};

const PTY_READ_BUF_SIZE: usize = 4096;

/// Manages a PTY-backed shell subprocess for a single ADB stream.
pub(crate) struct ShellService {
    master: File,
    child: Child,
    read_buf: Vec<u8>,
}

impl ShellService {
    /// Spawns a shell on a new PTY, optionally running `command`.
    ///
    /// # Errors
    ///
    /// Returns an error if PTY allocation or process spawning fails.
    pub(crate) fn spawn(command: Option<&str>) -> io::Result<Self> {
        let master_fd = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)
            .map_err(io::Error::from)?;

        grantpt(&master_fd).map_err(io::Error::from)?;
        unlockpt(&master_fd).map_err(io::Error::from)?;

        let slave_fd = ioctl_tiocgptpeer(&master_fd, OpenptFlags::RDWR).map_err(io::Error::from)?;

        let stdin: Stdio = slave_fd.try_clone()?.into();
        let stdout: Stdio = slave_fd.try_clone()?.into();
        let stderr: Stdio = slave_fd.into();

        let mut cmd = Command::new("/bin/sh");
        if let Some(c) = command {
            _ = cmd.args(["-c", c]);
        }

        _ = cmd.stdin(stdin).stdout(stdout).stderr(stderr);

        // SAFETY: This closure runs in the child process after fork, before exec.
        // setsid + TIOCSCTTY make the PTY the controlling terminal for the new
        // session.
        unsafe {
            _ = cmd.pre_exec(|| {
                #[expect(
                    unused_unsafe,
                    reason = "Inner unsafe needed for clippy::multiple_unsafe_ops_per_block"
                )]
                // SAFETY: fd 0 is the slave PTY we just attached as stdin.
                let stdin = unsafe { BorrowedFd::borrow_raw(0) };

                _ = rustix::process::setsid().map_err(io::Error::from)?;
                rustix::process::ioctl_tiocsctty(stdin).map_err(io::Error::from)?;

                Ok(())
            });
        };

        let child = cmd.spawn()?;

        // SAFETY: master_fd is a valid, owned fd. into_raw_fd() relinquishes
        // ownership so File takes sole ownership.
        let master = unsafe { File::from_raw_fd(master_fd.into_raw_fd()) };

        let read_buf = Vec::with_capacity(PTY_READ_BUF_SIZE);

        Ok(Self {
            master,
            child,
            read_buf,
        })
    }

    /// Returns the raw fd of the PTY master.
    pub(crate) fn master_raw_fd(&self) -> RawFd {
        self.master.as_raw_fd()
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
            .expect("PTY read buffer fits in u32")
    }

    /// Copies `len` bytes from the read buffer into a new `Vec`.
    pub(crate) fn read_buf_data(&self, len: usize) -> Vec<u8> {
        // SAFETY: The caller guarantees that io_uring has written `len` bytes
        // into the buffer before calling this method.
        unsafe { core::slice::from_raw_parts(self.read_buf.as_ptr(), len) }.to_vec()
    }

    /// Writes data to the PTY master (i.e. the shell's stdin).
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    pub(crate) fn write_input(&mut self, data: &[u8]) -> io::Result<()> {
        self.master.write_all(data)
    }
}

impl Drop for ShellService {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}
