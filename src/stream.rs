//! Stream management for ADB connections.
//!
//! ADB multiplexes multiple independent conversations over a single USB
//! connection. Each conversation is a "stream", identified by a pair of u32
//! IDs: one chosen by each side (`local_id` and `remote_id`).
//!
//! The host opens a stream by sending OPEN with a service name (e.g.
//! "sync:", "shell:ls"). The device allocates a `local_id`, creates the
//! appropriate service handler, and responds with OKAY. All subsequent
//! WRTE/OKAY/CLSE messages on that stream carry both IDs so payloads can
//! be routed to the right handler.
//!
//! `StreamManager` owns all active streams, keyed by our `local_id`. It handles
//! allocation of new IDs (monotonically increasing, starting at 1) and
//! service dispatch based on the destination string from OPEN.

use std::collections::HashMap;

use log::warn;

use crate::{forward::ForwardService, shell::ShellService, sync::SyncService};

/// Back-end handler for an open ADB stream.
pub(crate) enum Service {
    /// File-transfer service (`sync:`).
    Sync(SyncService),
    /// Interactive shell service (`shell:`).
    Shell(ShellService),
    /// Device reboot request (`reboot:`).
    Reboot,
    /// Socket forwarding service (`tcp:`, `localabstract:`, `localfilesystem:`).
    Forward(ForwardService),
}

/// An open ADB stream between host and device.
pub(crate) struct Stream {
    /// The host-assigned stream ID.
    pub remote_id: u32,
    /// The service handler for this stream.
    pub service: Service,
    /// Whether we are waiting for an OKAY before sending the next WRTE.
    ///
    /// Set *before* the WRTE is submitted to `io_uring`, cleared when the
    /// host's OKAY arrives. The WRTE write completion (CQE) is only used
    /// to free the buffer — it plays no role in flow control.
    ///
    /// `io_uring` may deliver the OKAY read CQE before the WRTE write CQE.
    /// When that happens we clear this flag and submit the next WRTE
    /// immediately, so two writes can be in-flight at once. This is safe
    /// because each write has its own buffer, and the host can only send
    /// the OKAY after it received the WRTE on the bus, so the OKAY
    /// implies the write reached the host regardless of CQE ordering.
    pub waiting_for_okay: bool,
    /// Whether the host has sent CLSE for this stream.
    ///
    /// For forward streams the host typically sends WRTE followed
    /// immediately by CLSE once the client's TCP connection closes.
    /// If the stream were torn down on CLSE, any response data still
    /// in flight from the forwarded socket (e.g. an echo server's
    /// reply) would be lost because the pending `SocketRead` CQE
    /// would find the stream already gone.
    ///
    /// Setting this flag instead of closing lets the socket drain:
    /// the write side is shut down so the destination gets EOF, while
    /// the read side stays alive to deliver remaining data back to
    /// the host. The stream is finally closed when `SocketRead`
    /// returns 0 or an error.
    pub remote_closed: bool,
}

/// Manages active ADB streams, keyed by device-local ID.
pub(crate) struct StreamManager {
    streams: HashMap<u32, Stream>,
    next_id: u32,
}

impl StreamManager {
    /// Creates an empty stream manager.
    pub(crate) fn new() -> Self {
        StreamManager {
            streams: HashMap::new(),
            next_id: 1,
        }
    }

    /// Opens a new stream for the given service name, returning the `local_id`.
    ///
    /// Returns `None` if the service is unknown.
    pub(crate) fn open(&mut self, remote_id: u32, service: &str) -> Option<u32> {
        let service = match service {
            "sync:" => Service::Sync(SyncService::new()),
            _ if service.starts_with("shell:") => {
                let Some(cmd) = service.strip_prefix("shell:") else {
                    unreachable!()
                };

                let cmd = if cmd.is_empty() { None } else { Some(cmd) };
                match ShellService::spawn(cmd) {
                    Ok(s) => Service::Shell(s),
                    Err(e) => {
                        warn!("cannot spawn shell: {e}");
                        return None;
                    }
                }
            }
            _ if service.starts_with("reboot:") => Service::Reboot,
            _ if service.starts_with("tcp:")
                || service.starts_with("localabstract:")
                || service.starts_with("localfilesystem:") =>
            {
                match ForwardService::connect(service) {
                    Ok(f) => Service::Forward(f),
                    Err(e) => {
                        warn!("cannot connect forward destination: {e}");
                        return None;
                    }
                }
            }
            _ => {
                warn!("unknown service: {service}");
                return None;
            }
        };

        let local_id = self.next_id;
        self.next_id += 1;

        let _prev = self.streams.insert(
            local_id,
            Stream {
                remote_id,
                service,
                waiting_for_okay: false,
                remote_closed: false,
            },
        );

        Some(local_id)
    }

    /// Returns a mutable reference to the stream with the given `local_id`.
    pub(crate) fn get(&mut self, local_id: u32) -> Option<&mut Stream> {
        self.streams.get_mut(&local_id)
    }

    /// Removes the stream with the given `local_id`.
    pub(crate) fn close(&mut self, local_id: u32) {
        let _stream = self.streams.remove(&local_id);
    }
}
