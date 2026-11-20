//! Per-namespace UDP sender pool for realistic multi-source traffic
//! generation.
//!
//! The kernel's heavy-hitter detector counts packets *per source IP*. A
//! single host-bound `UdpSocket` pool can only present ~50 distinct
//! source IPs even if the GUI pretends otherwise, so normal traffic
//! quickly trips the per-source threshold and everything gets dropped.
//!
//! To exercise the appliance against real diversity, the Makefile's
//! `setup_net_many` target creates N Linux network namespaces, each
//! with its own IP in `192.168.100.0/24` bridged to the tap the kernel
//! listens on. This module spawns one OS thread per namespace, calls
//! `setns(2)` on that thread so it inherits the namespace's network
//! stack, binds a `UdpSocket` there, and then just waits for
//! `(destination, payload)` messages over an mpsc channel.
//!
//! The pool init is all-or-nothing: if any namespace is missing or the
//! process lacks `CAP_SYS_ADMIN`, `NsPool::try_init` says why and the
//! caller falls back to the legacy host-bound socket pool. That keeps the GUI usable on machines where the netns setup
//! hasn't been run.

// setns(2) has no safe wrapper in std.
#![allow(unsafe_code)]

use std::fmt;
use std::fs::File;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread;
use std::time::Duration;

/// How many outstanding sends we queue per namespace thread before
/// `try_send` drops. Small on purpose — we'd rather drop a test-traffic
/// packet than blow up memory when the channel backs up.
const PER_NS_QUEUE_DEPTH: usize = 256;

/// How long a namespace thread has to enter its namespace and bind.
const NS_READY_TIMEOUT: Duration = Duration::from_secs(2);

/// A packet for a namespace thread to send.
type Outgoing = (SocketAddr, Vec<u8>);

/// Why the pool could not be built.
#[derive(Debug)]
pub enum NsPoolError {
    /// A namespace's file could not be opened; `make setup_net_many`
    /// creates them.
    Open {
        /// The namespace file.
        path: String,
        /// What went wrong.
        source: io::Error,
    },
    /// Entering a namespace or binding inside it failed, most often for
    /// want of `CAP_SYS_ADMIN`.
    Setup {
        /// The namespace.
        namespace: String,
        /// The call that failed: `setns` or `bind`.
        step: &'static str,
        /// What went wrong.
        source: io::Error,
    },
    /// A namespace's thread could not be started.
    Spawn(io::Error),
    /// A namespace's thread did not report in time.
    TimedOut {
        /// The namespace.
        namespace: String,
    },
}

impl fmt::Display for NsPoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, source } => write!(f, "open {path}: {source}"),
            Self::Setup {
                namespace,
                step,
                source,
            } => write!(f, "{namespace}: {step}: {source}"),
            Self::Spawn(source) => write!(f, "spawn a namespace thread: {source}"),
            Self::TimedOut { namespace } => write!(f, "{namespace}: setup timed out"),
        }
    }
}

impl std::error::Error for NsPoolError {}

/// Pool of per-namespace UDP senders.
///
/// Each entry owns a `SyncSender` that fans packets out to a dedicated
/// OS thread living inside one network namespace. Use [`Self::send`]
/// (non-blocking) to push a packet to a namespace picked by the caller.
pub struct NsPool {
    senders: Vec<SyncSender<Outgoing>>,
}

impl NsPool {
    /// Builds a sender pool for namespaces
    /// `<prefix>-000..<prefix>-{count-1:03}`, all or nothing, so the
    /// caller never has to reason about a pool where some worked.
    ///
    /// # Errors
    ///
    /// [`NsPoolError`] for the first namespace that could not be used.
    pub fn try_init(prefix: &str, count: usize) -> Result<Self, NsPoolError> {
        let senders = (0..count)
            .map(|i| spawn_sender(&format!("{prefix}-{i:03}")))
            .collect::<Result<_, _>>()?;
        Ok(Self { senders })
    }

    /// Number of namespace senders in the pool.
    pub const fn len(&self) -> usize {
        self.senders.len()
    }

    /// Non-blockingly queue `payload` to be sent to `dst` from
    /// namespace `idx`. Drops the packet if the channel is full or the
    /// worker thread has died — both are fine for test traffic.
    pub fn send(&self, idx: usize, dst: SocketAddr, payload: Vec<u8>) {
        let sender = &self.senders[idx % self.senders.len()];
        let _ = sender.try_send((dst, payload));
    }
}

/// Starts a thread inside `namespace` that sends whatever it is given
/// from a socket bound there, once it has entered and bound.
fn spawn_sender(namespace: &str) -> Result<SyncSender<Outgoing>, NsPoolError> {
    let path = format!("/var/run/netns/{namespace}");
    let ns_file = File::open(&path).map_err(|source| NsPoolError::Open { path, source })?;
    let (tx, rx) = sync_channel::<Outgoing>(PER_NS_QUEUE_DEPTH);
    let (ready_tx, ready_rx) = sync_channel::<Result<(), (&'static str, io::Error)>>(1);
    let _ = thread::Builder::new()
        .name(namespace.to_string())
        .spawn(move || {
            let socket = match enter_and_bind(&ns_file) {
                Ok(socket) => socket,
                Err(failure) => {
                    let _ = ready_tx.send(Err(failure));
                    return;
                }
            };
            let _ = ready_tx.send(Ok(()));
            // Test traffic: a packet the socket refuses is just dropped.
            while let Ok((dst, payload)) = rx.recv() {
                let _ = socket.send_to(&payload, dst);
            }
        })
        .map_err(NsPoolError::Spawn)?;
    match ready_rx.recv_timeout(NS_READY_TIMEOUT) {
        Ok(Ok(())) => Ok(tx),
        Ok(Err((step, source))) => Err(NsPoolError::Setup {
            namespace: namespace.to_string(),
            step,
            source,
        }),
        Err(_) => Err(NsPoolError::TimedOut {
            namespace: namespace.to_string(),
        }),
    }
}

/// Moves the calling thread into the namespace `ns_file` names and binds
/// a UDP socket there; on failure, which call failed and why.
fn enter_and_bind(ns_file: &File) -> Result<UdpSocket, (&'static str, io::Error)> {
    // SAFETY: setns only changes the calling thread's network namespace,
    // and this thread is dedicated to the namespace for its whole life.
    let rc = unsafe { libc::setns(ns_file.as_raw_fd(), libc::CLONE_NEWNET) };
    if rc != 0 {
        return Err(("setns", io::Error::last_os_error()));
    }
    UdpSocket::bind("0.0.0.0:0").map_err(|e| ("bind", e))
}
