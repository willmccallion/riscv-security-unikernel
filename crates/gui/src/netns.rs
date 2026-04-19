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
//! process lacks `CAP_SYS_ADMIN`, `NsPool::try_init` returns `None` and
//! the caller is expected to fall back to the legacy host-bound socket
//! pool. That keeps the GUI usable on machines where the netns setup
//! hasn't been run.

use std::fs::File;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::thread;

/// How many outstanding sends we queue per namespace thread before
/// `try_send` drops. Small on purpose — we'd rather drop a test-traffic
/// packet than blow up memory when the channel backs up.
const PER_NS_QUEUE_DEPTH: usize = 256;

/// Pool of per-namespace UDP senders.
///
/// Each entry owns a `SyncSender` that fans packets out to a dedicated
/// OS thread living inside one network namespace. Use [`Self::send`]
/// (non-blocking) to push a packet to a namespace picked by the caller.
pub struct NsPool {
    senders: Vec<SyncSender<(SocketAddr, Vec<u8>)>>,
}

impl NsPool {
    /// Attempt to build a sender pool for namespaces
    /// `<prefix>-000..<prefix>-{count-1:03}`.
    ///
    /// Returns `None` if any namespace file is missing, `setns(2)`
    /// fails (most commonly: the process doesn't have
    /// `CAP_SYS_ADMIN`), or the UDP bind inside a namespace fails.
    /// Partial init is not exposed — the caller gets the fallback path
    /// for free and doesn't have to reason about "some namespaces
    /// worked."
    pub fn try_init(prefix: &str, count: usize) -> Option<Self> {
        let mut senders = Vec::with_capacity(count);
        for i in 0..count {
            let path = format!("/var/run/netns/{prefix}-{i:03}");
            let ns_file = match File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[netns] open {path}: {e} — falling back to host sockets");
                    return None;
                }
            };
            let (tx, rx) = sync_channel::<(SocketAddr, Vec<u8>)>(PER_NS_QUEUE_DEPTH);
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);

            thread::Builder::new()
                .name(format!("ns-{i:03}"))
                .spawn(move || {
                    // SAFETY: setns is thread-local; we own this
                    // thread exclusively and never move work off it.
                    // CLONE_NEWNET only affects networking state.
                    let rc = unsafe { libc::setns(ns_file.as_raw_fd(), libc::CLONE_NEWNET) };
                    if rc != 0 {
                        let err = std::io::Error::last_os_error();
                        let _ = ready_tx.send(Err(format!("setns: {err}")));
                        return;
                    }
                    let sock = match UdpSocket::bind("0.0.0.0:0") {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = ready_tx.send(Err(format!("bind: {e}")));
                            return;
                        }
                    };
                    // Hold the ns fd open for the life of the thread;
                    // dropping it would not revert the namespace but
                    // keeping it alive mirrors how long the binding
                    // is valid.
                    let _ns_guard = ns_file;
                    let _ = ready_tx.send(Ok(()));

                    while let Ok((dst, payload)) = rx.recv() {
                        let _ = sock.send_to(&payload, dst);
                    }
                })
                .ok()?;

            match ready_rx.recv_timeout(std::time::Duration::from_secs(2)) {
                Ok(Ok(())) => senders.push(tx),
                Ok(Err(msg)) => {
                    eprintln!("[netns] ns {prefix}-{i:03}: {msg} — falling back to host sockets");
                    return None;
                }
                Err(_) => {
                    eprintln!("[netns] ns {prefix}-{i:03}: init timed out");
                    return None;
                }
            }
        }
        eprintln!("[netns] ready: {count} namespaces bound");
        Some(Self { senders })
    }

    /// Number of namespace senders in the pool.
    pub fn len(&self) -> usize {
        self.senders.len()
    }

    /// Non-blockingly queue `payload` to be sent to `dst` from
    /// namespace `idx`. Drops the packet if the channel is full or the
    /// worker thread has died — both are fine for test traffic.
    pub fn send(&self, idx: usize, dst: SocketAddr, payload: Vec<u8>) {
        let sender = &self.senders[idx % self.senders.len()];
        match sender.try_send((dst, payload)) {
            Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
        }
    }
}
