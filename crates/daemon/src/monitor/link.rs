//! Streaming summaries to viewers, such as the dashboard, over a local
//! Unix socket that only the monitor's user can open.

use super::hosts::Locality;
use super::names::NameSource;
use super::net::LocalNetworks;
use super::pipeline::Summary;
use super::totals::{Counter, TrafficTotals};
use crate::viewer_socket;
use anyhow::{Context, Result, bail};
use monitor_proto as proto;
use std::fs::{self, DirBuilder};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

/// Most viewers connected at once.
const MAX_VIEWERS: usize = 8;
/// Bytes queued for a viewer that is not reading before it is dropped,
/// so a stuck viewer can never hold up capture or use unbounded memory.
const MAX_QUEUED_BYTES: usize = 4 * 1024 * 1024;

/// The hello a viewer receives on connecting.
pub fn hello(interfaces: &[String], local: &LocalNetworks, interval_ms: u64) -> proto::Hello {
    proto::Hello {
        protocol: proto::PROTOCOL_VERSION,
        interfaces: interfaces.to_vec(),
        local_networks: local.prefixes().iter().map(ToString::to_string).collect(),
        interval_ms,
    }
}

/// A summary as viewers receive it.
pub fn summary_message(summary: &Summary) -> proto::Summary {
    proto::Summary {
        start_unix_ms: summary.start.as_nanos() / 1_000_000,
        length_ms: u64::try_from(summary.length.as_millis()).unwrap_or(u64::MAX),
        totals: totals(&summary.totals),
        hosts: summary
            .hosts
            .iter()
            .map(|host| proto::Host {
                addr: host.activity.addr,
                locality: match host.activity.locality {
                    Locality::Local => proto::Locality::Local,
                    Locality::Remote => proto::Locality::Remote,
                },
                name: host.name.as_ref().map(|name| proto::HostName {
                    name: name.name.to_string(),
                    source: match name.source {
                        NameSource::TlsServerName => proto::NameSource::TlsServerName,
                        NameSource::Dns => proto::NameSource::Dns,
                        NameSource::Mdns => proto::NameSource::Mdns,
                        NameSource::TlsCoverName => proto::NameSource::TlsCoverName,
                    },
                }),
                sent: counter(host.activity.sent),
                received: counter(host.activity.received),
                flows_opened: host.activity.flows_opened,
                flows_accepted: host.activity.flows_accepted,
            })
            .collect(),
        hosts_omitted: u64::try_from(summary.hosts_omitted).unwrap_or(u64::MAX),
        active_flows: u64::try_from(summary.active_flows).unwrap_or(u64::MAX),
        untracked: summary.untracked,
    }
}

const fn counter(c: Counter) -> proto::Counter {
    proto::Counter {
        packets: c.packets,
        bytes: c.bytes,
    }
}

const fn totals(t: &TrafficTotals) -> proto::Totals {
    proto::Totals {
        inbound: counter(t.inbound),
        outbound: counter(t.outbound),
        internal: counter(t.internal),
        transit: counter(t.transit),
        non_ip: counter(t.non_ip),
        ipv6: counter(t.ipv6),
        tcp: counter(t.tcp),
        udp: counter(t.udp),
    }
}

/// A connected viewer and what is queued for it.
#[derive(Debug)]
struct Viewer {
    stream: UnixStream,
    queued: Vec<u8>,
}

impl Viewer {
    /// Writes as much of the queue as the viewer will take without
    /// blocking; `false` if the viewer is gone or too far behind.
    fn flush(&mut self) -> bool {
        while !self.queued.is_empty() {
            match self.stream.write(&self.queued) {
                Ok(0) => return false,
                Ok(written) => drop(self.queued.drain(..written)),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(_) => return false,
            }
        }
        self.queued.len() <= MAX_QUEUED_BYTES
    }
}

/// The listening socket and the viewers connected to it. The monitor
/// only ever writes to viewers; nothing they send is read.
#[derive(Debug)]
pub struct ViewerServer {
    listener: UnixListener,
    viewers: Vec<Viewer>,
    hello_line: String,
}

impl ViewerServer {
    /// Listens at `path`, greeting each viewer with `hello`.
    ///
    /// The socket's directory is created private to this user if missing
    /// and refused if anyone else could reach into it; the socket itself
    /// is readable and writable by this user alone. A stale socket left by
    /// an earlier run is replaced, but one another monitor is serving on
    /// is not.
    pub fn bind(path: &Path, hello: &proto::Hello) -> Result<Self> {
        let directory = path.parent().context("socket path has no directory")?;
        prepare_private_directory(directory)?;
        if path.exists() {
            if UnixStream::connect(path).is_ok() {
                bail!("another monitor is already serving at {}", path.display());
            }
            fs::remove_file(path).with_context(|| format!("remove stale socket {}", path.display()))?;
        }
        let listener = UnixListener::bind(path).with_context(|| format!("listen at {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).context("restrict the socket to this user")?;
        listener.set_nonblocking(true).context("make the socket non-blocking")?;
        let hello_line = proto::Message::Hello(hello.clone()).to_line()?;
        Ok(Self {
            listener,
            viewers: Vec::new(),
            hello_line,
        })
    }

    /// Accepts any viewers waiting to connect, up to `MAX_VIEWERS`.
    pub fn accept_viewers(&mut self) -> Result<()> {
        while let Some(stream) = viewer_socket::accept_nonblocking(&self.listener).context("accept a viewer")? {
            if self.viewers.len() >= MAX_VIEWERS {
                continue;
            }
            let mut viewer = Viewer {
                stream,
                queued: self.hello_line.clone().into_bytes(),
            };
            if viewer.flush() {
                self.viewers.push(viewer);
            }
        }
        Ok(())
    }

    /// Sends `summary` to every viewer, dropping any that have gone or
    /// fallen too far behind.
    pub fn send(&mut self, summary: &Summary) -> Result<()> {
        let line = proto::Message::Summary(summary_message(summary)).to_line()?;
        for viewer in &mut self.viewers {
            viewer.queued.extend_from_slice(line.as_bytes());
        }
        self.viewers.retain_mut(Viewer::flush);
        Ok(())
    }

    /// Viewers connected now.
    pub const fn viewer_count(&self) -> usize {
        self.viewers.len()
    }
}

fn prepare_private_directory(directory: &Path) -> Result<()> {
    if !directory.exists() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)
            .with_context(|| format!("create {}", directory.display()))?;
    }
    let metadata = fs::metadata(directory).with_context(|| format!("inspect {}", directory.display()))?;
    let ours = fs::metadata("/proc/self").context("read /proc/self")?.uid();
    if !metadata.is_dir() || metadata.uid() != ours || metadata.mode() & 0o077 != 0 {
        bail!(
            "{} must be a directory owned by this user and closed to everyone else (mode 700)",
            directory.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::decode::LinkType;
    use crate::monitor::pipeline::Monitor;
    use crate::monitor::time::UnixNanos;
    use std::io::{BufRead, BufReader};
    use std::path::PathBuf;
    use std::time::Duration;

    /// A fresh private directory for one test's socket.
    fn private_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("security-daemon-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        dir
    }

    fn sample_hello() -> proto::Hello {
        hello(&["enp4s0".into()], &LocalNetworks::new(vec!["192.168.1.0/24".parse().unwrap()]), 1000)
    }

    fn sample_summary() -> Summary {
        let mut monitor = Monitor::new(LocalNetworks::new(vec!["192.168.1.0/24".parse().unwrap()]), Duration::from_secs(1));
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x08, 0x00, 0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 1, 1, 1, 1, 192, 168, 1, 86]);
        frame.extend_from_slice(&[0, 53, 0x9C, 0x40, 0, 8, 0, 0]);
        let _ = monitor.observe(LinkType::Ethernet, &frame, 60, UnixNanos::new(1_000_000_000));
        monitor.finish().unwrap()
    }

    #[test]
    fn a_viewer_receives_the_hello_then_summaries() {
        let dir = private_dir("stream");
        let path = dir.join("monitor.sock");
        let mut server = ViewerServer::bind(&path, &sample_hello()).unwrap();
        let client = UnixStream::connect(&path).unwrap();

        server.accept_viewers().unwrap();
        server.send(&sample_summary()).unwrap();
        let mut lines = BufReader::new(client).lines();
        let first = proto::Message::from_line(&lines.next().unwrap().unwrap()).unwrap();
        let second = proto::Message::from_line(&lines.next().unwrap().unwrap()).unwrap();

        assert!(matches!(first, proto::Message::Hello(h) if h.interfaces == ["enp4s0"]));
        let proto::Message::Summary(summary) = second else { panic!("not a summary") };
        assert_eq!(summary.totals.inbound.packets, 1);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_viewer_that_stops_reading_is_dropped() {
        let dir = private_dir("stuck");
        let path = dir.join("monitor.sock");
        let mut server = ViewerServer::bind(&path, &sample_hello()).unwrap();
        let _stuck = UnixStream::connect(&path).unwrap();
        server.accept_viewers().unwrap();

        let summary = sample_summary();
        for _ in 0..40_000 {
            server.send(&summary).unwrap();
        }

        assert_eq!(server.viewer_count(), 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_stale_socket_is_replaced_but_a_live_one_is_not() {
        let dir = private_dir("stale");
        let path = dir.join("monitor.sock");
        drop(UnixListener::bind(&path).unwrap());

        let first = ViewerServer::bind(&path, &sample_hello());
        let second = ViewerServer::bind(&path, &sample_hello());

        assert!(first.is_ok());
        assert!(second.unwrap_err().to_string().contains("already serving"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_directory_others_can_enter_is_refused() {
        let dir = private_dir("open");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        let refused = ViewerServer::bind(&dir.join("monitor.sock"), &sample_hello());

        assert!(refused.unwrap_err().to_string().contains("mode 700"));
        fs::remove_dir_all(dir).unwrap();
    }
}
