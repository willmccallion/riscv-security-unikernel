//! Boots the unikernel under QEMU and exchanges raw Ethernet frames with it.
//!
//! QEMU's `dgram` netdev carries one Ethernet frame per Unix datagram, so a
//! host process can inject arbitrary frames and read the kernel's replies
//! without a tap device or root. The serial console is captured so callers
//! can tell a healthy kernel from one that panicked, trapped or tripped its
//! stack guard.

pub mod frame;
pub mod mgmt;
pub mod mutate;

use anyhow::{Context, Result, bail};
use std::io::Read;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Serial line printed once the kernel has finished init and entered its
/// packet loop.
const READY_MARKER: &str = "[*] Entropy";

/// Serial markers that mean the kernel stopped processing packets.
const FATAL_MARKERS: [&str; 3] = ["[KERNEL PANIC]", "[TRAP]", "[STACK GUARD]"];

const BOOT_TIMEOUT: Duration = Duration::from_secs(20);

/// Why a kernel stopped responding, as reported on its serial console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatalReport(pub String);

/// A running kernel under QEMU.
#[derive(Debug)]
pub struct Kernel {
    child: Child,
    socket: UnixDatagram,
    qemu_endpoint: PathBuf,
    workdir: PathBuf,
    serial: Arc<Mutex<String>>,
    serial_reader: Option<JoinHandle<()>>,
}

impl Kernel {
    /// Boots `kernel_elf` and waits until its packet loop is running.
    pub fn boot(kernel_elf: &Path) -> Result<Self> {
        Self::boot_with(kernel_elf, &[])
    }

    /// Like [`Self::boot`], passing `extra_args` through to QEMU.
    pub fn boot_with(kernel_elf: &Path, extra_args: &[&str]) -> Result<Self> {
        let workdir = unique_workdir()?;
        let qemu_endpoint = workdir.join("qemu.sock");
        let host_endpoint = workdir.join("host.sock");
        let socket = UnixDatagram::bind(&host_endpoint)
            .with_context(|| format!("bind {}", host_endpoint.display()))?;

        let netdev = format!(
            "dgram,id=n0,local.type=unix,local.path={},remote.type=unix,remote.path={}",
            qemu_endpoint.display(),
            host_endpoint.display()
        );
        let mut child = Command::new("qemu-system-riscv64")
            .args(["-machine", "virt", "-m", "128M", "-bios", "none"])
            .args(["-global", "virtio-mmio.force-legacy=true"])
            .args(["-display", "none", "-monitor", "none", "-serial", "stdio"])
            .arg("-kernel")
            .arg(kernel_elf)
            .args(["-netdev", &netdev, "-device", "virtio-net-device,netdev=n0"])
            .args(["-object", "rng-random,id=rng0,filename=/dev/urandom"])
            .args(["-device", "virtio-rng-device,rng=rng0"])
            .args(extra_args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("spawn qemu-system-riscv64")?;

        let stdout = child.stdout.take().context("qemu stdout not captured")?;
        let serial = Arc::new(Mutex::new(String::new()));
        let serial_reader = Some(spawn_serial_reader(stdout, Arc::clone(&serial)));

        let kernel = Self {
            child,
            socket,
            qemu_endpoint,
            workdir,
            serial,
            serial_reader,
        };
        kernel.wait_for_serial(READY_MARKER, BOOT_TIMEOUT)?;
        Ok(kernel)
    }

    /// Sends one Ethernet frame to the kernel's NIC.
    ///
    /// Empty frames are refused: QEMU's `dgram` backend treats a
    /// zero-length datagram as end-of-stream and stops delivering frames,
    /// which would look like a dead kernel.
    pub fn send(&self, frame: &[u8]) -> Result<()> {
        if frame.is_empty() {
            bail!("refusing to send an empty frame; it would stall QEMU's netdev");
        }
        let sent = self
            .socket
            .send_to(frame, &self.qemu_endpoint)
            .context("send frame to qemu")?;
        if sent != frame.len() {
            bail!("short send: {sent} of {} bytes", frame.len());
        }
        Ok(())
    }

    /// Receives the next frame the kernel transmits, or `None` on timeout.
    pub fn recv(&self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        self.socket.set_read_timeout(Some(timeout))?;
        let mut buf = vec![0u8; 2048];
        match self.socket.recv(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                Ok(Some(buf))
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Receives frames until one satisfies `pred` or `timeout` elapses.
    pub fn recv_matching(
        &self,
        timeout: Duration,
        mut pred: impl FnMut(&[u8]) -> bool,
    ) -> Result<Option<Vec<u8>>> {
        let deadline = Instant::now() + timeout;
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            match self.recv(remaining)? {
                Some(f) if pred(&f) => return Ok(Some(f)),
                Some(_) => {}
                None => return Ok(None),
            }
        }
        Ok(None)
    }

    /// Discards every frame already queued from the kernel.
    pub fn drain(&self) -> Result<()> {
        while self.recv(Duration::from_millis(1))?.is_some() {}
        Ok(())
    }

    /// Returns the fatal serial report if the kernel has panicked, trapped
    /// or tripped its stack guard.
    pub fn fatal(&self) -> Option<FatalReport> {
        let serial = self.serial_snapshot();
        FATAL_MARKERS.iter().find_map(|marker| {
            serial.find(marker).map(|start| {
                let line_end = serial[start..]
                    .find('\n')
                    .map_or(serial.len(), |i| start + i);
                FatalReport(serial[start..line_end].to_string())
            })
        })
    }

    /// Checks the kernel still answers ARP for its own address.
    pub fn is_alive(&self) -> Result<bool> {
        self.drain()?;
        for _ in 0..3 {
            self.send(&frame::arp_request(frame::KERNEL_IP))?;
            if self
                .recv_matching(Duration::from_millis(500), frame::is_arp_reply_from_kernel)?
                .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Everything the kernel has printed on its serial console so far.
    pub fn serial_snapshot(&self) -> String {
        match self.serial.lock() {
            Ok(s) => s.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn wait_for_serial(&self, marker: &str, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(report) = self.fatal() {
                bail!("kernel died during boot: {}", report.0);
            }
            if self.serial_snapshot().contains(marker) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(20));
        }
        bail!(
            "kernel did not print {marker:?} within {timeout:?}; serial:\n{}",
            self.serial_snapshot()
        )
    }
}

impl Drop for Kernel {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.serial_reader.take() {
            let _ = reader.join();
        }
        let _ = std::fs::remove_dir_all(&self.workdir);
    }
}

fn spawn_serial_reader(
    stdout: std::process::ChildStdout,
    serial: Arc<Mutex<String>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut stdout = stdout;
        let mut chunk = [0u8; 4096];
        while let Ok(n @ 1..) = stdout.read(&mut chunk) {
            let text = String::from_utf8_lossy(&chunk[..n]);
            if let Ok(mut s) = serial.lock() {
                s.push_str(&text);
            }
        }
    })
}

fn unique_workdir() -> Result<PathBuf> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "qemu-harness-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir)
}

/// Path to the release kernel ELF, overridable with `KERNEL_ELF`.
pub fn default_kernel_elf() -> PathBuf {
    std::env::var_os("KERNEL_ELF").map_or_else(
        || {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/riscv64gc-unknown-none-elf/release/security-unikernel")
        },
        PathBuf::from,
    )
}
