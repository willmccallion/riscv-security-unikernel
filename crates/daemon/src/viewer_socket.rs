//! Accepting viewers' connections without ever blocking capture.

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};

/// Accepts a waiting connection on `listener`, already non-blocking and
/// close-on-exec, or `None` if nobody is waiting. Setting non-blocking at
/// accept time keeps `fcntl` and `ioctl` out of the sandbox's allowlist.
pub fn accept_nonblocking(listener: &UnixListener) -> io::Result<Option<UnixStream>> {
    // SAFETY: accept4 with null address pointers writes no memory.
    let fd = unsafe {
        libc::accept4(
            listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return match err.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(None),
            _ => Err(err),
        };
    }
    // SAFETY: fd is a freshly accepted descriptor that nothing else owns.
    Ok(Some(unsafe { UnixStream::from_raw_fd(fd) }))
}
